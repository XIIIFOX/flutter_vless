package com.github.tfox.flutter_vless.xray.core

import android.app.Service
import android.content.Context
import android.content.Intent
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.service.XraySocketProtector
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import com.github.tfox.flutter_vless.xray.utils.Utilities
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID
import java.util.concurrent.TimeUnit

/** Process owner delegates all session transitions to XrayVPNService. */
object XrayCoreManager {
    @Volatile private var xrayProcess: Process? = null
    private var runtimeFile: File? = null
    private var lastProxyUplink = 0L
    private var lastProxyDownlink = 0L
    private fun nextFreePort(preferredPort: Int, usedPorts: Set<Int>): Int {
        require(preferredPort in 1..65535) { "Invalid private listener port" }
        return ((preferredPort..65535).asSequence() + (1024 until preferredPort).asSequence())
            .firstOrNull { it !in usedPorts } ?: error("No private listener port is available")
    }

    private fun normalizeRuntimeConfig(value: Any?): Any? {
        return when (value) {
            is JSONObject -> {
                val normalized = JSONObject()
                val aliases = mapOf(
                    "xHTTPSettings" to "xhttpSettings",
                    "httpUpgradeSettings" to "httpupgradeSettings",
                    "splitHTTPSettings" to "splithttpSettings"
                )
                val keys = value.keys()
                while (keys.hasNext()) {
                    val key = keys.next()
                    if (key == "allowInsecure") continue

                    val targetKey = aliases[key] ?: key
                    if (aliases.containsKey(key) && value.has(targetKey)) continue

                    val normalizedValue = normalizeRuntimeConfig(value.opt(key))
                    if (targetKey == "network" && normalizedValue is String) {
                        normalized.put(targetKey, normalizedValue.lowercase())
                    } else {
                        normalized.put(targetKey, normalizedValue)
                    }
                }
                normalized
            }
            is JSONArray -> {
                val normalized = JSONArray()
                for (i in 0 until value.length()) {
                    normalized.put(normalizeRuntimeConfig(value.opt(i)))
                }
                normalized
            }
            else -> value
        }
    }

    private fun normalizeVlessOutbounds(configJson: JSONObject) {
        val outbounds = configJson.optJSONArray("outbounds") ?: return
        for (i in 0 until outbounds.length()) {
            val outbound = outbounds.optJSONObject(i) ?: continue
            if (outbound.optString("protocol") != "vless") continue

            val settings = outbound.optJSONObject("settings") ?: continue
            if (settings.has("vnext")) continue

            val address = settings.optString("address")
            val id = settings.optString("id")
            val port = settings.optInt("port", 0)
            if (address.isEmpty() || id.isEmpty() || port <= 0) continue

            val user = JSONObject(settings.toString()).apply { remove("address"); remove("port") }
            user.put("id", id)
            user.put("encryption", settings.optString("encryption", "none"))
            user.put("flow", settings.optString("flow", ""))
            user.put("level", settings.optInt("level", 8))

            val server = JSONObject()
            server.put("address", address)
            server.put("port", port)
            server.put("users", JSONArray().put(user))

            val normalizedSettings = JSONObject(settings.toString())
            normalizedSettings.put("vnext", JSONArray().put(server))
            outbound.put("settings", normalizedSettings)
        }
    }

    /** These upstream paths open sockets outside Xray's controller interfaces. */
    internal fun requireProtectedSocketSupport(value: Any?) {
        when (value) {
            is JSONObject -> value.keys().forEach { key ->
                val child = value.opt(key)
                require(!(key.equals("type", ignoreCase = true) && child is String && child.equals("xicmp", ignoreCase = true))) {
                    "xicmp is unavailable in protected VPN mode"
                }
                requireProtectedSocketSupport(child)
            }
            is JSONArray -> for (index in 0 until value.length()) requireProtectedSocketSupport(value.opt(index))
            is String -> require(!value.startsWith("quic+local://", ignoreCase = true)) {
                "quic+local DNS is unavailable in protected VPN mode; use https+local or tcp+local"
            }
        }
    }

    internal fun buildRuntimeConfigJson(config: XrayConfig, filesDir: File,
        credentials: LocalProxyCredentials? = null, protectedDns: AndroidTunnelDnsPolicy.Prepared? = null,
        environment: (String) -> String? = System::getenv): JSONObject {
        // The DNS preparer chooses the adapter identity before adding its rule.
        // Accept it only with the exact native-prepared document, including on
        // recovery; guessing a tag from caller JSON could scope another input.
        val dnsAdapterTag = if (protectedDns != null || config.ANDROID_DNS_POLICY == "proxy") {
            require(!config.PROXY_ONLY && protectedDns?.configJson == config.V2RAY_FULL_JSON_CONFIG) {
                "Protected DNS preparation is required"
            }
            requireNotNull(protectedDns?.managedInboundTag) { "Protected DNS adapter identity is unavailable" }
        } else null
        val imported = XrayCertificateAssets.prepare(config.V2RAY_FULL_JSON_CONFIG, config.CERTIFICATE_ASSETS_DIRECTORY)
        // Service and policy subtrees belong to the caller. Keep them outside
        // the compatibility normalizer, including explicit null and unknown
        // fields, and reject ambiguous Go-decoder aliases before choosing one.
        val callerRoots = mutableMapOf<String, Any>()
        for (key in imported.keys().asSequence().toList()) {
            val field = key.replace('\u017f', 's').replace('\u212a', 'k').lowercase(java.util.Locale.ROOT)
            if (field !in setOf("api", "stats", "policy")) continue
            require(!callerRoots.containsKey(field)) { "Duplicate native configuration field" }
            callerRoots[field] = imported.get(key)
            imported.remove(key)
        }
        val json = normalizeRuntimeConfig(imported) as JSONObject
        LocalProxyAccessPolicy.normalizeConfigInputs(json)
        callerRoots.forEach { (key, value) -> json.put(key, value) }
        normalizeVlessOutbounds(json)
        require(json.optJSONArray("outbounds")?.length()?.let { it > 0 } == true) { "At least one outbound is required" }
        // Raw native logs can contain addresses and secrets even at error level.
        json.put("log", JSONObject().put("loglevel", "none").put("access", "none").put("error", "none"))
        val inbounds = json.optJSONArray("inbounds") ?: JSONArray()
        val serviceTags = XrayServiceTags(json)
        val used = XrayPortSpec.serviceListenerPorts(json).toMutableSet()
        var hasSocks = false
        for (i in 0 until inbounds.length()) {
            val inbound = inbounds.getJSONObject(i)
            val port = inbound.optInt("port", -1)
            val listen = XrayPortSpec.bindListenEnvironment(inbound.optString("listen"), environment)
            if (inbound.opt("listen") is String) inbound.put("listen", listen)
            val unixSocket = XrayPortSpec.isUnixListen(listen)
            // Xray also accepts string port lists/ranges. Reserve every port
            // before allocating the private VPN listener.
            if (!unixSocket && inbound.has("port")) used.addAll(XrayPortSpec.reservedPorts(inbound.get("port")))
            if (!unixSocket && inbound.optString("protocol") == "socks" && port == config.LOCAL_SOCKS5_PORT) hasSocks = true
        }
        // A full Xray profile may contain several intentional SOCKS/HTTP or
        // other listeners. Never reuse/rewrite them for the tunnel adapter.
        if (!config.PROXY_ONLY || !hasSocks) {
            config.LOCAL_SOCKS5_PORT = nextFreePort(config.LOCAL_SOCKS5_PORT, used)
            require(dnsAdapterTag == null || (0 until inbounds.length()).none {
                inbounds.getJSONObject(it).optString("tag") == dnsAdapterTag
            }) { "Protected DNS adapter conflicts with imported input" }
            inbounds.put(JSONObject().put("tag", dnsAdapterTag ?: serviceTags.next("flutter-vless-tun"))
                .put("listen", "127.0.0.1").put("port", config.LOCAL_SOCKS5_PORT).put("protocol", "socks")
                .put("settings", JSONObject().put("auth", "noauth").put("udp", true))
                .put("sniffing", JSONObject().put("enabled", true).put("routeOnly", true)
                    .put("destOverride", JSONArray().put("http").put("tls").put("quic"))))
            used.add(config.LOCAL_SOCKS5_PORT)
        }
        if (!config.PROXY_ONLY) {
            LocalProxyAccessPolicy.apply(inbounds, requireNotNull(credentials) { "Native local credentials are required" }, config.LOCAL_SOCKS5_PORT)
            requireProtectedSocketSupport(json)
        } else {
            LocalProxyAccessPolicy.credentialsForProxyOnly(JSONObject().put("inbounds", inbounds), config.LOCAL_SOCKS5_PORT)
        }
        if (!json.has("stats")) json.put("stats", JSONObject())
        if (!json.has("policy")) json.put("policy", JSONObject().put("system", JSONObject()
            .put("statsOutboundUplink", true).put("statsOutboundDownlink", true)))
        if (json.has("api")) {
            // Zero means no library-owned API. Never query an arbitrary caller
            // service, including when the caller intentionally supplied null.
            config.LOCAL_API_PORT = 0
        } else {
            val apiOutboundTag = serviceTags.next("flutter-vless-stats")
            json.put("api", JSONObject().put("tag", apiOutboundTag).put("services", JSONArray().put("StatsService")))
            config.LOCAL_API_PORT = nextFreePort(if (config.LOCAL_API_PORT == 0) 10809 else config.LOCAL_API_PORT, used)
            val apiTag = serviceTags.next("flutter-vless-stats-in")
            inbounds.put(JSONObject().put("tag", apiTag).put("port", config.LOCAL_API_PORT).put("listen", "127.0.0.1")
                .put("protocol", "dokodemo-door").put("settings", JSONObject().put("address", "127.0.0.1")))
            val routing = json.optJSONObject("routing") ?: JSONObject()
            val rules = JSONArray().put(JSONObject().put("type", "field").put("inboundTag", JSONArray().put(apiTag)).put("outboundTag", apiOutboundTag))
            routing.optJSONArray("rules")?.let { for (i in 0 until it.length()) rules.put(it.get(i)) }
            routing.put("rules", rules)
            json.put("routing", routing)
        }
        json.put("inbounds", inbounds)
        return json
    }

    /** Pure preliminary validation in the application process; service repeats before mutation. */
    fun validateConfiguration(config: XrayConfig) {
        Utilities.validateAssetsDirectory(config.GEO_ASSETS_DIRECTORY)
        XrayCertificateAssets.validateDirectory(config.CERTIFICATE_ASSETS_DIRECTORY)
        require(config.ANDROID_DNS_POLICY in setOf("config", "proxy")) { "Unsupported Android DNS policy" }
        require(!(config.PROXY_ONLY && config.ANDROID_DNS_POLICY == "proxy")) { "Proxy DNS requires VPN mode" }
        require(config.ANDROID_DNS_PROXY_OUTBOUND_TAG == null || config.ANDROID_DNS_POLICY == "proxy") {
            "DNS proxy outbound tag requires proxy DNS policy"
        }
        if (!config.PROXY_ONLY) AndroidTunnelDnsPolicy.validate(config.V2RAY_FULL_JSON_CONFIG, config.ANDROID_DNS_POLICY,
            config.ANDROID_DNS_PROXY_OUTBOUND_TAG, config.BYPASS_SUBNETS)
        // DNS structural validation above does not resolve endpoints. The final
        // service preparation supplies the native DNS identity before Core test.
        buildRuntimeConfigJson(config.copy(ANDROID_DNS_POLICY = "config"), File("."), LocalProxyCredentials.generate())
    }

    internal fun buildDelayConfigJson(configJson: String, proxyPort: Int, filesDir: File,
        credentials: LocalProxyCredentials, certificateAssetsDirectory: String? = null): Pair<JSONObject, Int> {
        // A standalone measurement owns its temporary inputs. Caller API and
        // metrics listeners may already be bound by the active session. Remove
        // the whole services: clearing listen changes Core's outbound semantics.
        val json = JSONObject(configJson)
        LocalProxyAccessPolicy.normalizeConfigInputs(json)
        fun serviceField(key: String) = key.replace('\u017f', 's').replace('\u212a', 'k')
            .lowercase(java.util.Locale.ROOT)
        val serviceKeys = json.keys().asSequence().toList().filter {
            serviceField(it) in setOf("api", "metrics")
        }
        val seen = mutableSetOf<String>()
        for (key in serviceKeys) {
            // Match Go's service spelling, including long S. Reject ambiguous
            // aliases rather than depend on JSONObject's iteration order.
            require(seen.add(serviceField(key))) { "Duplicate native configuration field" }
            json.remove(key)
        }
        json.put("inbounds", JSONArray())
        val config = XrayConfig(V2RAY_FULL_JSON_CONFIG = json.toString(), LOCAL_SOCKS5_PORT = proxyPort, LOCAL_API_PORT = proxyPort + 1,
            CERTIFICATE_ASSETS_DIRECTORY = certificateAssetsDirectory)
        return buildRuntimeConfigJson(config, filesDir, credentials) to config.LOCAL_SOCKS5_PORT
    }

    /** Validate the actual native parser before replacing a working session. No raw output escapes. */
    internal fun validateNative(context: Context, json: JSONObject, geoAssetsDirectory: String? = null): Boolean {
        val file = File(context.noBackupFilesDir, "validate-${UUID.randomUUID()}.json")
        return try {
            file.writeText(json.toString())
            val builder = ProcessBuilder(File(context.applicationInfo.nativeLibraryDir, "libxray.so").absolutePath,
                "run", "-test", "-config", file.absolutePath).redirectErrorStream(true)
            Utilities.configureXrayAssets(context, builder.environment(), geoAssetsDirectory)
            val process = builder.start()
            val reader = drain(process)
            val done = process.waitFor(10, TimeUnit.SECONDS)
            if (!done) process.destroyForcibly()
            reader.join(1000)
            done && process.exitValue() == 0
        } catch (_: Exception) { false } finally { file.delete() }
    }

    internal fun startCore(context: Service, config: XrayConfig, json: JSONObject,
        protector: XraySocketProtector?, ownerGeneration: Long, onExit: (Long, Int) -> Unit): Boolean {
        if (!stopWorkers()) return false
        return try {
            val file = File(context.noBackupFilesDir, "xray-${UUID.randomUUID()}.json")
            runtimeFile = file
            file.writeText(json.toString())
            val builder = ProcessBuilder(File(context.applicationInfo.nativeLibraryDir, "libxray.so").absolutePath,
                "run", "-config", file.absolutePath).directory(context.noBackupFilesDir).redirectErrorStream(true)
            Utilities.configureXrayAssets(context, builder.environment(), config.GEO_ASSETS_DIRECTORY)
            if (protector != null) builder.environment()["FLUTTER_VLESS_PROTECT_SOCKET"] = protector.socketName
            val process = builder.start()
            xrayProcess = process
            Thread({
                try {
                    process.inputStream.use { stream -> val bytes = ByteArray(4096); while (stream.read(bytes) >= 0) { } }
                    val code = process.waitFor()
                    synchronized(this) { if (xrayProcess !== process) return@Thread }
                    onExit(ownerGeneration, code)
                } catch (_: Exception) { onExit(ownerGeneration, -1) }
            }, "xray-monitor").apply { isDaemon = true; start() }
            if (protector != null && !protector.awaitVerified()) { stopWorkers(); return false }
            if (!process.isAlive) { stopWorkers(); return false }
            AppConfigs.V2RAY_CONFIG = config
            lastProxyUplink = 0; lastProxyDownlink = 0
            true
        } catch (_: Exception) { stopWorkers(); false }
    }

    /** An identity snapshot, not a readiness result. Startup checks this exact
     * child and its session generation around every bounded probe operation. */
    internal fun currentCoreProcess(): Process? = xrayProcess
    internal fun ownsCoreProcess(candidate: Process): Boolean = xrayProcess === candidate && candidate.isAlive

    @Synchronized internal fun stopWorkers(): Boolean {
        val process = xrayProcess
        xrayProcess = null // Invalidate callbacks before signaling the old process.
        if (process != null) {
            process.destroy()
            if (!process.waitFor(1, TimeUnit.SECONDS)) process.destroyForcibly()
            if (!process.waitFor(1, TimeUnit.SECONDS)) { xrayProcess = process; return false }
        }
        runtimeFile?.delete(); runtimeFile = null
        return true
    }

    fun isXrayRunning() = AppConfigs.V2RAY_STATE != AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED
    fun getProviderDebugSnapshot(context: Context) = XrayDiagnosticsStore.snapshot(context.filesDir)

    internal fun publishState(context: Context, state: AppConfigs.V2RAY_STATES, seconds: Long = 0) {
        val changed = AppConfigs.V2RAY_STATE != state
        AppConfigs.V2RAY_STATE = state
        if (changed) com.github.tfox.flutter_vless.NativeQuickAccess.refresh(context)
        val traffic = if (state == AppConfigs.V2RAY_STATES.V2RAY_CONNECTED && statsQueryPort(AppConfigs.V2RAY_CONFIG) != null)
            getV2rayTraffic(context) else longArrayOf(0, 0, 0, 0)
        context.sendBroadcast(Intent(AppConfigs.V2RAY_CONNECTION_INFO).setPackage(context.packageName)
            .putExtra("STATE", state).putExtra("DURATION", seconds.toString())
            .putExtra("UPLOAD_SPEED", traffic[0]).putExtra("DOWNLOAD_SPEED", traffic[1])
            .putExtra("UPLOAD_TRAFFIC", traffic[2]).putExtra("DOWNLOAD_TRAFFIC", traffic[3]))
    }

    internal fun statsQueryPort(config: XrayConfig?): Int? = config?.LOCAL_API_PORT?.takeIf { it in 1..65535 }

    fun getV2rayTraffic(context: Context): LongArray {
        val apiPort = statsQueryPort(AppConfigs.V2RAY_CONFIG) ?: return longArrayOf(0, 0, 0, 0)
        if (xrayProcess?.isAlive != true) return longArrayOf(0, 0, 0, 0)
        return try {
            val process = ProcessBuilder(File(context.applicationInfo.nativeLibraryDir, "libxray.so").absolutePath,
                "api", "statsquery", "--server=127.0.0.1:$apiPort", "--pattern", "outbound>>>proxy>>>")
                .redirectErrorStream(true).start()
            // Stats are bounded and parsed locally; never included in diagnostics.
            val output = BoundedCoreCommand.capture(process)?.toString(Charsets.UTF_8)
                ?: return longArrayOf(0, 0, 0, 0)
            val stats = JSONObject(output).optJSONArray("stat") ?: JSONArray()
            var up = 0L; var down = 0L
            for (i in 0 until stats.length()) {
                val stat = stats.getJSONObject(i)
                when (stat.optString("name")) {
                    "outbound>>>proxy>>>traffic>>>uplink" -> up = stat.optLong("value")
                    "outbound>>>proxy>>>traffic>>>downlink" -> down = stat.optLong("value")
                }
            }
            val result = longArrayOf((up - lastProxyUplink).coerceAtLeast(0), (down - lastProxyDownlink).coerceAtLeast(0), up, down)
            lastProxyUplink = up; lastProxyDownlink = down
            result
        } catch (_: Exception) { longArrayOf(0, 0, 0, 0) }
    }

    fun getServerDelay(context: Context, configJson: String, url: String, geoAssetsDirectory: String? = null,
        certificateAssetsDirectory: String? = null): Long {
        var process: Process? = null
        val file = File(context.noBackupFilesDir, "delay-${UUID.randomUUID()}.json")
        fun event(event: XrayDiagnosticsStore.Event, value: Long? = null) =
            XrayDiagnosticsStore.event(context.filesDir, event, value = value)
        return try {
            event(XrayDiagnosticsStore.Event.DELAY_ALLOCATING_PORTS)
            val credentials = LocalProxyCredentials.generate()
            var socksPort = 0
            val builder = DelayProbePortAllocator.reserve().use { ports ->
                event(XrayDiagnosticsStore.Event.DELAY_PORTS_RESERVED)
                val (json, selectedPort) = buildDelayConfigJson(configJson, ports.socksPort, context.noBackupFilesDir, credentials,
                    certificateAssetsDirectory)
                socksPort = selectedPort
                file.writeText(json.toString())
                ProcessBuilder(File(context.applicationInfo.nativeLibraryDir, "libxray.so").absolutePath,
                    "run", "-config", file.absolutePath).directory(context.noBackupFilesDir).redirectErrorStream(true).also {
                    Utilities.configureXrayAssets(context, it.environment(), geoAssetsDirectory)
                    event(XrayDiagnosticsStore.Event.DELAY_CONFIG_READY)
                }
            }
            // Core cannot inherit these listeners. Release both immediately before
            // launch; another process can still win the unavoidable bind handoff race.
            val child = builder.start()
            process = child
            event(XrayDiagnosticsStore.Event.DELAY_CORE_STARTED)
            drain(child)
            event(XrayDiagnosticsStore.Event.DELAY_MEASURING)
            repeat(20) { attempt ->
                if (!child.isAlive) {
                    event(XrayDiagnosticsStore.Event.DELAY_CORE_EXIT, child.exitValue().toLong())
                    return -1
                }
                try {
                    val delay = AuthenticatedSocksClient.measure(socksPort, credentials, url)
                    event(XrayDiagnosticsStore.Event.DELAY_COMPLETE)
                    return delay
                } catch (_: Exception) {
                    event(XrayDiagnosticsStore.Event.DELAY_PROBE_FAILED, (attempt + 1).toLong())
                    Thread.sleep(100)
                }
            }
            event(XrayDiagnosticsStore.Event.DELAY_FAILED)
            -1
        } catch (_: Exception) { event(XrayDiagnosticsStore.Event.DELAY_FAILED); -1 } finally {
            if (!DelayProbeCleanup.cleanup(process, file)) event(XrayDiagnosticsStore.Event.DELAY_CLEANUP_FAILED)
        }
    }

    private fun drain(process: Process): Thread = Thread({
        runCatching { process.inputStream.use { val bytes = ByteArray(4096); while (it.read(bytes) >= 0) { } } }
    }, "xray-output-discard").apply { isDaemon = true; start() }
}
