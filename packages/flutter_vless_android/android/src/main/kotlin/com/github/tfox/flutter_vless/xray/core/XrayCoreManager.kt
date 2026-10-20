package com.github.tfox.flutter_vless.xray.core

import android.app.Service
import android.content.Context
import android.content.Intent
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.service.XraySocketProtector
import com.github.tfox.flutter_vless.xray.service.NativeRoutingSelection
import com.github.tfox.flutter_vless.xray.service.NativeRoutingSpec
import com.github.tfox.flutter_vless.xray.service.NativeRoutingPreparation
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import com.github.tfox.flutter_vless.xray.utils.Utilities
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.UUID
import java.util.concurrent.TimeUnit

/** Process owner delegates all session transitions to XrayVPNService. */
object XrayCoreManager {
    @Volatile private var xrayProcess: Process? = null
    private var runtimeInputs: NativeRuntimeConfig.Inputs? = null
    private var lastProxyUplink: Long? = null
    private var lastProxyDownlink: Long? = null
    private fun nextFreePort(preferredPort: Int, usedPorts: Set<Int>, tcpAvailable: ((Int) -> Boolean)?): Int {
        require(preferredPort in 1..65535) { "Invalid private listener port" }
        var attempts = 0
        for (port in (preferredPort..65535).asSequence() + (1024 until preferredPort).asSequence()) {
            if (port in usedPorts) continue
            if (tcpAvailable != null) {
                if (attempts == 32) break
                attempts++
                if (!tcpAvailable(port)) continue
            }
            return port
        }
        error("No private listener port is available")
    }

    /** Availability only: release-to-Core.bind remains a race, not a held reservation. */
    internal fun tcpListenerAvailable(port: Int): Boolean = try {
        ServerSocket().use { listener ->
            listener.reuseAddress = false
            listener.bind(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), port), 1)
        }
        true
    } catch (_: IOException) { false }

    private fun schemaField(key: String): String =
        key.replace('ſ', 's').replace('K', 'k').lowercase(java.util.Locale.ROOT)

    private fun schemaKey(value: JSONObject, name: String): String? {
        val matches = value.keys().asSequence().filter { schemaField(it) == name }.toList()
        require(matches.size <= 1) { "Duplicate native configuration field" }
        return matches.singleOrNull()
    }

    private fun schemaValue(value: JSONObject, name: String): Any? = schemaKey(value, name)?.let(value::opt)

    /** StreamConfig.Build compiles only the preferred XHTTP branch and its
     * selected extra/download, even when the parent chose another transport. */
    private fun forEachStream(config: JSONObject, action: (JSONObject) -> Unit) {
        fun stream(value: JSONObject) {
            action(value)
            val preferred = schemaValue(value, "xhttpsettings")
            val transport = (if (preferred == null || preferred == JSONObject.NULL)
                schemaValue(value, "splithttpsettings") else preferred) as? JSONObject ?: return
            val extra = schemaKey(transport, "extra")
            val effective = (if (extra == null) transport else transport.opt(extra)) as? JSONObject ?: return
            (schemaValue(effective, "downloadsettings") as? JSONObject)?.let(::stream)
        }
        for (collection in listOf("inbounds", "outbounds")) {
            val entries = schemaValue(config, collection) as? JSONArray ?: continue
            for (index in 0 until entries.length()) {
                val entry = entries.optJSONObject(index) ?: continue
                (schemaValue(entry, "streamsettings") as? JSONObject)?.let(::stream)
            }
        }
    }

    private fun udpMasks(stream: JSONObject): List<JSONObject> {
        val finalMask = schemaValue(stream, "finalmask") as? JSONObject ?: return emptyList()
        val masks = schemaValue(finalMask, "udp") as? JSONArray ?: return emptyList()
        return (0 until masks.length()).mapNotNull(masks::optJSONObject)
    }

    /** These are TLSConfig objects in the pinned schema. Keep legacy privacy
     * cleanup for their fields, while leaving every unknown child untouched. */
    private fun forEachTls(stream: JSONObject, action: (JSONObject) -> Unit) {
        (schemaValue(stream, "tlssettings") as? JSONObject)?.let(action)
        for (mask in udpMasks(stream)) {
            val settings = schemaValue(mask, "settings") as? JSONObject ?: continue
            when ((schemaValue(mask, "type") as? String)?.lowercase(java.util.Locale.ROOT)) {
                "realm" -> (schemaValue(settings, "tlsconfig") as? JSONObject)?.let(action)
                "xdns" -> {
                    val resolvers = schemaValue(settings, "resolvers") as? JSONArray ?: continue
                    for (index in 0 until resolvers.length()) {
                        val resolver = resolvers.optJSONObject(index) ?: continue
                        (schemaValue(resolver, "tlsconfig") as? JSONObject)?.let(action)
                    }
                }
            }
        }
    }

    private fun normalizeRuntimeConfig(value: JSONObject): JSONObject {
        val normalized = JSONObject(value.toString())
        // This root spelling must be canonical before the local-input policy;
        // its hosts dictionary and all other caller fields remain unchanged.
        schemaKey(normalized, "dns")?.takeIf { it != "dns" }?.let { spelling ->
            normalized.put("dns", normalized.remove(spelling))
        }
        forEachStream(normalized) { stream ->
            for ((legacy, canonical) in mapOf("xHTTPSettings" to "xhttpSettings",
                "httpUpgradeSettings" to "httpupgradeSettings", "splitHTTPSettings" to "splithttpSettings")) {
                if (stream.has(legacy)) {
                    val child = stream.remove(legacy)
                    if (!stream.has(canonical)) stream.put(canonical, child)
                }
            }
            schemaKey(stream, "network")?.let { spelling ->
                (stream.opt(spelling) as? String)?.let { stream.put(spelling, it.lowercase(java.util.Locale.ROOT)) }
            }
            forEachTls(stream) { tls ->
                tls.keys().asSequence().filter { schemaField(it) == "allowinsecure" }.toList().forEach(tls::remove)
            }
        }
        return normalized
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

    /** Only these schema paths open sockets outside Core's controller hooks;
     * feature-looking values in unknown metadata are not active features. */
    internal fun requireProtectedSocketSupport(value: Any?) {
        if (value !is JSONObject) return
        forEachStream(value) { stream ->
            for (mask in udpMasks(stream)) require(
                !(schemaValue(mask, "type") as? String).equals("xicmp", ignoreCase = true)) {
                "xicmp is unavailable in protected VPN mode"
            }
        }
        val dns = schemaValue(value, "dns") as? JSONObject ?: return
        val servers = schemaValue(dns, "servers") as? JSONArray ?: return
        for (index in 0 until servers.length()) {
            val server = servers.opt(index)
            val address = (if (server is JSONObject) schemaValue(server, "address") else server) as? String ?: continue
            val parsed = XrayPortSpec.coreAddressText(address)
            val scheme = parsed.substringBefore(':', "")
            require(!scheme.equals("quic+local", ignoreCase = true)) {
                "quic+local DNS is unavailable in protected VPN mode; use https+local or tcp+local"
            }
        }
    }

    internal fun buildRuntimeConfigJson(config: XrayConfig, filesDir: File,
        credentials: LocalProxyCredentials? = null, protectedDns: AndroidTunnelDnsPolicy.Prepared? = null,
        routingPrepared: ((NativeRoutingPreparation) -> Unit)? = null,
        tcpAvailable: ((Int) -> Boolean)? = null,
        changes: PreparationChanges? = null,
        environment: (String) -> String? = System::getenv): JSONObject {
        config.runtimeTrafficInboundTag = null
        // The DNS preparer chooses the adapter identity before adding its rule.
        // Accept it only with the exact native-prepared document, including on
        // recovery; guessing a tag from caller JSON could scope another input.
        val dnsAdapterTag = if (protectedDns != null || config.ANDROID_DNS_POLICY == "proxy") {
            require(!config.PROXY_ONLY && protectedDns?.configJson == config.V2RAY_FULL_JSON_CONFIG) {
                "Protected DNS preparation is required"
            }
            requireNotNull(protectedDns?.managedInboundTag) { "Protected DNS adapter identity is unavailable" }
        } else null
        val imported = XrayCertificateAssets.prepare(config.V2RAY_FULL_JSON_CONFIG, config.CERTIFICATE_ASSETS_DIRECTORY) {
            changes?.record(PreparationChange.CERTIFICATE_REFS_BOUND)
        }
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
        val json = normalizeRuntimeConfig(imported)
        LocalProxyAccessPolicy.normalizeConfigInputs(json)
        callerRoots.forEach { (key, value) -> json.put(key, value) }
        normalizeVlessOutbounds(json)
        require(json.optJSONArray("outbounds")?.length()?.let { it > 0 } == true) { "At least one outbound is required" }
        // Raw native logs can contain addresses and secrets even at error level.
        val previousLog = json.optJSONObject("log")
        val privateLogFields = setOf("loglevel", "access", "error")
        val typedLogFields = privateLogFields + setOf("dnslog", "maskaddress")
        if (previousLog == null || privateLogFields.any { previousLog.opt(it) != "none" } ||
            previousLog.keys().asSequence().any { it !in privateLogFields && schemaField(it) in typedLogFields })
            changes?.record(PreparationChange.PRIVATE_LOGGING_APPLIED)
        json.put("log", JSONObject().put("loglevel", "none").put("access", "none").put("error", "none"))
        val inbounds = json.optJSONArray("inbounds") ?: JSONArray()
        val originalInboundCount = inbounds.length()
        var apiRuleInsertions = 0
        val serviceTags = XrayServiceTags(json)
        val used = XrayPortSpec.serviceListenerPorts(json).toMutableSet()
        var hasSocks = false
        var managedInput: JSONObject? = null
        // Only a prepared VPN DNS bridge restores FakeDNS destinations.
        // Standalone delay owns an authenticated temporary input, not a TUN.
        val restoreFakeDns = !config.PROXY_ONLY && protectedDns != null && AndroidTunnelDnsPolicy.fakeDnsActive(json)
        for (i in 0 until inbounds.length()) {
            val inbound = inbounds.getJSONObject(i)
            val port = inbound.optInt("port", -1)
            val listen = XrayPortSpec.bindListenEnvironment(inbound.optString("listen"), environment) {
                changes?.record(PreparationChange.ADDRESS_ENVIRONMENT_BOUND)
            }
            if (inbound.opt("listen") is String) inbound.put("listen", listen)
            val unixSocket = XrayPortSpec.isUnixListen(listen)
            // Xray also accepts string port lists/ranges. Reserve every port
            // before allocating the private VPN listener.
            if (!unixSocket && inbound.has("port")) used.addAll(XrayPortSpec.reservedPorts(inbound.get("port"), environment))
            if (!unixSocket && inbound.optString("protocol") == "socks" && port == config.LOCAL_SOCKS5_PORT) hasSocks = true
        }
        // A full Xray profile may contain several intentional SOCKS/HTTP or
        // other listeners. Never reuse/rewrite them for the tunnel adapter.
        if (!config.PROXY_ONLY || !hasSocks) {
            config.LOCAL_SOCKS5_PORT = nextFreePort(config.LOCAL_SOCKS5_PORT, used, tcpAvailable)
            require(dnsAdapterTag == null || (0 until inbounds.length()).none {
                inbounds.getJSONObject(it).optString("tag") == dnsAdapterTag
            }) { "Protected DNS adapter conflicts with imported input" }
            inbounds.put(JSONObject().put("tag", dnsAdapterTag ?: serviceTags.next("flutter-vless-tun"))
                .put("listen", "127.0.0.1").put("port", config.LOCAL_SOCKS5_PORT).put("protocol", "socks")
                .put("settings", JSONObject().put("auth", "noauth").put("udp", true))
                .put("sniffing", JSONObject().put("enabled", true).put("routeOnly", true)
                    .put("destOverride", JSONArray().put("http").put("tls").put("quic")
                        .also { if (restoreFakeDns) it.put("fakedns") })))
            managedInput = inbounds.getJSONObject(inbounds.length() - 1)
            changes?.record(PreparationChange.PRIVATE_LISTENER_ADDED)
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
            .put("statsOutboundUplink", true).put("statsOutboundDownlink", true)
            .put("statsInboundUplink", true).put("statsInboundDownlink", true)))
        if (json.has("api")) {
            // Zero means no library-owned API. Never query an arbitrary caller
            // service, including when the caller intentionally supplied null.
            config.LOCAL_API_PORT = 0
        } else {
            apiRuleInsertions = 1
            val apiOutboundTag = serviceTags.next("flutter-vless-stats")
            json.put("api", JSONObject().put("tag", apiOutboundTag).put("services", JSONArray().put("StatsService")))
            config.LOCAL_API_PORT = nextFreePort(if (config.LOCAL_API_PORT == 0) 10809 else config.LOCAL_API_PORT, used, tcpAvailable)
            val apiTag = serviceTags.next("flutter-vless-stats-in")
            inbounds.put(JSONObject().put("tag", apiTag).put("port", config.LOCAL_API_PORT).put("listen", "127.0.0.1")
                .put("protocol", "dokodemo-door").put("settings", JSONObject().put("address", "127.0.0.1")))
            changes?.record(PreparationChange.PRIVATE_LISTENER_ADDED)
            val routing = json.optJSONObject("routing") ?: JSONObject()
            val rules = JSONArray().put(JSONObject().put("type", "field").put("inboundTag", JSONArray().put(apiTag)).put("outboundTag", apiOutboundTag))
            routing.optJSONArray("rules")?.let { for (i in 0 until it.length()) rules.put(it.get(i)) }
            routing.put("rules", rules)
            json.put("routing", routing)
        }
        json.put("inbounds", inbounds)
        NativeRoutingSelection.decode(config.VPN_ROUTING_SELECTION_JSON, config.PROXY_ONLY)?.let { intent ->
            val managed=inbounds.getJSONObject(originalInboundCount)
            routingPrepared?.invoke(NativeRoutingPreparation(intent, originalInboundCount, managed.getString("tag"),
                intent.sourceInboundIndex, // Imported inputs retain original order; private inputs are appended.
                protectedDns?.guardRuleIndices.orEmpty().map { it+apiRuleInsertions }))
        }
        // Match the already selected local SOCKS input. Imported duplicate or
        // untagged proxy listeners have no unambiguous counter identity.
        val selected = if (!config.PROXY_ONLY) managedInput else
            (0 until inbounds.length()).map(inbounds::getJSONObject).filter {
                !XrayPortSpec.isUnixListen(it.optString("listen")) &&
                    it.optString("protocol").lowercase() == "socks" && it.optInt("port") == config.LOCAL_SOCKS5_PORT
            }.singleOrNull()
        val selectedTag = selected?.opt("tag") as? String
        config.runtimeTrafficInboundTag = selectedTag?.takeIf { tag ->
            tag.isNotEmpty() && (0 until inbounds.length()).count { inbounds.getJSONObject(it).opt("tag") == tag } == 1
        }
        return json
    }

    /** Pure preliminary validation in the application process; service repeats before mutation. */
    fun validateConfiguration(config: XrayConfig) {
        val routingIntent=NativeRoutingSelection.decode(config.VPN_ROUTING_SELECTION_JSON, config.PROXY_ONLY)
        NativeRoutingSpec.validateOriginal(config.V2RAY_FULL_JSON_CONFIG, routingIntent)
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

    /** Only immutable APK-owned reserved names; caller JSON can never choose an executable. */
    internal fun runtimeExecutable(context: Context, routing: Boolean): File {
        val directory=File(context.applicationInfo.nativeLibraryDir)
        val preview=File(directory,"libxray_routing_preview.so")
        return if(routing && preview.exists()) preview else File(directory,"libxray.so")
    }

    /** Probe the installed executable on every requested admission/recovery, never a persisted flag. */
    internal fun supportsNativeRouting(context: Context): Boolean = try {
        val builder=ProcessBuilder(runtimeExecutable(context,true).absolutePath,
            "native-routing", "capabilities").redirectErrorStream(true)
        builder.environment().remove("FLUTTER_VLESS_PROTECT_SOCKET")
        NativeRoutingCommand.capabilities(BoundedCoreCommand.capture(builder.start(), maxBytes=4096))
    } catch (_: Exception) { false }

    /** Validate the actual native parser before replacing a working session. No raw output escapes. */
    internal fun validateNative(context: Context, configuration: NativeRuntimeConfig, geoAssetsDirectory: String? = null): Boolean =
        configuration.preflightInputs(context.noBackupFilesDir, launch = { inputs ->
            val executable=runtimeExecutable(context,configuration.hasRouting).absolutePath
            val builder = ProcessBuilder(*inputs.command(executable, check=true).toTypedArray()).redirectErrorStream(true)
            Utilities.configureXrayAssets(context, builder.environment(), geoAssetsDirectory)
            if (configuration.hasRouting) builder.environment().remove("FLUTTER_VLESS_PROTECT_SOCKET")
            builder.start()
        })

    internal fun startCore(context: Service, config: XrayConfig, configuration: NativeRuntimeConfig,
        protector: XraySocketProtector?, ownerGeneration: Long,
        admitStart: ((() -> Process) -> Process)? = null, onExit: (Long, Int) -> Unit): Boolean {
        if (!stopWorkers()) return false
        return try {
            val inputs = configuration.createInputs(context.noBackupFilesDir, "xray")
            runtimeInputs = inputs
            val executable=runtimeExecutable(context,configuration.hasRouting).absolutePath
            val builder = ProcessBuilder(*inputs.command(executable, check=false).toTypedArray())
                .directory(context.noBackupFilesDir).redirectErrorStream(true)
            Utilities.configureXrayAssets(context, builder.environment(), config.GEO_ASSETS_DIRECTORY)
            if (protector != null) builder.environment()["FLUTTER_VLESS_PROTECT_SOCKET"] = protector.socketName
            // The optional owner gate linearizes only launch admission, never readiness or success.
            val process = if (admitStart == null) builder.start() else admitStart { builder.start() }
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
            clearTrafficBaselines()
            true
        } catch (_: Exception) { stopWorkers(); false }
    }

    /** An identity snapshot, not a readiness result. Startup checks this exact
     * child and its session generation around every bounded probe operation. */
    internal fun currentCoreProcess(): Process? = xrayProcess
    internal fun ownsCoreProcess(candidate: Process): Boolean = xrayProcess === candidate && candidate.isAlive

    @Synchronized internal fun stopWorkers(): Boolean {
        clearTrafficBaselines()
        val process = xrayProcess
        xrayProcess = null // Invalidate callbacks before signaling the old process.
        if (process != null) {
            process.destroy()
            if (!process.waitFor(1, TimeUnit.SECONDS)) process.destroyForcibly()
            if (!process.waitFor(1, TimeUnit.SECONDS)) { xrayProcess = process; return false }
        }
        runtimeInputs?.close(); runtimeInputs = null
        return true
    }

    fun isXrayRunning() = AppConfigs.V2RAY_STATE != AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED
    fun getProviderDebugSnapshot(context: Context) = XrayDiagnosticsStore.snapshot(context.filesDir)

    internal fun publishState(context: Context, state: AppConfigs.V2RAY_STATES, seconds: Long = 0) {
        val changed = AppConfigs.V2RAY_STATE != state
        AppConfigs.V2RAY_STATE = state
        if (changed) com.github.tfox.flutter_vless.NativeQuickAccess.refresh(context)
        val traffic = if (state == AppConfigs.V2RAY_STATES.V2RAY_CONNECTED) getV2rayTraffic(context)
            else { clearTrafficBaselines(); longArrayOf(0, 0, 0, 0) }
        context.sendBroadcast(Intent(AppConfigs.V2RAY_CONNECTION_INFO).setPackage(context.packageName)
            .putExtra("STATE", state).putExtra("DURATION", seconds.toString())
            .putExtra("UPLOAD_SPEED", traffic[0]).putExtra("DOWNLOAD_SPEED", traffic[1])
            .putExtra("UPLOAD_TRAFFIC", traffic[2]).putExtra("DOWNLOAD_TRAFFIC", traffic[3]))
    }

    internal fun statsQueryPort(config: XrayConfig?): Int? = config?.LOCAL_API_PORT?.takeIf { it in 1..65535 }

    internal data class TrafficSample(val uplink: Long? = null, val downlink: Long? = null)

    private fun clearTrafficBaselines() { lastProxyUplink = null; lastProxyDownlink = null }

    internal fun readTraffic(context: Context): TrafficSample {
        val config = AppConfigs.V2RAY_CONFIG ?: return TrafficSample()
        val apiPort = statsQueryPort(config) ?: return TrafficSample()
        val tag = config.runtimeTrafficInboundTag ?: return TrafficSample()
        val owner = xrayProcess?.takeIf { it.isAlive } ?: return TrafficSample()
        return try {
            val process = ProcessBuilder(File(context.applicationInfo.nativeLibraryDir, "libxray.so").absolutePath,
                "api", "statsquery", "--server=127.0.0.1:$apiPort", "--pattern", "inbound>>>$tag>>>traffic>>>")
                .redirectErrorStream(true).start()
            // Stats are bounded and parsed locally; never included in diagnostics.
            val output = BoundedCoreCommand.capture(process)?.toString(Charsets.UTF_8)
                ?: return TrafficSample()
            if (xrayProcess !== owner || !owner.isAlive || AppConfigs.V2RAY_CONFIG !== config) return TrafficSample()
            val decoder = JSONTokener(output)
            val root = decoder.nextValue()
            if (root !is JSONObject || decoder.nextClean() != '\u0000') return TrafficSample()
            val stats = root.optJSONArray("stat") ?: return TrafficSample()
            fun direction(name: String): Long? {
                val matches = (0 until stats.length()).mapNotNull(stats::optJSONObject)
                    .filter { it.opt("name") == "inbound>>>$tag>>>traffic>>>$name" }
                val stat = matches.singleOrNull() ?: return null
                // The pinned CLI omits proto int64 value at zero. The named
                // counter still exists; a missing row means unavailable.
                if (!stat.has("value")) return 0
                val value = stat.opt("value") as? Number ?: return null
                return value.toString().toLongOrNull()?.takeIf { it >= 0 }
            }
            TrafficSample(direction("uplink"), direction("downlink"))
        } catch (_: Exception) { TrafficSample() }
    }

    fun getV2rayTraffic(context: Context): LongArray {
        val sample = readTraffic(context)
        fun delta(current: Long?, previous: Long?): Long =
            if (current != null && previous != null && current >= previous) current - previous else 0
        return longArrayOf(delta(sample.uplink, lastProxyUplink), delta(sample.downlink, lastProxyDownlink),
            sample.uplink ?: 0, sample.downlink ?: 0).also {
            lastProxyUplink = sample.uplink
            lastProxyDownlink = sample.downlink
        }
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
