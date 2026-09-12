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
import java.net.ServerSocket
import java.util.UUID
import java.util.concurrent.TimeUnit

/** Process owner delegates all session transitions to XrayVPNService. */
object XrayCoreManager {
    @Volatile private var xrayProcess: Process? = null
    private var runtimeFile: File? = null
    private var lastProxyUplink = 0L
    private var lastProxyDownlink = 0L
    private fun nextFreePort(preferredPort: Int, usedPorts: Set<Int>): Int {
        var port = preferredPort
        while (usedPorts.contains(port)) {
            port++
        }
        return port
    }

    private fun uniqueInboundTag(inbounds: JSONArray, preferredTag: String): String {
        val tags = mutableSetOf<String>()
        for (i in 0 until inbounds.length()) {
            val tag = inbounds.optJSONObject(i)?.optString("tag").orEmpty()
            if (tag.isNotEmpty()) tags.add(tag)
        }

        if (!tags.contains(preferredTag)) return preferredTag

        var index = 1
        var candidate = "${preferredTag}_$index"
        while (tags.contains(candidate)) {
            index++
            candidate = "${preferredTag}_$index"
        }
        return candidate
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
        credentials: LocalProxyCredentials? = null): JSONObject {
        val json = normalizeRuntimeConfig(JSONObject(config.V2RAY_FULL_JSON_CONFIG)) as JSONObject
        LocalProxyAccessPolicy.normalizeConfigInputs(json)
        normalizeVlessOutbounds(json)
        require(json.optJSONArray("outbounds")?.length()?.let { it > 0 } == true) { "At least one outbound is required" }
        // Raw native logs can contain addresses and secrets even at error level.
        json.put("log", JSONObject().put("loglevel", "none").put("access", "none").put("error", "none"))
        val inbounds = json.optJSONArray("inbounds") ?: JSONArray()
        val used = mutableSetOf<Int>()
        var hasSocks = false
        for (i in 0 until inbounds.length()) {
            val inbound = inbounds.getJSONObject(i)
            val port = inbound.optInt("port", -1)
            if (port > 0) used.add(port)
            if (inbound.optString("protocol") == "socks" && port == config.LOCAL_SOCKS5_PORT) hasSocks = true
        }
        if (!hasSocks) {
            config.LOCAL_SOCKS5_PORT = nextFreePort(config.LOCAL_SOCKS5_PORT, used)
            inbounds.put(JSONObject().put("tag", uniqueInboundTag(inbounds, "socks"))
                .put("listen", "127.0.0.1").put("port", config.LOCAL_SOCKS5_PORT).put("protocol", "socks")
                .put("settings", JSONObject().put("auth", "noauth").put("udp", true))
                .put("sniffing", JSONObject().put("enabled", true).put("routeOnly", true)
                    .put("destOverride", JSONArray().put("http").put("tls"))))
            used.add(config.LOCAL_SOCKS5_PORT)
        }
        if (!config.PROXY_ONLY) {
            LocalProxyAccessPolicy.apply(inbounds, requireNotNull(credentials) { "Native local credentials are required" }, config.LOCAL_SOCKS5_PORT)
            requireProtectedSocketSupport(json)
        } else {
            LocalProxyAccessPolicy.credentialsForProxyOnly(JSONObject().put("inbounds", inbounds), config.LOCAL_SOCKS5_PORT)
        }
        // Keep StatsService, but do not create an unsolicited HTTP proxy.
        require((json.optJSONArray("outbounds") ?: JSONArray()).let { array ->
            (0 until array.length()).none { array.getJSONObject(it).optString("tag") == "api" }
        }) { "Reserved API outbound tag collision" }
        json.put("api", JSONObject().put("tag", "api").put("services", JSONArray().put("StatsService")))
        json.put("stats", JSONObject())
        val policy = json.optJSONObject("policy") ?: JSONObject()
        val system = policy.optJSONObject("system") ?: JSONObject()
        system.put("statsOutboundUplink", true).put("statsOutboundDownlink", true)
        policy.put("system", system)
        json.put("policy", policy)
        config.LOCAL_API_PORT = nextFreePort(config.LOCAL_API_PORT, used)
        val apiTag = uniqueInboundTag(inbounds, "api")
        inbounds.put(JSONObject().put("tag", apiTag).put("port", config.LOCAL_API_PORT).put("listen", "127.0.0.1")
            .put("protocol", "dokodemo-door").put("settings", JSONObject().put("address", "127.0.0.1")))
        json.put("inbounds", inbounds)
        val routing = json.optJSONObject("routing") ?: JSONObject()
        val rules = JSONArray().put(JSONObject().put("type", "field").put("inboundTag", JSONArray().put(apiTag)).put("outboundTag", "api"))
        routing.optJSONArray("rules")?.let { for (i in 0 until it.length()) rules.put(it.get(i)) }
        routing.put("rules", rules)
        json.put("routing", routing)
        return json
    }

    /** Pure preliminary validation in the application process; service repeats before mutation. */
    fun validateConfiguration(config: XrayConfig) {
        require(config.ANDROID_DNS_POLICY in setOf("config", "proxy")) { "Unsupported Android DNS policy" }
        require(!(config.PROXY_ONLY && config.ANDROID_DNS_POLICY == "proxy")) { "Proxy DNS requires VPN mode" }
        AndroidTunnelDnsPolicy.validate(config.V2RAY_FULL_JSON_CONFIG, config.ANDROID_DNS_POLICY,
            config.ANDROID_DNS_PROXY_OUTBOUND_TAG, config.BYPASS_SUBNETS)
        buildRuntimeConfigJson(config.copy(), File("."), LocalProxyCredentials.generate())
    }

    internal fun buildDelayConfigJson(configJson: String, proxyPort: Int, filesDir: File,
        credentials: LocalProxyCredentials): Pair<JSONObject, Int> {
        // A standalone measurement owns a single temporary input; imported listeners never open.
        val json = JSONObject(configJson).put("inbounds", JSONArray())
        val config = XrayConfig(V2RAY_FULL_JSON_CONFIG = json.toString(), LOCAL_SOCKS5_PORT = proxyPort, LOCAL_API_PORT = proxyPort + 1)
        return buildRuntimeConfigJson(config, filesDir, credentials) to config.LOCAL_SOCKS5_PORT
    }

    /** Validate the actual native parser before replacing a working session. No raw output escapes. */
    internal fun validateNative(context: Context, json: JSONObject): Boolean {
        val file = File(context.noBackupFilesDir, "validate-${UUID.randomUUID()}.json")
        return try {
            file.writeText(json.toString())
            Utilities.copyAssets(context)
            val builder = ProcessBuilder(File(context.applicationInfo.nativeLibraryDir, "libxray.so").absolutePath,
                "run", "-test", "-config", file.absolutePath).redirectErrorStream(true)
            builder.environment()["XRAY_LOCATION_ASSET"] = Utilities.getUserAssetsPath(context)
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
            Utilities.copyAssets(context)
            val builder = ProcessBuilder(File(context.applicationInfo.nativeLibraryDir, "libxray.so").absolutePath,
                "run", "-config", file.absolutePath).directory(context.noBackupFilesDir).redirectErrorStream(true)
            builder.environment()["XRAY_LOCATION_ASSET"] = Utilities.getUserAssetsPath(context)
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
        AppConfigs.V2RAY_STATE = state
        val traffic = if (state == AppConfigs.V2RAY_STATES.V2RAY_CONNECTED) getV2rayTraffic(context) else longArrayOf(0, 0, 0, 0)
        context.sendBroadcast(Intent(AppConfigs.V2RAY_CONNECTION_INFO).setPackage(context.packageName)
            .putExtra("STATE", state).putExtra("DURATION", seconds.toString())
            .putExtra("UPLOAD_SPEED", traffic[0]).putExtra("DOWNLOAD_SPEED", traffic[1])
            .putExtra("UPLOAD_TRAFFIC", traffic[2]).putExtra("DOWNLOAD_TRAFFIC", traffic[3]))
    }

    fun getV2rayTraffic(context: Context): LongArray {
        if (xrayProcess?.isAlive != true) return longArrayOf(0, 0, 0, 0)
        return try {
            val process = ProcessBuilder(File(context.applicationInfo.nativeLibraryDir, "libxray.so").absolutePath,
                "api", "statsquery", "--server=127.0.0.1:${AppConfigs.V2RAY_CONFIG?.LOCAL_API_PORT ?: 10809}", "--pattern", "outbound>>>proxy>>>").start()
            // Stats are bounded and parsed locally; never included in diagnostics.
            val output = process.inputStream.bufferedReader().readText().take(64 * 1024)
            if (!process.waitFor(2, TimeUnit.SECONDS)) { process.destroyForcibly(); return longArrayOf(0, 0, 0, 0) }
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

    fun getServerDelay(context: Context, configJson: String, url: String): Long {
        var process: Process? = null
        val file = File(context.noBackupFilesDir, "delay-${UUID.randomUUID()}.json")
        return try {
            val port = ServerSocket(0).use { it.localPort }
            val credentials = LocalProxyCredentials.generate()
            val (json, socksPort) = buildDelayConfigJson(configJson, port, context.noBackupFilesDir, credentials)
            file.writeText(json.toString())
            Utilities.copyAssets(context)
            val builder = ProcessBuilder(File(context.applicationInfo.nativeLibraryDir, "libxray.so").absolutePath,
                "run", "-config", file.absolutePath).directory(context.noBackupFilesDir).redirectErrorStream(true)
            builder.environment()["XRAY_LOCATION_ASSET"] = Utilities.getUserAssetsPath(context)
            process = builder.start()
            drain(process)
            repeat(20) {
                if (process?.isAlive != true) return -1
                try { return AuthenticatedSocksClient.measure(socksPort, credentials, url) }
                catch (_: Exception) { Thread.sleep(100) }
            }
            -1
        } catch (_: Exception) { -1 } finally {
            process?.destroy()
            if (process?.waitFor(1, TimeUnit.SECONDS) == false) process?.destroyForcibly()
            file.delete()
        }
    }

    private fun drain(process: Process): Thread = Thread({
        runCatching { process.inputStream.use { val bytes = ByteArray(4096); while (it.read(bytes) >= 0) { } } }
    }, "xray-output-discard").apply { isDaemon = true; start() }
}
