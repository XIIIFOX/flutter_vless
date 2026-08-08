package com.github.tfox.flutter_vless.xray.core

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Build
import android.os.CountDownTimer
import android.util.Log
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.service.XrayVPNService
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import com.github.tfox.flutter_vless.xray.utils.Utilities
import org.json.JSONObject
import org.json.JSONArray
import java.io.File
import java.io.FileOutputStream

/**
 * Manages the Xray Core process (libxray.so).
 * 
 * This singleton object is responsible for:
 * 1. Generating the final Xray configuration file (config.json).
 * 2. Injecting necessary inbounds (SOCKS, HTTP, API) into the user-provided config.
 * 3. Starting and monitoring the Xray process.
 * 4. Collecting traffic statistics via the Xray API.
 * 5. Showing the persistent foreground notification.
 */
object XrayCoreManager {

    private const val NOTIFICATION_ID = 1
    private const val TAG = "XrayCoreManager"
    private var xrayProcess: Process? = null
    private var countDownTimer: CountDownTimer? = null
    private var seconds = 0
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

            val user = JSONObject()
            user.put("id", id)
            user.put("encryption", settings.optString("encryption", "none"))
            user.put("flow", settings.optString("flow", ""))
            user.put("level", settings.optInt("level", 8))

            val server = JSONObject()
            server.put("address", address)
            server.put("port", port)
            server.put("users", JSONArray().put(user))

            val normalizedSettings = JSONObject()
            normalizedSettings.put("vnext", JSONArray().put(server))
            outbound.put("settings", normalizedSettings)
            Log.d(TAG, "Normalized flat VLESS outbound settings for $address:$port")
        }
    }

    private fun sanitizeLogPaths(configJson: JSONObject, filesDir: File) {
        val log = configJson.optJSONObject("log") ?: return
        val accessPath = log.optString("access")
        val errorPath = log.optString("error")

        if (accessPath.isNotEmpty()) {
            log.put("access", File(filesDir, "access.log").absolutePath)
        }
        if (errorPath.isNotEmpty()) {
            log.put("error", File(filesDir, "error.log").absolutePath)
        }
    }

    internal fun buildRuntimeConfigJson(config: XrayConfig, filesDir: File): JSONObject {
        val configJson = normalizeRuntimeConfig(
            JSONObject(config.V2RAY_FULL_JSON_CONFIG)
        ) as JSONObject
        normalizeVlessOutbounds(configJson)
        sanitizeLogPaths(configJson, filesDir)

        // Android needs local control surfaces that may not exist in imported
        // Xray JSON. Keep this pure so unit tests can verify the exact config
        // handed to libxray without launching VPN services or native binaries.
        val apiObj = JSONObject()
        apiObj.put("tag", "api")
        apiObj.put("services", JSONArray().put("StatsService"))
        configJson.put("api", apiObj)

        configJson.put("stats", JSONObject())

        val policyObj = JSONObject()
        val levelsObj = JSONObject()
        val level8Obj = JSONObject()
        level8Obj.put("statsUserUplink", true)
        level8Obj.put("statsUserDownlink", true)
        levelsObj.put("8", level8Obj)

        val systemObj = JSONObject()
        systemObj.put("statsInboundUplink", true)
        systemObj.put("statsInboundDownlink", true)
        systemObj.put("statsOutboundUplink", true)
        systemObj.put("statsOutboundDownlink", true)

        policyObj.put("levels", levelsObj)
        policyObj.put("system", systemObj)
        configJson.put("policy", policyObj)

        val inbounds = configJson.optJSONArray("inbounds") ?: JSONArray()
        val usedPorts = mutableSetOf<Int>()
        var hasSocksOnLocalPort = false
        var hasHttpOnLocalPort = false
        for (i in 0 until inbounds.length()) {
            val inbound = inbounds.getJSONObject(i)
            val protocol = inbound.optString("protocol")
            val port = inbound.optInt("port", -1)
            if (port > 0) usedPorts.add(port)
            if (protocol == "socks" && port == config.LOCAL_SOCKS5_PORT) hasSocksOnLocalPort = true
            if (protocol == "http" && port == config.LOCAL_HTTP_PORT) hasHttpOnLocalPort = true
        }

        if (!hasSocksOnLocalPort) {
            if (usedPorts.contains(config.LOCAL_SOCKS5_PORT)) {
                config.LOCAL_SOCKS5_PORT = nextFreePort(config.LOCAL_SOCKS5_PORT, usedPorts)
            }
            val socksInbound = JSONObject()
            socksInbound.put("tag", uniqueInboundTag(inbounds, "socks"))
            socksInbound.put("port", config.LOCAL_SOCKS5_PORT)
            socksInbound.put("listen", "127.0.0.1")
            socksInbound.put("protocol", "socks")
            socksInbound.put("settings", JSONObject().put("auth", "noauth").put("udp", true))
            socksInbound.put(
                "sniffing",
                JSONObject().put("enabled", true).put("destOverride", JSONArray().put("http").put("tls"))
            )
            inbounds.put(socksInbound)
            usedPorts.add(config.LOCAL_SOCKS5_PORT)
            Log.d(TAG, "Injected SOCKS inbound on port ${config.LOCAL_SOCKS5_PORT}")
        }

        if (!hasHttpOnLocalPort) {
            if (usedPorts.contains(config.LOCAL_HTTP_PORT)) {
                config.LOCAL_HTTP_PORT = nextFreePort(config.LOCAL_HTTP_PORT, usedPorts)
            }
            val httpInbound = JSONObject()
            httpInbound.put("tag", uniqueInboundTag(inbounds, "http"))
            httpInbound.put("port", config.LOCAL_HTTP_PORT)
            httpInbound.put("listen", "127.0.0.1")
            httpInbound.put("protocol", "http")
            inbounds.put(httpInbound)
            usedPorts.add(config.LOCAL_HTTP_PORT)
            Log.d(TAG, "Injected HTTP inbound on port ${config.LOCAL_HTTP_PORT}")
        }

        if (usedPorts.contains(config.LOCAL_API_PORT)) {
            config.LOCAL_API_PORT = nextFreePort(config.LOCAL_API_PORT, usedPorts)
        }
        val apiInboundTag = uniqueInboundTag(inbounds, "api")
        val apiInbound = JSONObject()
        apiInbound.put("tag", apiInboundTag)
        apiInbound.put("port", config.LOCAL_API_PORT)
        apiInbound.put("listen", "127.0.0.1")
        apiInbound.put("protocol", "dokodemo-door")
        apiInbound.put("settings", JSONObject().put("address", "127.0.0.1"))
        inbounds.put(apiInbound)
        configJson.put("inbounds", inbounds)

        val routing = configJson.optJSONObject("routing") ?: JSONObject()
        val rules = routing.optJSONArray("rules") ?: JSONArray()
        val apiRule = JSONObject()
        apiRule.put("type", "field")
        apiRule.put("inboundTag", JSONArray().put(apiInboundTag))
        apiRule.put("outboundTag", "api")
        rules.put(apiRule)
        routing.put("rules", rules)
        configJson.put("routing", routing)

        return configJson
    }

    internal fun buildDelayConfigJson(configJson: String, proxyPort: Int, filesDir: File): Pair<JSONObject, Int> {
        val delayConfig = XrayConfig(
            V2RAY_FULL_JSON_CONFIG = configJson,
            LOCAL_SOCKS5_PORT = proxyPort,
            LOCAL_HTTP_PORT = proxyPort + 1,
            LOCAL_API_PORT = proxyPort + 2
        )
        val runtimeJson = buildRuntimeConfigJson(delayConfig, filesDir)
        return Pair(runtimeJson, delayConfig.LOCAL_SOCKS5_PORT)
    }

    /**
     * Starts the Xray Core process.
     * 
     * @param context The service context (needed for file access and notifications).
     * @param config The configuration object containing the user's settings.
     * @return true if started successfully, false otherwise.
     */
    fun startCore(context: Service, config: XrayConfig): Boolean {
        AppConfigs.V2RAY_STATE = AppConfigs.V2RAY_STATES.V2RAY_CONNECTING
        AppConfigs.V2RAY_CONFIG = config

        // 1. Prepare the configuration file
        val configFilesDir = context.filesDir
        
        try {
            val configJson = buildRuntimeConfigJson(config, configFilesDir)
            val configFile = File(context.filesDir, "config.json")
            configFile.writeText(configJson.toString())
        } catch (e: Exception) {
            Log.e(TAG, "Failed to write config file", e)
            return abortStart(context)
        }

        // 2. Find Xray executable (libxray.so)
        val nativeLibraryDir = context.applicationInfo.nativeLibraryDir
        val xrayExecutable = File(nativeLibraryDir, "libxray.so")
        if (!xrayExecutable.exists()) {
            Log.e(TAG, "Xray executable not found at ${xrayExecutable.absolutePath}")
            // Fallback or error
            return abortStart(context)
        }

        // 3. Prepare assets (geoip, geosite)
        Utilities.copyAssets(context)

        // 4. Run Xray
        try {
            val cmd = listOf(
                xrayExecutable.absolutePath,
                "-config", File(configFilesDir, "config.json").absolutePath
            )
            val pb = ProcessBuilder(cmd)
            pb.directory(configFilesDir)
            pb.redirectErrorStream(true)
            
            // Set environment variables (XRAY_LOCATION_ASSET is crucial for finding geoip/geosite)
            val env = pb.environment()
            env["XRAY_LOCATION_ASSET"] = Utilities.getUserAssetsPath(context)

            xrayProcess = pb.start()
            Thread.sleep(300)
            if (xrayProcess?.isAlive != true) {
                val output = xrayProcess?.inputStream?.bufferedReader()?.readText().orEmpty()
                Log.e(TAG, "Xray process exited during startup. Output: $output")
                xrayProcess = null
                return abortStart(context)
            }
            
            AppConfigs.V2RAY_STATE = AppConfigs.V2RAY_STATES.V2RAY_CONNECTED
            lastProxyUplink = 0L
            lastProxyDownlink = 0L
            sendCurrentStateBroadcast(context)
            startTimer(context)
            showNotification(context, config)
            
            // Monitor process in a separate thread to detect crash
            Thread {
                try {
                    xrayProcess?.inputStream?.bufferedReader()?.use { reader ->
                        reader.forEachLine { line ->
                            Log.d(TAG, "xray: $line")
                        }
                    }
                    
                    val exitCode = xrayProcess?.waitFor()
                    Log.e(TAG, "Xray process exited with code $exitCode")
                    if (AppConfigs.V2RAY_STATE == AppConfigs.V2RAY_STATES.V2RAY_CONNECTED) {
                        // Unexpected exit
                        stopCore(context)
                    }
                } catch (e: java.io.InterruptedIOException) {
                    // Expected when stopping
                } catch (e: InterruptedException) {
                    // Expected when stopping
                } catch (e: Exception) {
                    Log.e(TAG, "Error reading xray output", e)
                }
            }.start()

            return true

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start Xray process", e)
            return abortStart(context)
        }
    }

    private fun abortStart(context: Service): Boolean {
        AppConfigs.V2RAY_STATE = AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED
        sendDisconnectedBroadcast(context)
        return false
    }

    /**
     * Stops the Xray Core process and cleans up notifications.
     */
    fun stopCore(context: Service) {
        try {
            xrayProcess?.destroy()
            xrayProcess = null
        } catch (e: Exception) {
            Log.e(TAG, "Failed to destroy Xray process", e)
        }

        AppConfigs.V2RAY_STATE = AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED
        stopTimer()
        
        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.cancel(NOTIFICATION_ID)
        
        sendDisconnectedBroadcast(context)
    }

    fun isXrayRunning(): Boolean {
        // Check state instead of process because VPN runs in separate service process
        return AppConfigs.V2RAY_STATE == AppConfigs.V2RAY_STATES.V2RAY_CONNECTED ||
               AppConfigs.V2RAY_STATE == AppConfigs.V2RAY_STATES.V2RAY_CONNECTING
    }

    private fun startTimer(context: Context) {
        countDownTimer?.cancel()
        seconds = 0
        countDownTimer = object : CountDownTimer(Long.MAX_VALUE, 1000) {
            override fun onTick(millisUntilFinished: Long) {
                seconds++
                val intent = Intent(AppConfigs.V2RAY_CONNECTION_INFO)
                intent.putExtra("STATE", AppConfigs.V2RAY_STATE)
                intent.putExtra("DURATION", seconds.toString())
                
                val traffic = getV2rayTraffic(context)
                intent.putExtra("UPLOAD_SPEED", traffic[0])
                intent.putExtra("DOWNLOAD_SPEED", traffic[1])
                intent.putExtra("UPLOAD_TRAFFIC", traffic[2])
                intent.putExtra("DOWNLOAD_TRAFFIC", traffic[3])
                
                deliverConnectionBroadcast(context, intent)
            }

            override fun onFinish() {}
        }.start()
    }

    fun sendCurrentStateBroadcast(context: Context) {
        val intent = Intent(AppConfigs.V2RAY_CONNECTION_INFO)
        intent.putExtra("STATE", AppConfigs.V2RAY_STATE)
        intent.putExtra("DURATION", seconds.toString())
        if (isXrayRunning()) {
            val traffic = getV2rayTraffic(context)
            intent.putExtra("UPLOAD_SPEED", traffic[0])
            intent.putExtra("DOWNLOAD_SPEED", traffic[1])
            intent.putExtra("UPLOAD_TRAFFIC", traffic[2])
            intent.putExtra("DOWNLOAD_TRAFFIC", traffic[3])
        } else {
            intent.putExtra("UPLOAD_SPEED", 0L)
            intent.putExtra("DOWNLOAD_SPEED", 0L)
            intent.putExtra("UPLOAD_TRAFFIC", 0L)
            intent.putExtra("DOWNLOAD_TRAFFIC", 0L)
        }
        deliverConnectionBroadcast(context, intent)
    }

    private fun deliverConnectionBroadcast(context: Context, intent: Intent) {
        val state = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getSerializableExtra("STATE", AppConfigs.V2RAY_STATES::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getSerializableExtra("STATE") as? AppConfigs.V2RAY_STATES
        }
        if (state != null && !intent.hasExtra("STATE_NAME")) {
            intent.putExtra("STATE_NAME", state.name)
        }
        intent.setPackage(context.packageName)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY)
        }
        context.sendBroadcast(intent)
    }

    /**
     * Queries Xray's stats API for traffic sent through the application proxy.
     *
     * The generated configurations give the remote VLESS outbound the stable
     * `proxy` tag. Counters for injected `api`, `direct`, and `blackhole`
     * routes are intentionally ignored: polling the API itself generates
     * bytes and would otherwise make a broken tunnel look active.
     *
     * @return `[uploadSpeed, downloadSpeed, totalUpload, totalDownload]`,
     * where speed is the delta since the previous one-second timer tick.
     */
    fun getV2rayTraffic(context: Context): LongArray {
        if (!isXrayRunning()) return longArrayOf(0, 0, 0, 0)

        val xrayPath = File(context.applicationInfo.nativeLibraryDir, "libxray.so").absolutePath
        val cmd = arrayListOf(
            xrayPath,
            "api",
            "statsquery",
            "--server=127.0.0.1:${AppConfigs.V2RAY_CONFIG?.LOCAL_API_PORT ?: 10809}",
            "--pattern", ""
        )

        try {
            val pb = ProcessBuilder(cmd)
            val process = pb.start()
            val output = process.inputStream.bufferedReader().readText()
            process.waitFor()

            if (output.isNotEmpty()) {
                Log.d(TAG, "Stats query output: $output")
                val json = JSONObject(output)
                val stats = json.optJSONArray("stat") ?: return longArrayOf(0, 0, 0, 0)

                var proxyUplink = 0L
                var proxyDownlink = 0L

                for (i in 0 until stats.length()) {
                    val stat = stats.getJSONObject(i)
                    val name = stat.optString("name")
                    val value = stat.optLong("value")

                    if (name == "outbound>>>proxy>>>traffic>>>uplink") {
                        proxyUplink = value
                    } else if (name == "outbound>>>proxy>>>traffic>>>downlink") {
                        proxyDownlink = value
                    }
                }

                val uploadSpeed = (proxyUplink - lastProxyUplink).coerceAtLeast(0L)
                val downloadSpeed = (proxyDownlink - lastProxyDownlink).coerceAtLeast(0L)
                lastProxyUplink = proxyUplink
                lastProxyDownlink = proxyDownlink

                return longArrayOf(uploadSpeed, downloadSpeed, proxyUplink, proxyDownlink)
            } else {
                Log.d(TAG, "Stats query returned empty output")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to query stats", e)
        }
        return longArrayOf(0, 0, 0, 0)
    }

    private fun stopTimer() {
        countDownTimer?.cancel()
        countDownTimer = null
        seconds = 0
        lastProxyUplink = 0L
        lastProxyDownlink = 0L
    }

    private fun sendDisconnectedBroadcast(context: Context) {
        val intent = Intent(AppConfigs.V2RAY_CONNECTION_INFO)
        intent.putExtra("STATE", AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED)
        intent.putExtra("DURATION", "0")
        intent.putExtra("UPLOAD_SPEED", 0L)
        intent.putExtra("DOWNLOAD_SPEED", 0L)
        intent.putExtra("UPLOAD_TRAFFIC", 0L)
        intent.putExtra("DOWNLOAD_TRAFFIC", 0L)
        deliverConnectionBroadcast(context, intent)
    }

    private fun showNotification(context: Service, config: XrayConfig) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ActivityCompat.checkSelfPermission(context, android.Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                return
            }
        }

        val channelId = createNotificationChannel(context, config.APPLICATION_NAME)
        
        val launchIntent = context.packageManager.getLaunchIntentForPackage(context.packageName)
        launchIntent?.action = "FROM_DISCONNECT_BTN"
        launchIntent?.flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_NEW_TASK
        
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT else PendingIntent.FLAG_UPDATE_CURRENT
        val contentPendingIntent = PendingIntent.getActivity(context, 0, launchIntent, flags)

        val stopIntent = Intent(context, XrayVPNService::class.java)
        stopIntent.putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE)
        val stopPendingIntent = PendingIntent.getService(context, 0, stopIntent, flags)
        val smallIcon = if (config.APPLICATION_ICON != 0) config.APPLICATION_ICON else android.R.drawable.ic_dialog_info

        val builder = NotificationCompat.Builder(context, channelId)
            .setSmallIcon(smallIcon)
            .setContentTitle(config.REMARK)
            .setContentText("Connected")
            .addAction(0, config.NOTIFICATION_DISCONNECT_BUTTON_NAME, stopPendingIntent)
            .setContentIntent(contentPendingIntent)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setOngoing(true)
            .setShowWhen(true)

        context.startForeground(NOTIFICATION_ID, builder.build())
    }

    fun getConnectedV2rayServerDelay(context: Context, url: String): Long {
        // Use the configured SOCKS port (default 10807)
        val port = AppConfigs.V2RAY_CONFIG?.LOCAL_SOCKS5_PORT ?: 10807
        Log.d(TAG, "getConnectedV2rayServerDelay: Testing delay to $url via SOCKS port $port")
        
        return try {
            val start = System.currentTimeMillis()
            val proxy = java.net.Proxy(java.net.Proxy.Type.SOCKS, java.net.InetSocketAddress("127.0.0.1", port))
            val connection = java.net.URL(url).openConnection(proxy) as java.net.HttpURLConnection
            connection.connectTimeout = 5000
            connection.readTimeout = 5000
            connection.requestMethod = "HEAD"
            val responseCode = connection.responseCode
            val end = System.currentTimeMillis()
            val delay = end - start
            connection.disconnect()
            Log.d(TAG, "getConnectedV2rayServerDelay: Success! Response code: $responseCode, Delay: ${delay}ms")
            delay
        } catch (e: Exception) {
            Log.e(TAG, "getConnectedV2rayServerDelay: Failed to measure delay (VPN may not be running)", e)
            -1L
        }
    }

    /**
     * Measure delay for a server configuration (when not connected).
     * Temporarily starts Xray with the provided config, measures delay, then stops it.
     */
    fun getServerDelay(context: Context, configJson: String, url: String): Long {
        Log.d(TAG, "getServerDelay: Starting temporary Xray instance")
        
        var tempProcess: Process? = null
        try {
            // Find a random free port to avoid conflict with running VPN
            val freePort = try {
                val socket = java.net.ServerSocket(0)
                val port = socket.localPort
                socket.close()
                port
            } catch (e: Exception) {
                10806 // Fallback
            }
            
            val (json, socksPort) = buildDelayConfigJson(configJson, freePort, context.filesDir)
            Log.d(TAG, "getServerDelay: Using SOCKS port $socksPort")
            
            // Write temp config file
            val tempConfigFile = File(context.filesDir, "temp_delay_config.json")
            tempConfigFile.writeText(json.toString())
            
            // Copy assets
            Utilities.copyAssets(context)
            
            // Start Xray process
            val xrayExecutable = File(context.applicationInfo.nativeLibraryDir, "libxray.so")
            if (!xrayExecutable.exists()) {
                Log.e(TAG, "getServerDelay: Xray executable not found")
                return -1L
            }
            
            val cmd = listOf(
                xrayExecutable.absolutePath,
                "-config", tempConfigFile.absolutePath
            )
            
            val pb = ProcessBuilder(cmd)
            pb.directory(context.filesDir)
            val env = pb.environment()
            env["XRAY_LOCATION_ASSET"] = Utilities.getUserAssetsPath(context)
            
            tempProcess = pb.start()
            
            // Wait a bit for Xray to start
            Thread.sleep(1000)
            
            // Measure delay
            val delay = try {
                val start = System.currentTimeMillis()
                val proxy = java.net.Proxy(java.net.Proxy.Type.SOCKS, java.net.InetSocketAddress("127.0.0.1", socksPort))
                val connection = java.net.URL(url).openConnection(proxy) as java.net.HttpURLConnection
                connection.connectTimeout = 5000
                connection.readTimeout = 5000
                connection.requestMethod = "HEAD"
                val responseCode = connection.responseCode
                val end = System.currentTimeMillis()
                connection.disconnect()
                val result = end - start
                Log.d(TAG, "getServerDelay: Success! Response code: $responseCode, Delay: ${result}ms")
                result
            } catch (e: Exception) {
                Log.e(TAG, "getServerDelay: Failed to measure delay", e)
                -1L
            }
            
            // Stop temp process
            tempProcess?.destroy()
            tempConfigFile.delete()
            
            return delay
            
        } catch (e: Exception) {
            Log.e(TAG, "getServerDelay: Error starting temp Xray", e)
            tempProcess?.destroy()
            return -1L
        }
    }

    private fun createNotificationChannel(context: Context, appName: String): String {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channelId = "XRAY_SERVICE_CHANNEL"
            val channelName = "$appName Background Service"
            val channel = NotificationChannel(channelId, channelName, NotificationManager.IMPORTANCE_DEFAULT)
            channel.lightColor = Color.BLUE
            channel.lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
            return channelId
        }
        return ""
    }
}
