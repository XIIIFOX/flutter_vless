package com.github.tfox.flutter_vless.xray.service

import android.content.Intent
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.github.tfox.flutter_vless.xray.core.XrayCoreManager
import com.github.tfox.flutter_vless.xray.core.XrayDiagnosticsStore
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import org.json.JSONObject
import java.io.File
import java.io.FileDescriptor
import java.util.ArrayList

/**
 * Android VPN Service implementation.
 * 
 * This service is responsible for:
 * 1. Establishing the VPN interface (TUN device) using Android's VpnService API.
 * 2. Managing the `tun2socks` process, which routes traffic from the TUN device to the SOCKS proxy.
 * 3. Handling the lifecycle of the VPN connection (start, stop, cleanup).
 * 4. Supporting "Proxy Only" mode where VPN is skipped.
 * 
 * Key Technical Detail:
 * To support Android 15 (16KB page size) and avoid "bad file descriptor" errors, we use a custom
 * mechanism to pass the TUN file descriptor to `tun2socks`. Instead of passing it via command line
 * (which fails across process boundaries), we send it over a Unix Domain Socket.
 */
class XrayVPNService : VpnService() {

    private var mInterface: ParcelFileDescriptor? = null
    private var tun2socksProcess: Process? = null
    private var isRunning = false

    override fun onCreate() {
        super.onCreate()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            stopSelf()
            return START_NOT_STICKY
        }

        val command = if (Build.VERSION.SDK_INT >= 33) {
            intent.getSerializableExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getSerializableExtra("COMMAND") as? AppConfigs.V2RAY_SERVICE_COMMANDS
        }

        if (command == AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE) {
            stopAll()
            return START_NOT_STICKY
        }

        // Create notification channel and start foreground immediately to prevent crash.
        createNotificationChannel()
        val notification = createNotification("VPN Service Running")
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(1, notification, FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(1, notification)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start foreground", e)
        }

        if (command == AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE) {
            val config = if (Build.VERSION.SDK_INT >= 33) {
                intent.getSerializableExtra("V2RAY_CONFIG", XrayConfig::class.java)
            } else {
                @Suppress("DEPRECATION")
                intent.getSerializableExtra("V2RAY_CONFIG") as? XrayConfig
            }

            if (config != null) {
                // Ensure clean state before starting
                cleanup()
                
                // Check if we should run in Proxy Only mode (no VPN interface)
                val proxyOnly = intent.getBooleanExtra("PROXY_ONLY", false)
                
                // Start the Xray Core (SOCKS/HTTP proxy)
                if (XrayCoreManager.startCore(this, config)) {
                    if (!proxyOnly) {
                        // If not proxy-only, establish the VPN interface and start tun2socks
                        setupVpn(config)
                    } else {
                        // Proxy Only Mode: Just mark as running
                        isRunning = true
                        Log.d(TAG, "Starting in PROXY_ONLY mode")
                    }
                } else {
                    stopSelf()
                }
            }
        } else {
            stopSelf()
        }

        return START_STICKY
    }

    /**
     * Establishes the VPN interface (TUN) and starts tun2socks.
     */
    private fun setupVpn(config: XrayConfig) {
        try {
            if (mInterface != null) {
                mInterface?.close()
                mInterface = null
            }

            val builder = Builder()
            builder.setSession(config.REMARK)
            builder.setMtu(1500)
            builder.addAddress("26.26.26.1", 30)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }
            
          try {
    builder.addDisallowedApplication(packageName)
} catch (e: Exception) {
    Log.e(TAG, "Failed to exclude app from VPN", e)
}

for (pkg in config.BLOCKED_APPS) {
    try {
        builder.addDisallowedApplication(pkg)
        Log.d(TAG, "Excluded from VPN: $pkg")
    } catch (e: Exception) {
        Log.e(TAG, "Failed to exclude $pkg from VPN", e)
    }
}

            // Add routes to exclude the server IP (to prevent routing loop)
            val serverIp = config.CONNECTED_V2RAY_SERVER_ADDRESS
            if (serverIp.isIpv4Literal()) {
                try {
                    Log.d(TAG, "Excluding server IP: $serverIp")
                    val excludedRoutes = excludeIp(serverIp)
                    for (route in excludedRoutes) {
                        val parts = route.split("/")
                        builder.addRoute(parts[0], parts[1].toInt())
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to exclude server IP, falling back to 0.0.0.0/0", e)
                    builder.addRoute("0.0.0.0", 0)
                }
            } else {
                builder.addRoute("0.0.0.0", 0)
            }

            // Add DNS servers
            try {
                builder.addDnsServer("8.8.8.8")
                builder.addDnsServer("1.1.1.1")
            } catch (e: Exception) {
                // ignore
            }

            // Establish the VPN interface
            mInterface = builder.establish()
            isRunning = true
            
            // Start tun2socks to handle the traffic
            runTun2socks(config)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to setup VPN", e)
            stopAll()
        }
    }

    /**
     * Starts the tun2socks process and initiates the FD transfer.
     */
    @Synchronized
    private fun runTun2socks(config: XrayConfig) {
        val tun2socksPath = File(applicationInfo.nativeLibraryDir, "libtun2socks.so").absolutePath
        val sockPath = File(filesDir, "sock_path").absolutePath
        val diagnosticsGeneration = XrayDiagnosticsStore.currentGeneration()
        
        // Command to start tun2socks. 
        // Note: We pass -sock-path to tell it where to listen for the FD.
        val cmd = arrayListOf(
            tun2socksPath,
            "-sock-path", sockPath,
            "-proxy", "socks5://127.0.0.1:${config.LOCAL_SOCKS5_PORT}",
            "-mtu", "1500",
            "-loglevel", "debug"
        )

        Log.d(TAG, "tun2socks command: ${cmd.joinToString(" ")}")

        try {
            val pb = ProcessBuilder(cmd)
            pb.redirectErrorStream(true)
            pb.directory(filesDir)
            val process = pb.start()
            tun2socksProcess = process

            // Read tun2socks output in a separate thread
            Thread {
                try {
                    process.inputStream.bufferedReader().use { reader ->
                        reader.forEachLine { line ->
                            Log.d(TAG, "tun2socks: $line")
                            XrayDiagnosticsStore.append(
                                filesDir,
                                "tun2socks",
                                line,
                                diagnosticsGeneration
                            )
                        }
                    }
                    
                    process.waitFor()
                    restartTun2socksAfterUnexpectedExit(
                        config,
                        process,
                        diagnosticsGeneration
                    )
                } catch (e: java.io.InterruptedIOException) {
                    // Expected when stopping
                } catch (e: InterruptedException) {
                } catch (e: Exception) {
                    Log.e(TAG, "Error reading tun2socks output", e)
                    XrayDiagnosticsStore.append(
                        filesDir,
                        "runtime",
                        "Error reading tun2socks output: ${e.message}",
                        diagnosticsGeneration
                    )
                }
            }.start()

            // Send the TUN file descriptor to tun2socks via socket
            sendFd()

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start tun2socks", e)
            XrayDiagnosticsStore.append(
                filesDir,
                "runtime",
                "Failed to start tun2socks: ${e.message}",
                diagnosticsGeneration
            )
            stopAll()
        }
    }

    /** Restarts only when this callback still belongs to the active process. */
    @Synchronized
    private fun restartTun2socksAfterUnexpectedExit(
        config: XrayConfig,
        process: Process,
        diagnosticsGeneration: Long
    ) {
        if (!isRunning ||
            tun2socksProcess !== process ||
            XrayDiagnosticsStore.currentGeneration() != diagnosticsGeneration
        ) {
            return
        }
        Log.e(TAG, "tun2socks exited unexpectedly, restarting...")
        XrayDiagnosticsStore.append(
            filesDir,
            "runtime",
            "tun2socks exited unexpectedly; restarting",
            diagnosticsGeneration
        )
        runTun2socks(config)
    }

    /**
     * Sends the TUN interface file descriptor to the running tun2socks process.
     * This uses a Unix Domain Socket to pass the FD, which is required because
     * ProcessBuilder cannot inherit FDs on Android.
     */
    private fun sendFd() {
        val fd = mInterface?.fileDescriptor ?: return
        val sockFile = File(filesDir, "sock_path").absolutePath

        Thread {
            var tries = 0
            while (tries < 10) {
                try {
                    Thread.sleep(500)
                    val localSocket = LocalSocket()
                    localSocket.connect(LocalSocketAddress(sockFile, LocalSocketAddress.Namespace.FILESYSTEM))
                    val out = localSocket.outputStream
                    // This magic call attaches the FD to the socket message
                    localSocket.setFileDescriptorsForSend(arrayOf(fd))
                    out.write(32) // Send a dummy byte to trigger the transfer
                    localSocket.setFileDescriptorsForSend(null)
                    localSocket.shutdownOutput()
                    localSocket.close()
                    break
                } catch (e: Exception) {
                    tries++
                }
            }
        }.start()
    }

    /**
     * Cleans up resources (tun2socks process, VPN interface) without stopping the service completely.
     * Used when restarting or switching configurations.
     */
    @Synchronized
    private fun cleanup() {
        isRunning = false
        tun2socksProcess?.destroy()
        tun2socksProcess = null
        try {
            mInterface?.close()
            mInterface = null
        } catch (e: Exception) {}
    }

    /**
     * Stops everything: tun2socks, VPN interface, and Xray Core.
     */
    private fun stopAll() {
        cleanup()
        XrayCoreManager.stopCore(this)
        stopForeground(true)
        stopSelf()
    }

    override fun onDestroy() {
        stopAll()
        super.onDestroy()
    }

    /**
     * Calculates routes to exclude a specific IP address from the VPN.
     * This is done by splitting the 0.0.0.0/0 route into smaller subnets that cover everything EXCEPT the target IP.
     */
    private fun excludeIp(ip: String): List<String> {
        val parts = ip.split(".").map { it.toInt() }
        val ipLong = (parts[0].toLong() shl 24) + (parts[1].toLong() shl 16) + (parts[2].toLong() shl 8) + parts[3].toLong()
        
        val routes = ArrayList<String>()
        var start = 0L
        var end = 4294967295L // 255.255.255.255
        
        fun addRoutesExcluding(target: Long, current: Long, prefix: Int) {
            if (prefix >= 32) return
            
            val size = 1L shl (32 - prefix)
            val nextPrefix = prefix + 1
            val left = current
            val right = current + (1L shl (32 - nextPrefix))
            
            // Check if target is in left half
            if (target >= left && target < left + (1L shl (32 - nextPrefix))) {
                // Target is in left half, so add right half fully
                routes.add(longToIp(right) + "/$nextPrefix")
                addRoutesExcluding(target, left, nextPrefix)
            } else {
                // Target is in right half, so add left half fully
                routes.add(longToIp(left) + "/$nextPrefix")
                addRoutesExcluding(target, right, nextPrefix)
            }
        }
        
        addRoutesExcluding(ipLong, 0L, 0)
        return routes
    }

    private fun longToIp(ip: Long): String {
        return "${(ip shr 24) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 8) and 0xFF}.${ip and 0xFF}"
    }

    private fun String.isIpv4Literal(): Boolean {
        val parts = split(".")
        if (parts.size != 4) return false
        return parts.all { part ->
            part.isNotEmpty() &&
                part.all { it.isDigit() } &&
                part.toIntOrNull()?.let { it in 0..255 } == true
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channelId = "vpn_service_channel"
            val channelName = "VPN Service"
            val channel = android.app.NotificationChannel(
                channelId,
                channelName,
                android.app.NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(android.app.NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }

    private fun createNotification(content: String): android.app.Notification {
        val channelId = "vpn_service_channel"
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            android.app.Notification.Builder(this, channelId)
        } else {
            @Suppress("DEPRECATION")
            android.app.Notification.Builder(this)
        }
        
        // Use a default icon if not set
        var icon = android.R.drawable.ic_dialog_info
        
        return builder
            .setContentTitle("VPN Service")
            .setContentText(content)
            .setSmallIcon(icon)
            .build()
    }

    companion object {
        private const val TAG = "XrayVPNService"
        private const val FOREGROUND_SERVICE_TYPE_SPECIAL_USE = 0x40000000
    }
}
