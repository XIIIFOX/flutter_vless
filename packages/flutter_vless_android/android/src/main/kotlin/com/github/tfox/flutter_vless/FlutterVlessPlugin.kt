// Copyright (c) 2024-2026 13FOX Studio / tfox.dev.
// SPDX-License-Identifier: MIT

package com.github.tfox.flutter_vless

import android.Manifest
import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import androidx.core.app.ActivityCompat
import com.github.tfox.flutter_vless.xray.core.XrayCoreManager
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.service.XrayVPNService
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.PluginRegistry
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.util.ArrayList
import java.util.concurrent.Executors

/**
 * Main entry point for the Flutter Vless plugin on Android.
 * 
 * This class handles communication between Flutter (Dart) and Android (Kotlin) using MethodChannels.
 * It is responsible for:
 * 1. Receiving commands from Flutter (start, stop, get delay, etc.).
 * 2. managing permissions (VPN, Notifications).
 * 3. Starting the [XrayVPNService] to run the VPN or Proxy.
 * 4. Sending status updates and traffic statistics back to Flutter via EventChannel.
 */
class FlutterVlessPlugin : FlutterPlugin, ActivityAware, PluginRegistry.ActivityResultListener, MethodChannel.MethodCallHandler {

    private val executor = Executors.newSingleThreadExecutor()
    private lateinit var vpnControlMethod: MethodChannel
    private lateinit var vpnStatusEvent: EventChannel
    private var vpnStatusSink: EventChannel.EventSink? = null
    private var activity: Activity? = null
    private var xrayReceiver: BroadcastReceiver? = null
    private var pendingResult: MethodChannel.Result? = null
    private lateinit var context: Context

    companion object {
        private const val REQUEST_CODE_VPN_PERMISSION = 24
        private const val REQUEST_CODE_POST_NOTIFICATIONS = 1
    }

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        // Channel for method calls (startVless, stopVless, etc.)
        vpnControlMethod = MethodChannel(binding.binaryMessenger, "flutter_vless")
        // Channel for streaming status updates (Connected, Disconnected, Traffic stats)
        vpnStatusEvent = EventChannel(binding.binaryMessenger, "flutter_vless/status")

        vpnControlMethod.setMethodCallHandler(this)
        vpnStatusEvent.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                vpnStatusSink = events
                registerReceiver()
            }

            override fun onCancel(arguments: Any?) {
                vpnStatusSink = null
                unregisterReceiver()
            }
        })
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "startVless" -> {
                // 1. Parse configuration from Flutter
                val config = XrayConfig()
                config.REMARK = call.argument("remark") ?: ""
                config.V2RAY_FULL_JSON_CONFIG = call.argument("config") ?: ""
                config.BLOCKED_APPS = call.argument<ArrayList<String>>("blocked_apps") ?: ArrayList()
                config.BYPASS_SUBNETS = call.argument<ArrayList<String>>("bypass_subnets") ?: ArrayList()
                config.NOTIFICATION_DISCONNECT_BUTTON_NAME = call.argument("notificationDisconnectButtonName") ?: "Disconnect"
                
                // 2. Handle custom notification icon if set via initializeVless
                if (AppConfigs.NOTIFICATION_ICON_RESOURCE_NAME.isNotEmpty() && AppConfigs.NOTIFICATION_ICON_RESOURCE_TYPE.isNotEmpty()) {
                    config.NOTIFICATION_ICON_RESOURCE_NAME = AppConfigs.NOTIFICATION_ICON_RESOURCE_NAME
                    config.NOTIFICATION_ICON_RESOURCE_TYPE = AppConfigs.NOTIFICATION_ICON_RESOURCE_TYPE
                    val resId = context.resources.getIdentifier(
                        AppConfigs.NOTIFICATION_ICON_RESOURCE_NAME, 
                        AppConfigs.NOTIFICATION_ICON_RESOURCE_TYPE, 
                        context.packageName
                    )
                    config.APPLICATION_ICON = resId
                }

                // 3. Determine connection mode (VPN vs Proxy Only)
                if (call.argument<Boolean>("proxy_only") == true) {
                    AppConfigs.V2RAY_CONNECTION_MODE = AppConfigs.V2RAY_CONNECTION_MODES.PROXY_ONLY
                } else {
                    AppConfigs.V2RAY_CONNECTION_MODE = AppConfigs.V2RAY_CONNECTION_MODES.VPN_TUN
                }

                // 4. Try to parse the server address to exclude it from VPN routing (avoid loop)
                try {
                    val jsonConfig = org.json.JSONObject(config.V2RAY_FULL_JSON_CONFIG)
                    val outbounds = jsonConfig.optJSONArray("outbounds")
                    if (outbounds != null && outbounds.length() > 0) {
                        val firstOutbound = outbounds.getJSONObject(0)
                        val settings = firstOutbound.optJSONObject("settings")
                        val vnext = settings?.optJSONArray("vnext")
                        if (vnext != null && vnext.length() > 0) {
                            val server = vnext.getJSONObject(0)
                            config.CONNECTED_V2RAY_SERVER_ADDRESS = server.optString("address", "")
                            config.CONNECTED_V2RAY_SERVER_PORT = server.optInt("port", 0).toString()
                        } else if (settings != null) {
                            config.CONNECTED_V2RAY_SERVER_ADDRESS = settings.optString("address", "")
                            config.CONNECTED_V2RAY_SERVER_PORT = settings.optInt("port", 0).toString()
                        }
                    }
                } catch (e: Exception) {
                    // Ignore parsing errors, fallback to not excluding IP
                }

                // 5. Start the XrayVPNService
                // We pass the config and PROXY_ONLY flag via Intent extras
                val intent = Intent(context, XrayVPNService::class.java)
                intent.putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE)
                intent.putExtra("V2RAY_CONFIG", config)
                intent.putExtra("PROXY_ONLY", call.argument<Boolean>("proxy_only") ?: false)
                
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
                result.success(null)
            }
            "stopVless" -> {
                val intent = Intent(context, XrayVPNService::class.java)
                intent.putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE)
                context.startService(intent)
                result.success(null)
            }
            "initializeVless" -> {
                // Store notification icon settings globally
                val iconResourceName = call.argument<String>("notificationIconResourceName")
                val iconResourceType = call.argument<String>("notificationIconResourceType")
                if (iconResourceName != null && iconResourceType != null) {
                    AppConfigs.NOTIFICATION_ICON_RESOURCE_NAME = iconResourceName
                    AppConfigs.NOTIFICATION_ICON_RESOURCE_TYPE = iconResourceType
                }
                result.success(null)
            }
            "getServerDelay" -> {
                // Measures delay (ping) to a target URL using a specific config (without connecting)
                android.util.Log.d("FlutterVlessPlugin", "getServerDelay called")
                val configJson = call.argument<String>("config")
                val url = call.argument<String>("url") ?: "https://www.google.com"
                
                if (configJson == null) {
                    result.error("INVALID_CONFIG", "Config is null", null)
                    return
                }
                
                val currentActivity = activity
                if (currentActivity == null) {
                    result.error("NO_ACTIVITY", "Activity is null", null)
                    return
                }
                
                executor.execute {
                    val delay = XrayCoreManager.getServerDelay(currentActivity, configJson, url)
                    currentActivity.runOnUiThread {
                        result.success(delay)
                    }
                }
            }
            "getConnectedServerDelay" -> {
                // Measures delay through the CURRENTLY active connection
                val url = call.argument<String>("url") ?: "https://www.google.com"
                val currentActivity = activity
                if (currentActivity == null) {
                    result.error("NO_ACTIVITY", "Activity is null", null)
                    return
                }
                executor.execute {
                    val delay = XrayCoreManager.getConnectedV2rayServerDelay(currentActivity, url)
                    currentActivity.runOnUiThread {
                        result.success(delay)
                    }
                }
            }
            "getCoreVersion" -> {
                // Returns the version of the underlying libxray.so
                executor.submit {
                    try {
                        val nativeLibraryDir = context.applicationInfo.nativeLibraryDir
                        val xrayExecutable = File(nativeLibraryDir, "libxray.so")
                        if (xrayExecutable.exists()) {
                            val p = Runtime.getRuntime().exec(arrayOf(xrayExecutable.absolutePath, "-version"))
                            val reader = BufferedReader(InputStreamReader(p.inputStream))
                            val version = reader.readLine()
                            result.success(version)
                        } else {
                            result.success("Xray not found")
                        }
                    } catch (e: Exception) {
                        result.success("Error: ${e.message}")
                    }
                }
            }
            "getProviderDebugSnapshot" -> {
                result.success(XrayCoreManager.getProviderDebugSnapshot(context))
            }
            "requestPermission" -> {
                // Requests VPN permission from the OS
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    if (ActivityCompat.checkSelfPermission(activity!!, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                        ActivityCompat.requestPermissions(activity!!, arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_CODE_POST_NOTIFICATIONS)
                    }
                }
                val request = VpnService.prepare(activity)
                if (request != null) {
                    pendingResult = result
                    activity!!.startActivityForResult(request, REQUEST_CODE_VPN_PERMISSION)
                } else {
                    result.success(true)
                }
            }
            else -> result.notImplemented()
        }
    }

    /**
     * Registers a BroadcastReceiver to listen for updates from XrayVPNService.
     * This allows us to receive state changes (Connected/Disconnected) and traffic stats.
     */
    private fun registerReceiver() {
        if (activity == null) return
        if (xrayReceiver == null) {
            xrayReceiver = object : BroadcastReceiver() {
                override fun onReceive(context: Context?, intent: Intent?) {
                    if (intent == null || vpnStatusSink == null) return
                    val state = intent.getSerializableExtra("STATE") as? AppConfigs.V2RAY_STATES
                    val duration = intent.getStringExtra("DURATION")
                    val uploadSpeed = intent.getLongExtra("UPLOAD_SPEED", 0)
                    val downloadSpeed = intent.getLongExtra("DOWNLOAD_SPEED", 0)
                    val uploadTraffic = intent.getLongExtra("UPLOAD_TRAFFIC", 0)
                    val downloadTraffic = intent.getLongExtra("DOWNLOAD_TRAFFIC", 0)

                    val stateName = when (state) {
                        AppConfigs.V2RAY_STATES.V2RAY_CONNECTED -> "CONNECTED"
                        AppConfigs.V2RAY_STATES.V2RAY_CONNECTING -> "CONNECTING"
                        else -> "DISCONNECTED"
                    }

                    val data = ArrayList<String>()
                    data.add(duration ?: "0")
                    data.add(uploadSpeed.toString())
                    data.add(downloadSpeed.toString())
                    data.add(uploadTraffic.toString())
                    data.add(downloadTraffic.toString())
                    data.add(stateName)

                    vpnStatusSink?.success(data)
                }
            }
        }
        val filter = IntentFilter(AppConfigs.V2RAY_CONNECTION_INFO)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            activity?.registerReceiver(xrayReceiver, filter, Context.RECEIVER_EXPORTED)
        } else {
            activity?.registerReceiver(xrayReceiver, filter)
        }
    }

    private fun unregisterReceiver() {
        if (activity != null && xrayReceiver != null) {
            try {
                activity?.unregisterReceiver(xrayReceiver)
            } catch (e: Exception) {
                // ignore
            }
            xrayReceiver = null
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        vpnControlMethod.setMethodCallHandler(null)
        vpnStatusEvent.setStreamHandler(null)
        executor.shutdown()
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity
        binding.addActivityResultListener(this)
        if (vpnStatusSink != null) {
            registerReceiver()
        }
    }

    override fun onDetachedFromActivityForConfigChanges() {}

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activity = binding.activity
        binding.addActivityResultListener(this)
        if (vpnStatusSink != null) {
            registerReceiver()
        }
    }

    override fun onDetachedFromActivity() {
        unregisterReceiver()
        activity = null
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        if (requestCode == REQUEST_CODE_VPN_PERMISSION) {
            if (resultCode == Activity.RESULT_OK) {
                pendingResult?.success(true)
            } else {
                pendingResult?.success(false)
            }
            pendingResult = null
            return true
        }
        return false
    }
}
