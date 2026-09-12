package com.github.tfox.flutter_vless

import android.content.Context
import android.content.Intent
import android.os.Build
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.service.XrayVPNService
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import org.json.JSONObject
import java.util.ArrayList

object VpnLaunchHelper {
    data class StartParams(
        val remark: String,
        val configJson: String,
        val blockedApps: ArrayList<String> = ArrayList(),
        val bypassSubnets: ArrayList<String> = ArrayList(),
        val proxyOnly: Boolean = false,
        val disconnectButtonName: String = "Disconnect",
    )

    fun buildConfig(context: Context, params: StartParams): XrayConfig {
        val config = XrayConfig()
        config.REMARK = params.remark
        config.V2RAY_FULL_JSON_CONFIG = params.configJson
        config.BLOCKED_APPS = params.blockedApps
        config.BYPASS_SUBNETS = params.bypassSubnets
        config.NOTIFICATION_DISCONNECT_BUTTON_NAME = params.disconnectButtonName

        if (AppConfigs.NOTIFICATION_ICON_RESOURCE_NAME.isNotEmpty() &&
            AppConfigs.NOTIFICATION_ICON_RESOURCE_TYPE.isNotEmpty()
        ) {
            config.NOTIFICATION_ICON_RESOURCE_NAME = AppConfigs.NOTIFICATION_ICON_RESOURCE_NAME
            config.NOTIFICATION_ICON_RESOURCE_TYPE = AppConfigs.NOTIFICATION_ICON_RESOURCE_TYPE
            val resId = context.resources.getIdentifier(
                AppConfigs.NOTIFICATION_ICON_RESOURCE_NAME,
                AppConfigs.NOTIFICATION_ICON_RESOURCE_TYPE,
                context.packageName,
            )
            config.APPLICATION_ICON = resId
        }

        AppConfigs.V2RAY_CONNECTION_MODE = if (params.proxyOnly) {
            AppConfigs.V2RAY_CONNECTION_MODES.PROXY_ONLY
        } else {
            AppConfigs.V2RAY_CONNECTION_MODES.VPN_TUN
        }

        applyServerExclusion(config)
        return config
    }

    private fun applyServerExclusion(config: XrayConfig) {
        try {
            val jsonConfig = JSONObject(config.V2RAY_FULL_JSON_CONFIG)
            val outbounds = jsonConfig.optJSONArray("outbounds") ?: return
            if (outbounds.length() == 0) return

            val firstOutbound = outbounds.getJSONObject(0)
            val settings = firstOutbound.optJSONObject("settings") ?: return
            val vnext = settings.optJSONArray("vnext")
            if (vnext != null && vnext.length() > 0) {
                val server = vnext.getJSONObject(0)
                config.CONNECTED_V2RAY_SERVER_ADDRESS = server.optString("address", "")
                config.CONNECTED_V2RAY_SERVER_PORT = server.optInt("port", 0).toString()
            } else {
                config.CONNECTED_V2RAY_SERVER_ADDRESS = settings.optString("address", "")
                config.CONNECTED_V2RAY_SERVER_PORT = settings.optInt("port", 0).toString()
            }
        } catch (_: Exception) {
            // Ignore parsing errors; VPN routing exclusion is best-effort.
        }
    }

    fun startService(context: Context, config: XrayConfig, proxyOnly: Boolean) {
        val intent = Intent(context, XrayVPNService::class.java).apply {
            putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE)
            putExtra("V2RAY_CONFIG", config)
            putExtra("PROXY_ONLY", proxyOnly)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent)
        } else {
            context.startService(intent)
        }
    }

    fun stopService(context: Context) {
        val intent = Intent(context, XrayVPNService::class.java).apply {
            putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE)
        }
        context.startService(intent)
    }

    fun startFromStore(context: Context): Boolean {
        val profile = QuickSettingsTileStore.loadProfile(context) ?: return false
        AppConfigs.V2RAY_CONNECTION_MODE = profile.connectionMode
        val params = StartParams(
            remark = profile.remark,
            configJson = profile.configJson,
            blockedApps = profile.blockedApps,
            bypassSubnets = profile.bypassSubnets,
            proxyOnly = profile.proxyOnly,
            disconnectButtonName = profile.disconnectButtonName,
        )
        val config = buildConfig(context, params)
        startService(context, config, profile.proxyOnly)
        return true
    }
}
