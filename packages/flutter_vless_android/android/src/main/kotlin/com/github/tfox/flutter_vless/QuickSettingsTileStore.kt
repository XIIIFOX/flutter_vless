package com.github.tfox.flutter_vless

import android.content.Context
import android.content.SharedPreferences
import com.github.tfox.flutter_vless.xray.utils.AppConfigs

object QuickSettingsTileStore {
    const val PREFS_NAME = "flutter_vless_prefs"

    const val KEY_TILE_LABEL = "tile_label"
    const val KEY_TILE_ICON_TYPE = "tile_icon_resource_type"
    const val KEY_TILE_ICON_NAME = "tile_icon_resource_name"
    const val KEY_NOTIFICATION_ICON_TYPE = "notification_icon_resource_type"
    const val KEY_NOTIFICATION_ICON_NAME = "notification_icon_resource_name"
    const val KEY_LAST_CONFIG = "last_config"
    const val KEY_LAST_REMARK = "last_remark"
    const val KEY_LAST_PROXY_ONLY = "last_proxy_only"
    const val KEY_LAST_BLOCKED_APPS = "last_blocked_apps"
    const val KEY_LAST_BYPASS_SUBNETS = "last_bypass_subnets"
    const val KEY_LAST_DISCONNECT_BUTTON = "last_notification_disconnect_button_name"
    const val KEY_LAST_CONNECTION_MODE = "last_connection_mode"
    const val KEY_LAST_VPN_STATE = "last_vpn_state"

    data class SavedProfile(
        val configJson: String,
        val remark: String,
        val proxyOnly: Boolean,
        val blockedApps: ArrayList<String>,
        val bypassSubnets: ArrayList<String>,
        val disconnectButtonName: String,
        val connectionMode: AppConfigs.V2RAY_CONNECTION_MODES,
    )

    fun prefs(context: Context): SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun saveAppearance(
        context: Context,
        label: String,
        iconType: String,
        iconName: String,
    ) {
        prefs(context).edit()
            .putString(KEY_TILE_LABEL, label)
            .putString(KEY_TILE_ICON_TYPE, iconType)
            .putString(KEY_TILE_ICON_NAME, iconName)
            .apply()
    }

    fun saveProfile(
        context: Context,
        configJson: String,
        remark: String,
        proxyOnly: Boolean,
        blockedApps: List<String>,
        bypassSubnets: List<String>,
        disconnectButtonName: String,
        connectionMode: AppConfigs.V2RAY_CONNECTION_MODES,
    ) {
        prefs(context).edit()
            .putString(KEY_LAST_CONFIG, configJson)
            .putString(KEY_LAST_REMARK, remark)
            .putBoolean(KEY_LAST_PROXY_ONLY, proxyOnly)
            .putStringSet(KEY_LAST_BLOCKED_APPS, blockedApps.toSet())
            .putStringSet(KEY_LAST_BYPASS_SUBNETS, bypassSubnets.toSet())
            .putString(KEY_LAST_DISCONNECT_BUTTON, disconnectButtonName)
            .putString(KEY_LAST_CONNECTION_MODE, connectionMode.name)
            .apply()
    }

    fun loadProfile(context: Context): SavedProfile? {
        val configJson = prefs(context).getString(KEY_LAST_CONFIG, null) ?: return null
        val connectionModeName = prefs(context).getString(
            KEY_LAST_CONNECTION_MODE,
            AppConfigs.V2RAY_CONNECTION_MODES.VPN_TUN.name,
        ) ?: AppConfigs.V2RAY_CONNECTION_MODES.VPN_TUN.name
        val connectionMode = runCatching {
            AppConfigs.V2RAY_CONNECTION_MODES.valueOf(connectionModeName)
        }.getOrDefault(AppConfigs.V2RAY_CONNECTION_MODES.VPN_TUN)

        return SavedProfile(
            configJson = configJson,
            remark = prefs(context).getString(KEY_LAST_REMARK, "") ?: "",
            proxyOnly = prefs(context).getBoolean(KEY_LAST_PROXY_ONLY, false),
            blockedApps = ArrayList(prefs(context).getStringSet(KEY_LAST_BLOCKED_APPS, emptySet()) ?: emptySet()),
            bypassSubnets = ArrayList(prefs(context).getStringSet(KEY_LAST_BYPASS_SUBNETS, emptySet()) ?: emptySet()),
            disconnectButtonName = prefs(context).getString(KEY_LAST_DISCONNECT_BUTTON, "Disconnect") ?: "Disconnect",
            connectionMode = connectionMode,
        )
    }

    fun saveVpnState(context: Context, state: AppConfigs.V2RAY_STATES) {
        prefs(context).edit()
            .putString(KEY_LAST_VPN_STATE, state.name)
            .apply()
    }

    fun loadVpnState(context: Context): AppConfigs.V2RAY_STATES {
        val name = prefs(context).getString(KEY_LAST_VPN_STATE, null) ?: return AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED
        return runCatching { AppConfigs.V2RAY_STATES.valueOf(name) }
            .getOrDefault(AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED)
    }

    fun getTileLabel(context: Context): String? =
        prefs(context).getString(KEY_TILE_LABEL, null)

    fun getTileIconType(context: Context): String? =
        prefs(context).getString(KEY_TILE_ICON_TYPE, null)

    fun getTileIconName(context: Context): String? =
        prefs(context).getString(KEY_TILE_ICON_NAME, null)

    fun saveNotificationIcon(
        context: Context,
        iconType: String,
        iconName: String,
    ) {
        prefs(context).edit()
            .putString(KEY_NOTIFICATION_ICON_TYPE, iconType)
            .putString(KEY_NOTIFICATION_ICON_NAME, iconName)
            .apply()
    }

    fun getNotificationIconType(context: Context): String? =
        prefs(context).getString(KEY_NOTIFICATION_ICON_TYPE, null)

    fun getNotificationIconName(context: Context): String? =
        prefs(context).getString(KEY_NOTIFICATION_ICON_NAME, null)

    fun loadNotificationIconIntoAppConfigs(context: Context) {
        val type = getNotificationIconType(context) ?: return
        val name = getNotificationIconName(context) ?: return
        AppConfigs.NOTIFICATION_ICON_RESOURCE_TYPE = type
        AppConfigs.NOTIFICATION_ICON_RESOURCE_NAME = name
    }
}
