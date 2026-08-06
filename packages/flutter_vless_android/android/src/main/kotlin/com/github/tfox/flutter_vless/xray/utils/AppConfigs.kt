package com.github.tfox.flutter_vless.xray.utils

import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import java.io.Serializable

/**
 * Global application configuration and state.
 *
 * This object holds:
 * 1. Constants for Intent actions and Service commands.
 * 2. Enums for connection states and modes.
 * 3. Global state variables (current connection state, active config).
 * 4. Static storage for notification icon resources (passed from Flutter).
 */
object AppConfigs {
    const val V2RAY_CONNECTION_INFO = "com.github.tfox.flutter_vless.xray.V2RAY_CONNECTION_INFO"

    /**
     * Commands sent to the XrayVPNService via Intent.
     */
    enum class V2RAY_SERVICE_COMMANDS : Serializable {
        START_SERVICE, STOP_SERVICE, RESTART_SERVICE
    }

    /**
     * Connection states for the Xray Core.
     */
    enum class V2RAY_STATES : Serializable {
        V2RAY_CONNECTED, V2RAY_DISCONNECTED, V2RAY_CONNECTING
    }

    /**
     * Connection modes:
     * - VPN_TUN: Standard VPN mode using Android VpnService (TUN device).
     * - PROXY_ONLY: Runs Xray as a local SOCKS/HTTP proxy without establishing a VPN tunnel.
     */
    enum class V2RAY_CONNECTION_MODES : Serializable {
        VPN_TUN, PROXY_ONLY
    }

    const val ACTION_REQUEST_VPN_STATE =
        "com.github.tfox.flutter_vless.REQUEST_VPN_STATE"

    var V2RAY_STATE: V2RAY_STATES = V2RAY_STATES.V2RAY_DISCONNECTED
    var V2RAY_CONFIG: XrayConfig? = null
    var V2RAY_CONNECTION_MODE: V2RAY_CONNECTION_MODES = V2RAY_CONNECTION_MODES.VPN_TUN

    // Stores the resource name and type for the custom notification icon
    var NOTIFICATION_ICON_RESOURCE_NAME: String = ""
    var NOTIFICATION_ICON_RESOURCE_TYPE: String = ""
}
