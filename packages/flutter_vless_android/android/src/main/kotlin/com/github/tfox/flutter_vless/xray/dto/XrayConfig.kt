package com.github.tfox.flutter_vless.xray.dto

import java.io.Serializable
import java.util.ArrayList

/**
 * Data class representing the Xray configuration and app settings.
 * 
 * This class is passed from Flutter to Android and contains:
 * 1. The full Xray JSON configuration (V2RAY_FULL_JSON_CONFIG).
 * 2. App-specific settings like blocked apps, notification text, etc.
 * 3. Connection parameters (server address, ports).
 */
data class XrayConfig(
    /** The IP address of the connected server (used to exclude it from VPN routing). */
    var CONNECTED_V2RAY_SERVER_ADDRESS: String = "",
    
    /** The port of the connected server. */
    var CONNECTED_V2RAY_SERVER_PORT: String = "",
    
    /** Local port for SOCKS5 proxy (default: 10807). used by tun2socks. */
    var LOCAL_SOCKS5_PORT: Int = 10807,
    
    /** Local port for HTTP proxy (default: 10808). */
    var LOCAL_HTTP_PORT: Int = 10808,
    
    /** Local port for Xray API (stats, etc.) (default: 10809). */
    var LOCAL_API_PORT: Int = 10809,
    
    /** Timeout for connections in milliseconds. */
    var ALLOWED_TIMEOUT_MS: Int = 0,
    
    /** List of subnets to bypass (not routed through VPN). */
    var BYPASS_SUBNETS: ArrayList<String> = ArrayList(),
    
    /** List of app package names to exclude from VPN. */
    var BLOCKED_APPS: ArrayList<String> = ArrayList(),
    
    /** The raw Xray configuration JSON string. */
    var V2RAY_FULL_JSON_CONFIG: String = "",
    
    /** Whether to enable traffic statistics collection. */
    var ENABLE_TRAFFIC_STATICS: Boolean = false,
    
    /** Remark/Name of the server configuration. */
    var REMARK: String = "",
    
    /** Name of the application (displayed in notification). */
    var APPLICATION_NAME: String = "Flutter Vless",
    
    /** Resource ID of the notification icon. */
    var APPLICATION_ICON: Int = 0,
    
    /** Resource name of the notification icon (e.g. "ic_notification"). */
    var NOTIFICATION_ICON_RESOURCE_NAME: String = "",
    
    /** Resource type of the notification icon (e.g. "drawable"). */
    var NOTIFICATION_ICON_RESOURCE_TYPE: String = "",
    
    /** Text for the disconnect button in the notification. */
    var NOTIFICATION_DISCONNECT_BUTTON_NAME: String = "Disconnect",
    
    /** Domain resolution strategy (e.g. "IPIfNonMatch"). */
    var DOMAIN_STRATEGY: String = "",
    
    /** Routing domain strategy. */
    var ROUTING_DOMAIN_STRATEGY: String = ""
) : Serializable
