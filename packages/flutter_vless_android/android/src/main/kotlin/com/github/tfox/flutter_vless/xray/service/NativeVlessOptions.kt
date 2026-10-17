package com.github.tfox.flutter_vless.xray.service

/** Validated snapshots: changing presentation never changes an active session's policy. */
internal data class NativeVlessOptions(
    val notification: Notice = Notice(), val quickAccess: QuickAccess = QuickAccess(),
    val reconnect: Reconnect = Reconnect(), val protection: Protection = Protection(),
    val diagnostics: Diagnostics = Diagnostics(), val version: Int = 1
) {
    data class Notice(val iconResourceType: String = "mipmap", val iconResourceName: String = "ic_launcher",
        val buttonLabel: String = "DISCONNECT", val action: String = "disconnect")
    data class QuickAccess(val enabled: Boolean = false, val surface: String = "platformDefault", val label: String = "VPN",
        val action: String = "toggle", val requireUnlock: Boolean = true,
        val androidIconResourceName: String = "flutter_vless_ic_quick_tile", val appleSymbol: String = "network",
        val windowsIconPath: String? = null)
    data class Reconnect(val enabled: Boolean = true, val initialDelayMs: Long = 1000, val maxDelayMs: Long = 60000,
        val maxAttempts: Int = 0) {
        fun delay(failures: Int): Long = (initialDelayMs * (1L shl failures.coerceIn(0, 23))).coerceAtMost(maxDelayMs)
        fun mayRetry(failures: Int) = enabled && (maxAttempts == 0 || failures < maxAttempts)
    }
    data class Protection(val killSwitch: String = "required", val onDemand: String = "platformDefault", val alwaysOn: String = "system")
    data class Diagnostics(val enabled: Boolean = true, val maxBytes: Int = 128 * 1024, val maxLines: Int = 300)

    companion object {
        fun parse(raw: Map<*, *>?): NativeVlessOptions {
            if (raw == null) return NativeVlessOptions()
            fun section(name: String): Map<*, *> {
                require(raw[name] == null || raw[name] is Map<*, *>) { "Invalid $name options" }
                return raw[name] as? Map<*, *> ?: emptyMap<Any, Any>()
            }
            fun text(map: Map<*, *>, name: String, default: String, limit: Int = 128): String {
                val value = map[name] ?: return default
                require(value is String && value.isNotBlank() && value.length <= limit && value.none { it.code < 32 || it.code == 127 }) { "Invalid $name" }
                return value
            }
            fun flag(map: Map<*, *>, name: String, default: Boolean): Boolean {
                val value = map[name] ?: return default
                require(value is Boolean) { "Invalid $name" }; return value
            }
            fun number(map: Map<*, *>, name: String, default: Long): Long {
                val value = map[name] ?: return default
                require(value is Number && value.toDouble().isFinite() && value.toDouble() == value.toLong().toDouble()) { "Invalid $name" }
                return value.toLong()
            }
            fun resource(value: String): String {
                require(value.matches(Regex("[a-zA-Z_][a-zA-Z0-9_]*"))) { "Invalid resource name" }; return value
            }
            val n = section("notification"); val q = section("quickAccess"); val r = section("reconnect")
            val p = section("protection"); val d = section("diagnostics")
            require(number(raw, "version", 1) == 1L) { "Unsupported options version" }
            val notice = Notice(text(n,"iconResourceType","mipmap"), resource(text(n,"iconResourceName","ic_launcher")),
                text(n,"buttonLabel","DISCONNECT",80), text(n,"action","disconnect"))
            require(notice.iconResourceType in listOf("mipmap","drawable") && notice.action in listOf("disconnect","openApp","none")) { "Invalid notification action or icon" }
            val quick = QuickAccess(flag(q,"enabled",false),text(q,"surface","platformDefault"),text(q,"label","VPN",80),
                text(q,"action","toggle"),flag(q,"requireUnlock",true),resource(text(q,"androidIconResourceName","flutter_vless_ic_quick_tile")),
                text(q,"appleSymbol","network"),q["windowsIconPath"] as? String)
            if (q.containsKey("windowsIconPath")) {
                val path = q["windowsIconPath"]
                require(path is String && !path.contains('\u0000') && path.endsWith(".ico", ignoreCase = true) &&
                    Regex("^(?:[a-zA-Z]:[\\\\/]|\\\\\\\\)").containsMatchIn(path)) { "Invalid windowsIconPath" }
            }
            require(quick.surface in listOf("platformDefault","quickTile","menuBar","systemTray","controlCenter") && quick.action in listOf("toggle","openApp")) { "Invalid quick control" }
            val attempts = number(r,"maxAttempts",0)
            require(attempts in 0..1000) { "Invalid retry limit" }
            val reconnect = Reconnect(flag(r,"enabled",true),number(r,"initialDelayMs",1000),number(r,"maxDelayMs",60000),attempts.toInt())
            require(reconnect.initialDelayMs >= 100 && reconnect.maxDelayMs >= reconnect.initialDelayMs && reconnect.maxDelayMs <= 600000) { "Invalid retry timing" }
            val protection = Protection(text(p,"killSwitch","required"),text(p,"onDemand","platformDefault"),text(p,"alwaysOn","system"))
            require(protection.killSwitch in listOf("required","platformDefault") && protection.onDemand in listOf("platformDefault","enabled","disabled") && protection.alwaysOn in listOf("system","requireEnabled")) { "Invalid protection policy" }
            require(reconnect.enabled || protection.onDemand != "enabled") { "On Demand requires recovery" }
            val bytes = number(d,"maxBytes",131072); val lines = number(d,"maxLines",300)
            require(bytes in 4096..131072 && lines in 1..300) { "Invalid diagnostics limits" }
            return NativeVlessOptions(notice,quick,reconnect,protection,Diagnostics(flag(d,"enabled",true),bytes.toInt(),lines.toInt()))
        }
    }

    fun validateAndroid(sdk: Int) {
        require(!quickAccess.enabled || sdk >= 24) { "Quick Tile requires Android 7 or newer" }
        require(!quickAccess.enabled || quickAccess.surface in listOf("platformDefault","quickTile")) { "This quick control surface is not supported on Android" }
        require(protection.onDemand != "enabled") { "Use Android system Always-on VPN instead of Apple On Demand" }
        require(protection.alwaysOn != "requireEnabled" || sdk >= 29) { "Always-on state requires Android 10 or newer" }
    }
}
