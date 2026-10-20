package com.github.tfox.flutter_vless.xray.service

/** An immutable UI intent, never permission to reinterpret a newer policy or session. */
internal data class QuickAccessSnapshot(val options: NativeVlessOptions, val revision: String)
internal data class QuickAccessAction(val revision: String, val configuredAction: String,
    val operation: Operation, val session: Long = 0, val profile: String? = null) {
    enum class Operation { OPEN, START, STOP }
    fun valid(): Boolean = revision.matches(Regex("[a-f0-9]{32}|[a-f0-9]{64}")) &&
        configuredAction in listOf("openApp", "toggle") && when (operation) {
            Operation.OPEN -> session == 0L && profile == null
            Operation.START -> configuredAction == "toggle" && session == 0L && profile?.matches(Regex("[a-f0-9]{64}")) == true
            Operation.STOP -> configuredAction == "toggle" && session > 0 && profile == null
        }
    fun permits(snapshot: QuickAccessSnapshot, locked: Boolean): Boolean = valid() &&
        snapshot.revision == revision && snapshot.options.quickAccess.enabled &&
        snapshot.options.quickAccess.action == configuredAction &&
        (!snapshot.options.quickAccess.requireUnlock || !locked)
}

/** A pending tile request is consumed only at the actual native process launch boundary. */
internal class PendingQuickStart(val request: Long, val action: QuickAccessAction) {
    @Volatile var owner: Long? = null
    var persisted = false // service worker only
}
