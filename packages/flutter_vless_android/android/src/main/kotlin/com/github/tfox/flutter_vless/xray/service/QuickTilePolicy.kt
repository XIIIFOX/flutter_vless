package com.github.tfox.flutter_vless.xray.service

/** Pure UI policy. A system control never authorizes an automatic restart. */
internal object QuickTilePolicy {
    enum class State { UNAVAILABLE, ACTIVE, CONNECTING, INACTIVE }
    enum class Action { NONE, OPEN_APP, TOGGLE }
    fun state(enabled: Boolean, hasProfile: Boolean, connected: Boolean, connecting: Boolean,
        proxyOnly: Boolean, acceptedSession: Boolean): State = when {
        !enabled || proxyOnly -> State.UNAVAILABLE
        acceptedSession -> if (connected) State.ACTIVE else State.CONNECTING
        // A pending cold start or stop must not authorize a second start.
        connected || connecting -> State.UNAVAILABLE
        hasProfile -> State.INACTIVE
        else -> State.UNAVAILABLE
    }
    fun mayToggle(enabled: Boolean, acceptedSession: Boolean, startPending: Boolean,
        sessionInProgress: Boolean, consented: Boolean): Boolean = enabled && consented &&
        (acceptedSession || (!startPending && !sessionInProgress))
    fun action(state: State, openApp: Boolean, lockdown: Boolean): Action = when {
        state == State.UNAVAILABLE -> Action.OPEN_APP
        openApp || (state in setOf(State.ACTIVE, State.CONNECTING) && lockdown) -> Action.OPEN_APP
        else -> Action.TOGGLE
    }
}
