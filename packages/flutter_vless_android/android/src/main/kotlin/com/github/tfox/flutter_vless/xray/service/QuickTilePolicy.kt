package com.github.tfox.flutter_vless.xray.service

/** Pure UI policy. A system control never authorizes an automatic restart. */
internal object QuickTilePolicy {
    enum class State { UNAVAILABLE, ACTIVE, INACTIVE }
    enum class Action { NONE, OPEN_APP, TOGGLE }
    fun state(enabled: Boolean, hasProfile: Boolean, connected: Boolean, connecting: Boolean, proxyOnly: Boolean): State = when {
        !enabled || connecting || proxyOnly -> State.UNAVAILABLE
        connected -> State.ACTIVE
        hasProfile -> State.INACTIVE
        else -> State.UNAVAILABLE
    }
    fun action(state: State, openApp: Boolean, lockdown: Boolean): Action = when {
        state == State.UNAVAILABLE -> Action.OPEN_APP
        openApp || (state == State.ACTIVE && lockdown) -> Action.OPEN_APP
        else -> Action.TOGGLE
    }
}
