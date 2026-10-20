package com.github.tfox.flutter_vless

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.github.tfox.flutter_vless.xray.service.NativeOptionsStore
import com.github.tfox.flutter_vless.xray.service.QuickTilePolicy
import com.github.tfox.flutter_vless.xray.service.QuickAccessAction
import com.github.tfox.flutter_vless.xray.service.XrayVPNService
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import java.lang.ref.WeakReference

/** Same daemon process as the VPN service; no Flutter engine or broadcast trust boundary. */
class VlessTileService : TileService() {
    private var listening = false
    override fun onTileAdded() {
        super.onTileAdded()
        // ACTIVE_TILE can be added after the last session-state notification.
        // Addition and listening are independent lifecycle events; request a
        // fresh listening callback after SystemUI has registered this tile.
        NativeQuickAccess.refresh(this)
        if (listening) refreshTile()
    }
    override fun onStartListening() {
        super.onStartListening()
        listening = true
        listeningInstance = WeakReference(this)
        refreshTile()
    }
    override fun onStopListening() {
        listening = false
        if (listeningInstance?.get() === this) listeningInstance = null
        super.onStopListening()
    }
    override fun onDestroy() {
        listening = false
        if (listeningInstance?.get() === this) listeningInstance = null
        super.onDestroy()
    }
    private fun state(): QuickTilePolicy.State {
        val accepted = XrayVPNService.hasAcceptedSession()
        return QuickTilePolicy.state(
            NativeOptionsStore(this).read().quickAccess.enabled,NativeQuickAccess.profile(this).exists(),
            AppConfigs.V2RAY_STATE == AppConfigs.V2RAY_STATES.V2RAY_CONNECTED,
            AppConfigs.V2RAY_STATE == AppConfigs.V2RAY_STATES.V2RAY_CONNECTING,
            (accepted || AppConfigs.V2RAY_STATE != AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED) && AppConfigs.V2RAY_CONFIG?.PROXY_ONLY == true,
            accepted)
    }
    private fun refreshTile() {
        val tile = qsTile ?: return
        val settings = NativeOptionsStore(this).read().quickAccess
        val state = state()
        tile.label = settings.label
        val resource = resources.getIdentifier(settings.androidIconResourceName,"drawable",packageName)
            .takeIf { it != 0 } ?: R.drawable.flutter_vless_ic_quick_tile
        tile.icon = Icon.createWithResource(this,resource)
        tile.state = when(state) {
            QuickTilePolicy.State.ACTIVE, QuickTilePolicy.State.CONNECTING -> Tile.STATE_ACTIVE
            QuickTilePolicy.State.INACTIVE -> Tile.STATE_INACTIVE
            else -> Tile.STATE_UNAVAILABLE
        }
        if (Build.VERSION.SDK_INT >= 29) tile.subtitle = getString(when(state) {
            QuickTilePolicy.State.ACTIVE -> R.string.flutter_vless_tile_connected
            QuickTilePolicy.State.CONNECTING -> R.string.flutter_vless_tile_connecting
            QuickTilePolicy.State.INACTIVE -> R.string.flutter_vless_tile_disconnected
            else -> R.string.flutter_vless_tile_unavailable
        })
        tile.updateTile()
    }
    override fun onClick() {
        super.onClick()
        val snapshot = NativeOptionsStore(this).beginAction()
        val settings = snapshot.options.quickAccess
        if (!settings.enabled) { refreshTile(); return }
        val desired = QuickTilePolicy.action(state(), settings.action == "openApp",
            AppConfigs.LOCKDOWN_ENABLED || AppConfigs.ALWAYS_ON_ENABLED)
        if (desired == QuickTilePolicy.Action.NONE) return
        val session = XrayVPNService.acceptedSessionGeneration()
        val operation = if (desired == QuickTilePolicy.Action.OPEN_APP) QuickAccessAction.Operation.OPEN
            else if (session != null) QuickAccessAction.Operation.STOP else QuickAccessAction.Operation.START
        val profile = if (operation == QuickAccessAction.Operation.START)
            runCatching { NativeQuickAccess.profile(this).revision() }.getOrNull() ?: return else null
        val ticket = QuickAccessAction(snapshot.revision, settings.action, operation, session ?: 0, profile)
            .let { if (operation == QuickAccessAction.Operation.STOP) it else it.copy(session = 0) }
        val action = Runnable { performAction(ticket) }
        if (settings.requireUnlock && isLocked) unlockAndRun(action) else action.run()
    }
    /** Rechecked after unlock; never retarget the UI intent to a new policy/session. */
    internal fun performAction(ticket: QuickAccessAction) {
        if (!ticket.permits(NativeOptionsStore(this).readSnapshot(), NativeQuickAccess.locked(this))) return
        when (ticket.operation) {
            QuickAccessAction.Operation.OPEN -> packageManager.getLaunchIntentForPackage(packageName)?.let(::collapseTo)
            QuickAccessAction.Operation.START -> {
                if (XrayVPNService.hasAcceptedSession() ||
                    AppConfigs.V2RAY_STATE != AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED ||
                    NativeQuickAccess.profile(this).revision() != ticket.profile) return
                if (VpnService.prepare(this) != null)
                    collapseTo(NativeQuickAccess.putAction(Intent(this,VlessTilePermissionActivity::class.java), ticket))
                else dispatch(ticket)
            }
            QuickAccessAction.Operation.STOP -> {
                if (XrayVPNService.acceptedSessionGeneration() != ticket.session ||
                    AppConfigs.LOCKDOWN_ENABLED || AppConfigs.ALWAYS_ON_ENABLED) return
                dispatch(ticket)
            }
        }
    }
    private fun dispatch(ticket: QuickAccessAction) {
        val intent = NativeQuickAccess.putAction(Intent(this,XrayVPNService::class.java)
            .setAction(XrayVPNService.ACTION_QUICK_ACCESS_TOGGLE), ticket)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
    }
    @Suppress("DEPRECATION")
    private fun collapseTo(intent: Intent) {
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        if (Build.VERSION.SDK_INT >= 34) startActivityAndCollapse(PendingIntent.getActivity(this,24,intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT))
        else startActivityAndCollapse(intent)
    }
    companion object {
        @Volatile private var listeningInstance: WeakReference<VlessTileService>? = null
        private val mainHandler by lazy { Handler(Looper.getMainLooper()) }

        internal fun refreshListeningInstance() {
            val reference = listeningInstance ?: return
            // requestListeningState does not repeat onStartListening when an
            // active tile is already listening. Render each state change there
            // directly, on the lifecycle thread, without retaining a Context.
            mainHandler.post {
                reference.get()?.let { service ->
                    if (service.listening && listeningInstance?.get() === service) service.refreshTile()
                }
            }
        }
    }
}
