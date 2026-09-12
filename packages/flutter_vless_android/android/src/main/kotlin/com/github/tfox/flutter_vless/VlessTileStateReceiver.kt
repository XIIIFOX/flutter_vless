package com.github.tfox.flutter_vless

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.github.tfox.flutter_vless.xray.utils.AppConfigs

/**
 * Runs in the default process so tile prefs and [TileService.requestListeningState]
 * are not tied to the Flutter engine or the isolated VPN process.
 */
class VlessTileStateReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != AppConfigs.ACTION_TILE_STATE) return
        val state = VpnStateExtras.read(intent) ?: return
        if (state != AppConfigs.V2RAY_STATES.V2RAY_CONNECTED &&
            state != AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED
        ) {
            return
        }
        QuickSettingsTileStore.saveVpnState(context, state)
        QuickSettingsTileUpdater.requestTileRefresh(context)
    }
}
