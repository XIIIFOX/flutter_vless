package com.github.tfox.flutter_vless

import android.content.ComponentName
import android.content.Context
import android.os.Build
import android.service.quicksettings.TileService
import android.util.Log

object QuickSettingsTileUpdater {
    private const val TAG = "QuickSettingsTileUpdater"

    fun requestTileRefresh(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return
        try {
            val appContext = context.applicationContext
            val component = ComponentName(appContext, VlessTileService::class.java)
            TileService.requestListeningState(appContext, component)
        } catch (e: Exception) {
            // Tile may not be added to Quick Settings yet.
            Log.d(TAG, "requestListeningState skipped: ${e.message}")
        }
    }
}
