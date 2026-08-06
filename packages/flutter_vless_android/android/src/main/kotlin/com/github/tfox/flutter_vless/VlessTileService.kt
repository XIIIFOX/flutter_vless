package com.github.tfox.flutter_vless

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.github.tfox.flutter_vless.xray.utils.AppConfigs

class VlessTileService : TileService() {

    private var receiverRegistered = false
    private var vpnState = AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED
    private var isPendingConnect = false

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent == null) return
            val state = readStateExtra(intent) ?: return
            vpnState = state
            when (state) {
                AppConfigs.V2RAY_STATES.V2RAY_CONNECTED,
                AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED,
                -> isPendingConnect = false
                else -> Unit
            }
            updateTile()
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        QuickSettingsTileStore.loadNotificationIconIntoAppConfigs(this)
        vpnState = QuickSettingsTileStore.loadVpnState(this)
        updateTile()
        registerStateReceiver()
        sendBroadcast(
            Intent(AppConfigs.ACTION_REQUEST_VPN_STATE).setPackage(packageName),
        )
    }

    override fun onStopListening() {
        unregisterStateReceiver()
        super.onStopListening()
    }

    override fun onClick() {
        unlockAndRun { handleClick() }
    }

    private fun handleClick() {
        if (isConnectingState()) return

        val running = vpnState == AppConfigs.V2RAY_STATES.V2RAY_CONNECTED
        if (running) {
            VpnLaunchHelper.stopService(this)
            return
        }

        if (QuickSettingsTileStore.loadProfile(this) == null) {
            launchHostApp()
            return
        }

        if (VpnService.prepare(this) != null) {
            val permissionIntent = Intent(this, VpnPermissionActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivityAndCollapse(permissionIntent)
            return
        }

        isPendingConnect = true
        VpnLaunchHelper.startFromStore(this)
        updateTile()
    }

    private fun updateTile() {
        val tile = qsTile ?: return
        val customLabel = QuickSettingsTileStore.getTileLabel(this)
        val connecting = isConnectingState()

        tile.label = when {
            customLabel != null -> customLabel
            connecting -> getString(R.string.tile_state_connecting)
            else -> getString(R.string.tile_label_default)
        }

        tile.icon = resolveTileIcon() ?: Icon.createWithResource(this, R.drawable.ic_tile_vpn)
        tile.state = when {
            connecting -> Tile.STATE_UNAVAILABLE
            vpnState == AppConfigs.V2RAY_STATES.V2RAY_CONNECTED -> Tile.STATE_ACTIVE
            else -> Tile.STATE_INACTIVE
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = if (vpnState == AppConfigs.V2RAY_STATES.V2RAY_CONNECTED && !connecting) {
                val remark = QuickSettingsTileStore.loadProfile(this)?.remark
                if (!remark.isNullOrEmpty()) remark else null
            } else {
                null
            }
        }

        tile.updateTile()
    }

    private fun isConnectingState(): Boolean {
        return vpnState == AppConfigs.V2RAY_STATES.V2RAY_CONNECTING ||
            (isPendingConnect && vpnState != AppConfigs.V2RAY_STATES.V2RAY_CONNECTED)
    }

    private fun registerStateReceiver() {
        if (receiverRegistered) return
        val filter = IntentFilter(AppConfigs.V2RAY_CONNECTION_INFO)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(stateReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(stateReceiver, filter)
        }
        receiverRegistered = true
    }

    private fun unregisterStateReceiver() {
        if (!receiverRegistered) return
        try {
            unregisterReceiver(stateReceiver)
        } finally {
            receiverRegistered = false
        }
    }

    private fun resolveTileIcon(): Icon? {
        val tileType = QuickSettingsTileStore.getTileIconType(this)
        val tileName = QuickSettingsTileStore.getTileIconName(this)
        if (tileType != null && tileName != null) {
            val resId = resources.getIdentifier(tileName, tileType, packageName)
            if (resId != 0) {
                return Icon.createWithResource(this, resId)
            }
        }

        val notificationType = QuickSettingsTileStore.getNotificationIconType(this)
        val notificationName = QuickSettingsTileStore.getNotificationIconName(this)
        if (notificationType != null && notificationName != null) {
            val resId = resources.getIdentifier(notificationName, notificationType, packageName)
            if (resId != 0) {
                return Icon.createWithResource(this, resId)
            }
        }

        return null
    }

    private fun launchHostApp() {
        val launchIntent = packageManager.getLaunchIntentForPackage(packageName) ?: return
        launchIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        startActivityAndCollapse(launchIntent)
    }

    private fun readStateExtra(intent: Intent): AppConfigs.V2RAY_STATES? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getSerializableExtra("STATE", AppConfigs.V2RAY_STATES::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getSerializableExtra("STATE") as? AppConfigs.V2RAY_STATES
        }
    }
}
