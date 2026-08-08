package com.github.tfox.flutter_vless

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.github.tfox.flutter_vless.xray.utils.AppConfigs

class VlessTileService : TileService() {

    private var receiverRegistered = false
    private var vpnState = AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED
    private var isPendingConnect = false
    private val mainHandler = Handler(Looper.getMainLooper())
    private var pendingReconcileRunnable: Runnable? = null

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent == null) return
            val state = readStateExtra(intent) ?: run {
                reconcileVpnState()
                updateTile()
                return
            }
            if (state == vpnState && !isPendingConnect) return
            vpnState = state
            when (state) {
                AppConfigs.V2RAY_STATES.V2RAY_CONNECTED,
                AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED,
                -> {
                    isPendingConnect = false
                    cancelPendingReconcile()
                    context?.let { QuickSettingsTileStore.saveVpnState(it, state) }
                }
                else -> Unit
            }
            updateTile()
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        QuickSettingsTileStore.loadNotificationIconIntoAppConfigs(this)
        registerStateReceiver()
        vpnState = QuickSettingsTileStore.loadVpnState(this)
        reconcileVpnState()
        updateTile()
        requestVpnState()
    }

    override fun onStopListening() {
        cancelPendingReconcile()
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

        if (!VpnLaunchHelper.startFromStore(this)) {
            return
        }

        isPendingConnect = true
        schedulePendingReconcile()
        updateTile()
    }

    private fun updateTile() {
        val tile = qsTile ?: return
        reconcileVpnState()
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
        if (vpnState == AppConfigs.V2RAY_STATES.V2RAY_CONNECTED) {
            return false
        }
        return vpnState == AppConfigs.V2RAY_STATES.V2RAY_CONNECTING ||
            isPendingConnect
    }

    private fun reconcileVpnState() {
        val persisted = QuickSettingsTileStore.loadVpnState(this)
        if (persisted == AppConfigs.V2RAY_STATES.V2RAY_CONNECTED) {
            vpnState = persisted
            isPendingConnect = false
            cancelPendingReconcile()
            return
        }
        if (!isPendingConnect && persisted != vpnState) {
            vpnState = persisted
        }
    }

    private fun schedulePendingReconcile() {
        cancelPendingReconcile()
        pendingReconcileRunnable = Runnable {
            reconcileVpnState()
            updateTile()
            requestVpnState()
        }
        mainHandler.postDelayed(pendingReconcileRunnable!!, PENDING_RECONCILE_DELAY_MS)
    }

    private fun cancelPendingReconcile() {
        pendingReconcileRunnable?.let { mainHandler.removeCallbacks(it) }
        pendingReconcileRunnable = null
    }

    private fun requestVpnState() {
        sendBroadcast(
            Intent(AppConfigs.ACTION_REQUEST_VPN_STATE).setPackage(packageName),
        )
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
        val typed = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getSerializableExtra("STATE", AppConfigs.V2RAY_STATES::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getSerializableExtra("STATE") as? AppConfigs.V2RAY_STATES
        }
        if (typed != null) {
            return typed
        }
        val name = intent.getStringExtra("STATE_NAME") ?: return null
        return runCatching { AppConfigs.V2RAY_STATES.valueOf(name) }
            .getOrDefault(AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED)
    }

    companion object {
        private const val PENDING_RECONCILE_DELAY_MS = 1500L
    }
}
