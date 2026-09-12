package com.github.tfox.flutter_vless

import android.app.PendingIntent
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
            val state = VpnStateExtras.read(intent) ?: return
            applyCoreState(state)
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        QuickSettingsTileStore.loadNotificationIconIntoAppConfigs(this)
        registerStateReceiver()
        // Prefs are only a hint until the VPN process answers.
        applyCoreState(QuickSettingsTileStore.loadVpnState(this), fromCore = false)
        requestVpnState()
    }

    override fun onStopListening() {
        cancelPendingReconcile()
        unregisterStateReceiver()
        super.onStopListening()
    }

    override fun onClick() {
        // unlockAndRun collapses Quick Settings even on an unlocked device.
        // Keep the shade open for VPN toggle; still unlock when the keyguard is up.
        if (isLocked) {
            unlockAndRun { handleClick() }
        } else {
            handleClick()
        }
    }

    private fun handleClick() {
        if (vpnState == AppConfigs.V2RAY_STATES.V2RAY_CONNECTED) {
            VpnLaunchHelper.stopService(this)
            return
        }
        if (isConnectingState()) return

        val profile = QuickSettingsTileStore.loadProfile(this)
        if (profile == null) {
            launchHostApp()
            return
        }

        if (!profile.proxyOnly && VpnService.prepare(this) != null) {
            val permissionIntent = Intent(this, VpnPermissionActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivityAndCollapseCompat(permissionIntent, REQUEST_CODE_VPN_PERMISSION)
            return
        }

        if (!VpnLaunchHelper.startFromStore(this)) {
            return
        }

        isPendingConnect = true
        schedulePendingReconcile()
        updateTile()
    }

    private fun applyCoreState(state: AppConfigs.V2RAY_STATES, fromCore: Boolean = true) {
        if (state == AppConfigs.V2RAY_STATES.V2RAY_CONNECTED ||
            state == AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED
        ) {
            isPendingConnect = false
            cancelPendingReconcile()
            if (fromCore) {
                QuickSettingsTileStore.saveVpnState(this, state)
            }
        }
        vpnState = state
        updateTile()
    }

    private fun updateTile() {
        val tile = qsTile ?: return
        val customLabel = QuickSettingsTileStore.getTileLabel(this)
        // Appearance follows the core. Local pending-connect only blocks
        // double-taps; it must not freeze the tile as UNAVAILABLE.
        val connecting = vpnState == AppConfigs.V2RAY_STATES.V2RAY_CONNECTING

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
            isPendingConnect
    }

    private fun schedulePendingReconcile() {
        cancelPendingReconcile()
        pendingReconcileRunnable = Runnable {
            isPendingConnect = false
            requestVpnState()
            updateTile()
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
        filter.addAction(AppConfigs.ACTION_TILE_STATE)
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
        startActivityAndCollapseCompat(launchIntent, REQUEST_CODE_LAUNCH_APP)
    }

    /**
     * Android 14+ throws if [startActivityAndCollapse] is called with a raw
     * [Intent] when targetSdk is 34+. Use [PendingIntent] on API 34+ and the
     * deprecated Intent overload on older platforms.
     */
    private fun startActivityAndCollapseCompat(intent: Intent, requestCode: Int) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pendingIntent = PendingIntent.getActivity(
                this,
                requestCode,
                intent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            startActivityAndCollapse(pendingIntent)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    companion object {
        private const val PENDING_RECONCILE_DELAY_MS = 1500L
        private const val REQUEST_CODE_VPN_PERMISSION = 1
        private const val REQUEST_CODE_LAUNCH_APP = 2
    }
}
