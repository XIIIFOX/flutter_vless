package com.github.tfox.flutter_vless

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import com.github.tfox.flutter_vless.xray.service.NativeOptionsStore
import com.github.tfox.flutter_vless.xray.service.XrayVPNService

/** Non-exported permission UI. Extras carry only a stale-rejectable intent, never profile data or authority. */
class VlessTilePermissionActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (currentAction() == null) { finish(); return }
        if (savedInstanceState != null) return
        val permission = VpnService.prepare(this)
        if (permission == null) connect() else {
            @Suppress("DEPRECATION")
            startActivityForResult(permission,24)
        }
    }
    @Deprecated("Legacy Activity permission callback")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode,resultCode,data)
        if (requestCode == 24 && resultCode == RESULT_OK) connect() else finish()
    }
    private fun currentAction() = NativeQuickAccess.action(intent)?.takeIf {
        it.operation == com.github.tfox.flutter_vless.xray.service.QuickAccessAction.Operation.START &&
            it.permits(NativeOptionsStore(this).readSnapshot(), NativeQuickAccess.locked(this)) &&
            !XrayVPNService.hasAcceptedSession() && NativeQuickAccess.profile(this).revision() == it.profile
    }
    internal fun connect() {
        val ticket = currentAction()
        if (ticket != null && VpnService.prepare(this) == null) {
            val service = NativeQuickAccess.putAction(Intent(this,XrayVPNService::class.java)
                .setAction(XrayVPNService.ACTION_QUICK_ACCESS_TOGGLE), ticket)
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(service) else startService(service)
        }
        finish()
    }
}
