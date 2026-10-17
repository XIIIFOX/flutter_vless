package com.github.tfox.flutter_vless

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import com.github.tfox.flutter_vless.xray.service.NativeOptionsStore
import com.github.tfox.flutter_vless.xray.service.XrayVPNService

/** Permission UI only. No profile or native action is accepted from intent extras. */
class VlessTilePermissionActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!NativeOptionsStore(this).read().quickAccess.enabled) { finish(); return }
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
    private fun connect() {
        if (NativeOptionsStore(this).read().quickAccess.enabled && VpnService.prepare(this) == null) {
            val service = Intent(this,XrayVPNService::class.java).setAction(XrayVPNService.ACTION_QUICK_ACCESS_TOGGLE)
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(service) else startService(service)
        }
        finish()
    }
}
