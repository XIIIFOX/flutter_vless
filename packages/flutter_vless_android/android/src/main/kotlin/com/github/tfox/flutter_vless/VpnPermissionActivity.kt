package com.github.tfox.flutter_vless

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle

/**
 * Transparent activity used by [VlessTileService] to request VPN consent
 * when toggling a VPN-mode profile from Quick Settings or the lock screen.
 * Proxy-only profiles skip this activity.
 */
class VpnPermissionActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val profile = QuickSettingsTileStore.loadProfile(this)
        if (profile?.proxyOnly == true) {
            startSavedProfile()
            finish()
            return
        }
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            startActivityForResult(prepareIntent, REQUEST_VPN)
        } else {
            startSavedProfile()
            finish()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN) {
            if (resultCode == RESULT_OK) {
                startSavedProfile()
            }
            finish()
        }
    }

    private fun startSavedProfile() {
        VpnLaunchHelper.startFromStore(applicationContext)
    }

    companion object {
        private const val REQUEST_VPN = 1001
    }
}
