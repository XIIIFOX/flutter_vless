package com.github.tfox.flutter_vless

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle

/**
 * Transparent activity used by [VlessTileService] to request VPN consent
 * when toggling from Quick Settings or the lock screen.
 */
class VpnPermissionActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
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
