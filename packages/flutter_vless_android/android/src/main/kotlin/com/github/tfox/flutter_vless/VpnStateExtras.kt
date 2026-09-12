package com.github.tfox.flutter_vless

import android.content.Intent
import android.os.Build
import com.github.tfox.flutter_vless.xray.utils.AppConfigs

internal object VpnStateExtras {
    const val EXTRA_STATE = "STATE"
    const val EXTRA_STATE_NAME = "STATE_NAME"

    fun put(intent: Intent, state: AppConfigs.V2RAY_STATES) {
        intent.putExtra(EXTRA_STATE, state)
        intent.putExtra(EXTRA_STATE_NAME, state.name)
    }

    fun read(intent: Intent): AppConfigs.V2RAY_STATES? {
        val typed = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getSerializableExtra(EXTRA_STATE, AppConfigs.V2RAY_STATES::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getSerializableExtra(EXTRA_STATE) as? AppConfigs.V2RAY_STATES
        }
        if (typed != null) {
            return typed
        }
        val name = intent.getStringExtra(EXTRA_STATE_NAME) ?: return null
        return runCatching { AppConfigs.V2RAY_STATES.valueOf(name) }
            .getOrDefault(AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED)
    }
}
