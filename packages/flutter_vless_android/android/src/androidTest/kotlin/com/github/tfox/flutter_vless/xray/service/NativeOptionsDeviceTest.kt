package com.github.tfox.flutter_vless.xray.service

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class NativeOptionsDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private fun emulatorOnly() { check(Build.HARDWARE in setOf("ranchu","goldfish")) { "Disposable emulator only" } }
    @Test fun profileNamespacesUseAuthenticatedEncryptionAndClearIndependently() {
        emulatorOnly()
        val authorized=AuthorizedProfileStore(context)
        val quick=AuthorizedProfileStore(context,AuthorizedProfileStore.Kind.QUICK_ACCESS)
        val profile=XrayConfig(REMARK="quick-canary",V2RAY_FULL_JSON_CONFIG="secret-vpn-canary")
        try {
            authorized.save(profile); quick.save(profile)
            val encrypted=File(context.noBackupFilesDir,"flutter_vless_quick_access_v1.bin")
            assertFalse(encrypted.readBytes().toString(Charsets.ISO_8859_1).contains("secret-vpn-canary"))
            assertEquals(profile.V2RAY_FULL_JSON_CONFIG,quick.load().V2RAY_FULL_JSON_CONFIG)
            authorized.disarm(); assertFalse(authorized.exists()); assertTrue(quick.exists())
            val tampered=encrypted.readBytes(); tampered[tampered.lastIndex]=(tampered.last().toInt() xor 1).toByte(); encrypted.writeBytes(tampered)
            var rejected=false; try { quick.load() } catch (_:Exception) { rejected=true }; assertTrue(rejected)
            quick.save(profile); quick.disarm(); assertFalse(quick.exists())
        } finally { authorized.disarm(); quick.disarm() }
    }
    @Test fun optionsSurviveNewStoreInstancesAndCorruptionDisablesControls() {
        emulatorOnly()
        val file=File(context.noBackupFilesDir,"flutter_vless_options_v1.json")
        val old=if(file.exists()) file.readBytes() else null
        try {
            val options=NativeVlessOptions(quickAccess=NativeVlessOptions.QuickAccess(enabled=true,label="Fixture VPN"),reconnect=NativeVlessOptions.Reconnect(maxAttempts=3),diagnostics=NativeVlessOptions.Diagnostics(false,4096,7))
            NativeOptionsStore(context).write(options)
            assertEquals(options,NativeOptionsStore(context).read())
            file.writeText("corrupt")
            val recovered=NativeOptionsStore(context).read()
            assertFalse(recovered.quickAccess.enabled); assertFalse(recovered.diagnostics.enabled)
        } finally { if(old==null) file.delete() else file.writeBytes(old) }
    }
}
