package com.github.tfox.flutter_vless.xray.service

import android.app.ActivityManager
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.github.tfox.flutter_vless.xray.core.XrayCoreManager
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.concurrent.TimeUnit

/** Explicit emulator-only OS policy tests; every modified OS policy is restored in finally. */
@RunWith(AndroidJUnit4::class)
class SessionSystemPolicyDeviceTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val manager get() = context.getSystemService(ConnectivityManager::class.java)
    private fun captured() = manager.getNetworkCapabilities(manager.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    private fun snapshot() = XrayCoreManager.getProviderDebugSnapshot(context)
    private fun start() {
        check(android.net.VpnService.prepare(context) == null) { "Disposable test VPN consent is required" }
        context.startForegroundService(Intent(context, XrayVPNService::class.java)
            .putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE)
            .putExtra("V2RAY_CONFIG", XrayConfig(REMARK = "System policy test", V2RAY_FULL_JSON_CONFIG =
                """{"inbounds":[],"outbounds":[{"tag":"proxy","protocol":"socks","settings":{"address":"10.0.2.2","port":18080}}]}""")))
    }
    private fun stop() = context.startService(Intent(context, XrayVPNService::class.java)
        .putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE))
    private fun await(description: String, predicate: () -> Boolean) {
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(45)
        while (System.nanoTime() < end) { if (predicate()) return; Thread.sleep(100) }
        fail("$description; events=${snapshot()}")
    }
    private fun ready() = captured() && snapshot().contains("CONNECTED")
    private fun otherUidProbe(): JSONObject {
        val text = instrumentation.uiAutomation.executeShellCommand(
            "am instrument -w -e mode httpProbe -e url http://10.0.2.2:18083/ -e timeout 1500 " +
                "com.github.tfox.flutter_vless.adversary/com.github.tfox.flutter_vless.adversary.Probe"
        ).use { android.os.ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText() }
        val report = text.lineSequence().firstOrNull { it.startsWith("INSTRUMENTATION_RESULT: report=") }
            ?: error("Separate UID helper unavailable")
        return JSONObject(report.substringAfter("report=")).also { assertNotEquals(android.os.Process.myUid(), it.getInt("adversary_uid")) }
    }
    private fun requireEmulator() {
        check(Build.HARDWARE in setOf("ranchu", "goldfish")) { "This test is restricted to a dedicated emulator" }
    }

    @Test fun osAlwaysOnRestoresAfterProcessDeathAndLockdownSurvivesExplicitStop() {
        requireEmulator()
        val policy = EmulatorVpnPolicy()
        assertNull("Use a dedicated emulator with no prior always-on profile", policy.alwaysOn())
        try {
                stop(); await("initial stop") { !captured() }
                assertTrue("Direct control must be reachable before lockdown", otherUidProbe().getBoolean("success"))
                start(); await("initial session ready", ::ready)
                policy.enableLockdown()
                assertEquals(context.packageName, policy.alwaysOn()); assertTrue(policy.locked())
                val oldPid = context.getSystemService(ActivityManager::class.java).runningAppProcesses.first {
                    it.processName == "${context.packageName}:RunSoLibXrayDaemon"
                }.pid
                android.os.Process.killProcess(oldPid)
                await("OS always-on restart with encrypted authorization") {
                    val replacement = context.getSystemService(ActivityManager::class.java).runningAppProcesses.firstOrNull {
                        it.processName == "${context.packageName}:RunSoLibXrayDaemon" && it.pid != oldPid
                    }
                    replacement != null && ready()
                }
                stop(); await("explicit library stop") { !captured() }
                assertEquals(context.packageName, policy.alwaysOn()); assertTrue(policy.locked())
                val denied = otherUidProbe()
                assertFalse("Other UID escaped OS lockdown", denied.getBoolean("success"))
                assertTrue("No direct application connection is permitted", denied.getBoolean("blocked"))
                Thread.sleep(2000)
                assertFalse("STOP must not re-arm the authorized profile", captured())
                assertFalse(File(context.noBackupFilesDir, "flutter_vless_authorized_v1.bin").exists())
        } finally {
            policy.clearLockdown()
            stop(); await("policy cleanup") { !captured() }
        }
        assertTrue("Direct control must recover after lockdown is removed", otherUidProbe().getBoolean("success"))
    }

    @Test fun lostKeystoreKeyCannotRestoreAnArbitraryProfileOrEscapeLockdown() {
        requireEmulator()
        val policy = EmulatorVpnPolicy()
        assertNull(policy.alwaysOn())
        try {
            start(); await("key-loss control ready", ::ready)
            policy.enableLockdown()
            assertTrue(File(context.noBackupFilesDir, "flutter_vless_authorized_v1.bin").exists())
            File(context.noBackupFilesDir, "validate-11111111-2222-4333-8444-555555555555.json").writeText("abandoned-validation-canary")
            val oldRuntimeFiles = context.noBackupFilesDir.listFiles().orEmpty().filter {
                it.name.startsWith("xray-") || it.name.startsWith("tun-") || it.name.startsWith("validate-")
            }
            java.security.KeyStore.getInstance("AndroidKeyStore").apply {
                load(null)
                assertTrue(containsAlias("flutter_vless.authorized-profile.v1"))
                deleteEntry("flutter_vless.authorized-profile.v1")
                assertFalse(containsAlias("flutter_vless.authorized-profile.v1"))
            }
            val oldPid = context.getSystemService(ActivityManager::class.java).runningAppProcesses.first {
                it.processName == "${context.packageName}:RunSoLibXrayDaemon"
            }.pid
            android.os.Process.killProcess(oldPid)
            await("system restore must diagnose key loss") { snapshot().contains("PROFILE_UNAVAILABLE") && !captured() }
            assertTrue("Failed cold restore must remove abandoned private runtime files", oldRuntimeFiles.none { it.exists() })
            assertEquals(context.packageName, policy.alwaysOn()); assertTrue(policy.locked())
            assertTrue("Other UID must stay blocked when decryption prevents restore", otherUidProbe().getBoolean("blocked"))
            Thread.sleep(1500); assertFalse(captured())
        } finally {
            policy.clearLockdown(); stop(); await("key-loss cleanup") { !captured() }
        }
    }

    @Test fun osForgetVpnRevokesAndDisarmsAutomaticRestoration() {
        requireEmulator()
        val policy = EmulatorVpnPolicy()
        assertNull(policy.alwaysOn())
        try {
            start(); await("revocation control ready", ::ready)
            policy.forget()
            await("OS revoke must stop and disarm") {
                !captured() && !File(context.noBackupFilesDir, "flutter_vless_authorized_v1.bin").exists()
            }
            assertNotNull("OS consent must be required again", android.net.VpnService.prepare(context))
            context.startForegroundService(Intent(context, XrayVPNService::class.java))
            await("system request after revoke must reject missing authorization") { snapshot().contains("PROFILE_UNAVAILABLE") }
            Thread.sleep(1500); assertFalse(captured())
        } finally { stop(); policy.restoreTestConsent() }
    }

    @Test fun rapidStartStopCannotRearmOrDeleteNewSessionFiles() {
        requireEmulator()
        try {
            repeat(10) { start(); stop() }
            start(); await("last explicit START owns the session", ::ready)
            val configs = context.noBackupFilesDir.listFiles().orEmpty().filter { it.name.startsWith("xray-") || it.name.startsWith("tun-") }
            assertEquals(2, configs.size)
            Thread.sleep(2500)
            assertTrue(ready()); configs.forEach { assertTrue(it.exists()) }
            stop(); await("final explicit STOP") { !captured() }
            Thread.sleep(2000)
            assertFalse(captured()); assertFalse(File(context.noBackupFilesDir, "flutter_vless_authorized_v1.bin").exists())
            assertTrue(context.noBackupFilesDir.listFiles().orEmpty().none { it.name.startsWith("xray-") || it.name.startsWith("tun-") })
        } finally { stop() }
    }
}
