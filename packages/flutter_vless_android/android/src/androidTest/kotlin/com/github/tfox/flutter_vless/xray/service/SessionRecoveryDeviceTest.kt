package com.github.tfox.flutter_vless.xray.service

import android.app.ActivityManager
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.github.tfox.flutter_vless.xray.core.XrayCoreManager
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.TimeUnit

/** Uses tool/android_protection_fixture.py --relay-readiness; host VPN remains enabled. */
@RunWith(AndroidJUnit4::class)
class SessionRecoveryDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val manager get() = context.getSystemService(ConnectivityManager::class.java)
    private fun captured() = manager.getNetworkCapabilities(manager.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    private fun snapshot() = XrayCoreManager.getProviderDebugSnapshot(context)
    private fun profile() = XrayConfig(REMARK = "Recovery test", V2RAY_FULL_JSON_CONFIG =
        """{"inbounds":[],"outbounds":[{"tag":"proxy","protocol":"socks","settings":{"address":"10.0.2.2","port":18080}}]}""")
    private fun start(value: XrayConfig = profile()) {
        assertNull(VpnService.prepare(context))
        context.startForegroundService(Intent(context, XrayVPNService::class.java)
            .putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE).putExtra("V2RAY_CONFIG", value))
    }
    private fun await(description: String, predicate: () -> Boolean) {
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(45)
        while (System.nanoTime() < end) { if (predicate()) return; Thread.sleep(100) }
        fail("$description; events=${snapshot()}")
    }
    private fun directProbe(): String = Socket().use {
        it.soTimeout = 1500
        it.connect(InetSocketAddress("10.0.2.2", 18083), 500)
        it.getOutputStream().write("GET / HTTP/1.1\r\nHost: 10.0.2.2:18083\r\nConnection: close\r\n\r\n".toByteArray())
        it.getInputStream().bufferedReader().readText()
    }
    @After fun stop() {
        context.startService(Intent(context, XrayVPNService::class.java).putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE))
        Thread.sleep(500)
    }
    @Test fun bothNativeWorkerCrashesRetainTunAndNeverExposeTheDirectControl() {
        start(); await("initial ready") { snapshot().contains("CONNECTED") && captured() }
        assertTrue(directProbe().contains("flutter-vless-protected-host"))
        for (workerName in listOf("libxray.so", "libtun2socks.so")) {
            val leak = AtomicBoolean(false); val lostTun = AtomicBoolean(false); val sampling = AtomicBoolean(true)
            val sampler = Thread {
                while (sampling.get()) {
                    if (!captured()) lostTun.set(true)
                    if (runCatching { directProbe() }.getOrDefault("").contains("flutter-vless-direct-bypass")) leak.set(true)
                }
            }.apply { start() }
            try {
                val before = snapshot().split("CONNECTED").size
                assertEquals(0, ProcessBuilder("pkill", "-9", "-x", workerName).start().waitFor())
                await("worker recovery") { snapshot().contains("RECOVERING") && snapshot().split("CONNECTED").size > before }
                assertTrue(directProbe().contains("flutter-vless-protected-host"))
            } finally { sampling.set(false); sampler.join(2000) }
            assertFalse("TUN disappeared while workers recovered", lostTun.get())
            assertFalse("Control traffic escaped directly", leak.get())
        }
    }
    @Test fun invalidReplacementPreservesActiveSessionAndStopDisarmsSystemRestore() {
        start(profile().apply { BLOCKED_APPS.add("com.fluttervless.uninstalled.exclusion") }); await("initial ready") { snapshot().contains("CONNECTED") && captured() }
        start(profile().apply { V2RAY_FULL_JSON_CONFIG = """{"inbounds":[],"outbounds":[{"protocol":"unsupported-canary"}]}""" })
        await("replacement rejection") { snapshot().contains("CONFIG_REJECTED") }
        assertTrue(captured()); assertTrue(directProbe().contains("flutter-vless-protected-host"))
        stop(); await("explicit stop") { !captured() }
        context.startForegroundService(Intent(context, XrayVPNService::class.java))
        await("system restore disarmed") { snapshot().contains("PROFILE_UNAVAILABLE") }
        Thread.sleep(1500)
        assertFalse(captured())
    }
    @Test fun wholeServiceCrashRestoresAuthorizedEncryptedProfile() {
        start(); await("initial ready") { snapshot().contains("CONNECTED") && captured() }
        val service = context.getSystemService(ActivityManager::class.java).runningAppProcesses.first {
            it.processName == "${context.packageName}:RunSoLibXrayDaemon"
        }
        val oldFiles = context.noBackupFilesDir.listFiles().orEmpty().filter { it.name.startsWith("xray-") || it.name.startsWith("tun-") }
        assertEquals(2, oldFiles.size)
        android.os.Process.killProcess(service.pid)
        // Android START_STICKY delivers a null Intent; request system-style startup if restart is delayed.
        Thread.sleep(1000)
        context.startForegroundService(Intent(context, XrayVPNService::class.java))
        await("authorized service restore") { snapshot().contains("CONNECTED") && captured() && runCatching { directProbe().contains("flutter-vless-protected-host") }.getOrDefault(false) }
        assertTrue(snapshot().contains("CONNECTED"))
        oldFiles.forEach { assertFalse("Abandoned service config must be removed after restore", it.exists()) }
    }
}
