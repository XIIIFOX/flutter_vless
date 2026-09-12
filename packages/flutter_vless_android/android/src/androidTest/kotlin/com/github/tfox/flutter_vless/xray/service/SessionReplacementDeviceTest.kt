package com.github.tfox.flutter_vless.xray.service

import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import android.os.ResultReceiver
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.github.tfox.flutter_vless.xray.core.AuthenticatedSocksClient
import com.github.tfox.flutter_vless.xray.core.LocalProxyCredentials
import com.github.tfox.flutter_vless.xray.core.XrayCoreManager
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

@RunWith(AndroidJUnit4::class)
class SessionReplacementDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val raw = """{"inbounds":[],"outbounds":[{"tag":"proxy","protocol":"socks","settings":{"address":"10.0.2.2","port":18080}}]}"""
    private fun captured(): Boolean {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        return manager.getNetworkCapabilities(manager.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }
    private fun start(json: String = raw): Boolean {
        check(android.net.VpnService.prepare(context) == null) { "Disposable test VPN consent is required" }
        val result = AtomicInteger(-1); val latch = CountDownLatch(1)
        val receiver = object : ResultReceiver(null) {
            override fun onReceiveResult(code: Int, data: Bundle?) { result.set(code); latch.countDown() }
        }
        context.startForegroundService(Intent(context, XrayVPNService::class.java)
            .putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE)
            .putExtra("V2RAY_CONFIG", XrayConfig(REMARK = "Replacement control", V2RAY_FULL_JSON_CONFIG = json))
            .putExtra("start_receiver", receiver))
        assertTrue("Every START must complete its IPC result", latch.await(15, TimeUnit.SECONDS))
        return result.get() == 0
    }
    private fun stop() = context.startService(Intent(context, XrayVPNService::class.java)
        .putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE))
    private fun await(description: String, predicate: () -> Boolean) {
        repeat(450) { if (predicate()) return; Thread.sleep(100) }
        fail(description)
    }
    private fun ready() = captured() && XrayCoreManager.getProviderDebugSnapshot(context).contains("CONNECTED")
    private fun credentials(): Pair<Int, LocalProxyCredentials> {
        val file = context.noBackupFilesDir.listFiles().orEmpty().single { it.name.startsWith("xray-") }
        val inputs = JSONObject(file.readText()).getJSONArray("inbounds")
        val socks = (0 until inputs.length()).map { inputs.getJSONObject(it) }.single { it.optString("protocol") == "socks" }
        val account = socks.getJSONObject("settings").getJSONArray("accounts").getJSONObject(0)
        return socks.getInt("port") to LocalProxyCredentials(account.getString("user"), account.getString("pass"))
    }
    @Test fun newSessionRejectsOldCredentialsAndStopThenInvalidStartLeavesNoOldSession() {
        try {
            assertTrue(start()); await("initial session ready", ::ready)
            val (port, old) = credentials()
            assertTrue(AuthenticatedSocksClient.measure(port, old, "http://192.0.2.99:18081/") >= 0)
            assertTrue(start()); await("replacement session ready", ::ready)
            val (newPort, current) = credentials()
            assertNotEquals(old, current)
            assertTrue(AuthenticatedSocksClient.measure(newPort, current, "http://192.0.2.99:18081/") >= 0)
            assertThrows(Exception::class.java) { AuthenticatedSocksClient.measure(newPort, old, "http://192.0.2.99:18081/") }
            stop()
            assertFalse("Malformed START after STOP must be rejected", start("{"))
            await("STOP must release the old session despite newer invalid START") {
                !captured() && !File(context.noBackupFilesDir, "flutter_vless_authorized_v1.bin").exists() &&
                    context.noBackupFilesDir.listFiles().orEmpty().none { it.name.startsWith("xray-") || it.name.startsWith("tun-") }
            }
            Thread.sleep(1500); assertFalse(captured())
        } finally { stop() }
    }
}
