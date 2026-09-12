package com.github.tfox.flutter_vless.xray.service

import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
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
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.util.concurrent.TimeUnit

/** Optional real-profile acceptance: inputs supplied privately in the test app's noBackup directory. */
@RunWith(AndroidJUnit4::class)
class ActualProfileRoutingTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private fun snapshot() = XrayCoreManager.getProviderDebugSnapshot(context)
    private fun captured() = context.getSystemService(ConnectivityManager::class.java)
        .getNetworkCapabilities(context.getSystemService(ConnectivityManager::class.java).activeNetwork)
        ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    private fun start(raw: String, proxyOnly: Boolean): Boolean {
        if (!proxyOnly) check(android.net.VpnService.prepare(context) == null) { "Disposable test VPN consent is required" }
        val result = java.util.concurrent.atomic.AtomicInteger(-1)
        val accepted = java.util.concurrent.CountDownLatch(1)
        val receiver = object : android.os.ResultReceiver(null) {
            override fun onReceiveResult(code: Int, data: android.os.Bundle?) { result.set(code); accepted.countDown() }
        }
        context.startForegroundService(Intent(context, XrayVPNService::class.java)
            .putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE)
            .putExtra("PROXY_ONLY", proxyOnly)
            .putExtra("start_receiver", receiver)
            .putExtra("V2RAY_CONFIG", XrayConfig(REMARK = "Private routing acceptance", V2RAY_FULL_JSON_CONFIG = raw,
                ANDROID_DNS_POLICY = if (proxyOnly) "config" else "proxy")))
        assertTrue("Private test START must finish native validation", accepted.await(15, TimeUnit.SECONDS))
        return result.get() == 0
    }
    private fun stop() {
        context.startService(Intent(context, XrayVPNService::class.java).putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE))
        Thread.sleep(750)
    }
    private fun await(description: String, predicate: () -> Boolean) {
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(60)
        while (System.nanoTime() < end) { if (predicate()) return; Thread.sleep(150) }
        fail("$description; events=${snapshot()}")
    }
    private fun get(url: String, socksPort: Int? = null): String {
        val proxy = socksPort?.let { Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", it)) } ?: Proxy.NO_PROXY
        val connection = URL(url).openConnection(proxy) as HttpURLConnection
        // Each site's routing assertion requires a distinct TLS connection. A shared Android HTTP
        // pool may otherwise reuse a connection whose original SNI belongs to the preceding site.
        (connection as javax.net.ssl.HttpsURLConnection).sslSocketFactory = javax.net.ssl.SSLContext.getInstance("TLS").apply {
            init(null, null, null)
        }.socketFactory
        try {
            connection.connectTimeout = 10000; connection.readTimeout = 10000
            connection.instanceFollowRedirects = false; connection.setRequestProperty("Connection", "close")
            assertEquals(200, connection.responseCode)
            return connection.inputStream.bufferedReader().use { it.readText().trim() }.also {
                assertTrue("IP service must return only an address", it.matches(Regex("[0-9a-fA-F:.]{2,80}")))
            }
        } finally { connection.disconnect() }
    }
    private fun traffic(): Map<String, Long> {
        val process = ProcessBuilder(File(context.applicationInfo.nativeLibraryDir, "libxray.so").absolutePath,
            "api", "statsquery", "--server=127.0.0.1:10809", "--pattern", "outbound>>>").start()
        try {
            val stats = JSONObject(process.inputStream.bufferedReader().readText()).getJSONArray("stat")
            assertTrue(process.waitFor(3, TimeUnit.SECONDS)); assertEquals(0, process.exitValue())
            val result = mutableMapOf("direct" to 0L, "proxy" to 0L, "direct_down" to 0L)
            for (i in 0 until stats.length()) {
                val entry = stats.getJSONObject(i); val name = entry.getString("name")
                for (tag in listOf("direct", "proxy")) if (name.startsWith("outbound>>>$tag>>>traffic>>>")) result[tag] = result.getValue(tag) + entry.optLong("value", 0L)
                if (name == "outbound>>>direct>>>traffic>>>downlink") result["direct_down"] = entry.optLong("value", 0L)
            }
            return result
        } finally { process.destroy() }
    }
    private fun assertRoutes(generation: Int) {
        val before = traffic()
        val directIp = get("https://api.ipify.org/")
        Thread.sleep(300)
        var afterDirect = traffic()
        val initialDirect = afterDirect.getValue("direct")
        val settleEnd = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        while (afterDirect.getValue("direct_down") <= before.getValue("direct_down") && System.nanoTime() < settleEnd) {
            Thread.sleep(100); afterDirect = traffic()
        }
        instrumentation.sendStatus(0, android.os.Bundle().apply {
            putString("stream", "Direct response counter observation initial_bytes=$initialDirect complete_bytes=${afterDirect.getValue("direct")} complete_download_bytes=${afterDirect.getValue("direct_down")}\n")
        })
        assertTrue("Completed direct response must be represented in native download statistics", afterDirect.getValue("direct_down") > before.getValue("direct_down"))
        assertTrue("Direct domain must transfer bytes through direct outbound", afterDirect.getValue("direct") > before.getValue("direct"))
        val proxyIp = get("https://api4.ipify.org/")
        Thread.sleep(300)
        val afterProxy = traffic()
        instrumentation.sendStatus(0, android.os.Bundle().apply {
            putString("stream", "Actual routing generation=$generation direct_egress=$directIp proxy_egress=$proxyIp direct_bytes=${afterDirect.getValue("direct") - before.getValue("direct")} proxy_bytes=${afterProxy.getValue("proxy") - afterDirect.getValue("proxy")} proxy_request_direct_bytes=${afterProxy.getValue("direct") - afterDirect.getValue("direct")}\n")
        })
        assertTrue("Proxy domain must transfer bytes through proxy outbound", afterProxy.getValue("proxy") > afterDirect.getValue("proxy"))
        assertEquals("Proxy domain must not transfer payload through direct", afterDirect.getValue("direct"), afterProxy.getValue("direct"))
        // Public control egress and aggregate counts only; never print input configurations/credentials.
    }
    @Test fun suppliedProfileSeparatesDomainRoutesAndPreservesThemAfterRecovery() {
        val name = InstrumentationRegistry.getArguments().getString("actualProfile")
        org.junit.Assume.assumeTrue("Private profile was not supplied", name != null)
        require(name!!.matches(Regex("profile-[12]"))) { "Unexpected private test input name" }
        val original = File(context.noBackupFilesDir, "$name.json").readText()
        val vpn = File(context.noBackupFilesDir, "$name-vpn.json").readText()
        try {
            stop()
            assertTrue(start(original, proxyOnly = true))
            await("proxy-only baselines ready") { snapshot().lineSequence().lastOrNull() == "CONNECTED" && !captured() }
            for ((url, site) in listOf("https://api.ipify.org/" to "direct-site", "https://api4.ipify.org/" to "proxy-site")) {
                val physical = get(url, 10820); val proxied = get(url, 10808)
                instrumentation.sendStatus(0, android.os.Bundle().apply {
                    putString("stream", "Actual routing baseline site=$site physical_egress=$physical proxy_egress=$proxied\n")
                })
            }
            stop()
            assertTrue(start(vpn, proxyOnly = false))
            await("VPN routes ready") { captured() && snapshot().lineSequence().lastOrNull { it.isNotBlank() } == "CONNECTED" }
            assertRoutes(1)
            // The original extra direct SOCKS input must reject before replacing this working VPN.
            assertFalse(start(original, proxyOnly = false))
            await("incompatible replacement rejected") { snapshot().contains("CONFIG_REJECTED") }
            assertTrue(captured())
            val before = snapshot().lineSequence().count { it == "CONNECTED" }
            assertEquals(0, ProcessBuilder("pkill", "-9", "-x", "libxray.so").start().waitFor())
            await("recovered routes ready") { captured() && snapshot().lineSequence().count { it == "CONNECTED" } > before }
            assertRoutes(2)
        } finally { stop() }
    }
}
