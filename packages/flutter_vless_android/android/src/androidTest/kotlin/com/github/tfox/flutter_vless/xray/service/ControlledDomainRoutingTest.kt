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
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class ControlledDomainRoutingTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private fun snapshot() = XrayCoreManager.getProviderDebugSnapshot(context)
    private fun captured() = context.getSystemService(ConnectivityManager::class.java)
        .getNetworkCapabilities(context.getSystemService(ConnectivityManager::class.java).activeNetwork)
        ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    private fun awaitReady(previousConnections: Int = 0) {
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(45)
        while (System.nanoTime() < end) {
            if (captured() && snapshot().lineSequence().count { it == "CONNECTED" } > previousConnections) return
            Thread.sleep(100)
        }
        fail("Routing session unavailable; events=${snapshot()}")
    }
    private fun request(host: String): String = Socket().use {
        it.soTimeout = 4000; it.connect(InetSocketAddress("10.0.2.2", 18083), 4000)
        it.getOutputStream().write("GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n".toByteArray())
        it.getInputStream().bufferedReader().readText()
    }
    private fun traffic(): Map<String, Long> {
        val process = ProcessBuilder(File(context.applicationInfo.nativeLibraryDir, "libxray.so").absolutePath,
            "api", "statsquery", "--server=127.0.0.1:10809", "--pattern", "outbound>>>").start()
        try {
            val stats = JSONObject(process.inputStream.bufferedReader().readText()).getJSONArray("stat")
            assertTrue(process.waitFor(3, TimeUnit.SECONDS)); assertEquals(0, process.exitValue())
            val result = mutableMapOf("direct" to 0L, "proxy" to 0L)
            for (i in 0 until stats.length()) {
                val entry = stats.getJSONObject(i)
                val name = entry.getString("name")
                for (tag in result.keys.toList()) if (name.startsWith("outbound>>>$tag>>>traffic>>>")) result[tag] = result.getValue(tag) + entry.optLong("value", 0L)
            }
            return result
        } finally { process.destroy() }
    }
    private fun assertRoutes() {
        val beforeDirect = traffic()
        assertTrue("Domain direct route must reach the physical control origin", request("direct-site.invalid").contains("flutter-vless-direct-bypass"))
        val afterDirect = traffic()
        assertTrue("Direct outbound must carry application bytes", afterDirect.getValue("direct") > beforeDirect.getValue("direct"))
        assertTrue("Domain proxy route must reach the proxy control origin", request("proxy-site.invalid").contains("flutter-vless-protected-host"))
        val afterProxy = traffic()
        assertTrue("Proxy outbound must carry application bytes", afterProxy.getValue("proxy") > afterDirect.getValue("proxy"))
        assertEquals("Proxy request must not use direct outbound", afterDirect.getValue("direct"), afterProxy.getValue("direct"))
    }
    @Test fun sniffedDomainRulesSelectDirectAndProxyAndSurviveRecovery() {
        val config = XrayConfig(REMARK = "Controlled routing", V2RAY_FULL_JSON_CONFIG = """
            {"inbounds":[],"dns":{"hosts":{"direct-site.invalid":"10.0.2.2","proxy-site.invalid":"10.0.2.2"},"servers":[]},
             "outbounds":[{"tag":"proxy","protocol":"socks","settings":{"address":"10.0.2.2","port":18080}},
                          {"tag":"direct","protocol":"freedom","settings":{"domainStrategy":"UseIP"}}],
             "routing":{"rules":[{"type":"field","domain":["full:direct-site.invalid"],"outboundTag":"direct"},
                                   {"type":"field","domain":["full:proxy-site.invalid"],"outboundTag":"proxy"}]}}
        """.trimIndent())
        try {
            context.startForegroundService(Intent(context, XrayVPNService::class.java)
                .putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE).putExtra("V2RAY_CONFIG", config))
            awaitReady(); assertRoutes()
            val prior = snapshot().lineSequence().count { it == "CONNECTED" }
            assertEquals(0, ProcessBuilder("pkill", "-9", "-x", "libxray.so").start().waitFor())
            awaitReady(prior); assertRoutes()
        } finally {
            context.startService(Intent(context, XrayVPNService::class.java).putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE))
            Thread.sleep(500)
        }
    }
}
