package com.github.tfox.flutter_vless.xray.service

import android.content.Intent
import android.net.VpnService
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.util.ArrayList
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLSocketFactory

/** Native library tests: the request originates in the same UID as the service. */
@RunWith(AndroidJUnit4::class)
class ProtectedHostTrafficTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val arguments = InstrumentationRegistry.getArguments()
    private val sentinel = "192.0.2.99"
    private val marker = "flutter-vless-protected-host"

    private fun config(): XrayConfig {
        val port = arguments.getString("proxyPort", "18080")!!.toInt()
        val json = JSONObject().put("log", JSONObject().put("loglevel", "none").put("access", "none"))
            .put("inbounds", JSONArray())
            .put("outbounds", JSONArray().put(JSONObject().put("tag", "proxy").put("protocol", "socks")
                .put("settings", JSONObject().put("address", arguments.getString("proxyHost", "10.0.2.2")).put("port", port))))
        return XrayConfig(V2RAY_FULL_JSON_CONFIG = json.toString(), REMARK = "Native protection regression")
    }

    private fun start(config: XrayConfig, proxyOnly: Boolean = false) {
        assertNull("Authorize ACTIVATE_VPN for the test APK before instrumentation", VpnService.prepare(context))
        context.startForegroundService(Intent(context, XrayVPNService::class.java)
            .putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE)
            .putExtra("V2RAY_CONFIG", config).putExtra("PROXY_ONLY", proxyOnly))
    }

    @After fun stop() {
        context.startService(Intent(context, XrayVPNService::class.java)
            .putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE))
        Thread.sleep(500)
    }

    private fun request(useSocks: Boolean = false): String {
        val socket = if (useSocks) Socket(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", 10807))) else Socket()
        return socket.use {
            it.soTimeout = 2500
            it.connect(InetSocketAddress(sentinel, 18081), 2500)
            it.getOutputStream().write("GET / HTTP/1.1\r\nHost: native-control.test\r\nConnection: close\r\n\r\n".toByteArray())
            it.getInputStream().bufferedReader().readText()
        }
    }

    private fun awaitRequest(useSocks: Boolean = false): String {
        var last: Exception? = null
        repeat(15) {
            try {
                val response = request(useSocks)
                if (response.contains(marker)) return response
            } catch (e: Exception) { last = e }
            Thread.sleep(300)
        }
        throw AssertionError("No response through native runtime", last)
    }

    @Test fun hostUIDTCPAndUDPTraverseProxy() {
        start(config())
        assertTrue(awaitRequest().contains(marker))
        DatagramSocket().use { socket ->
            socket.soTimeout = 5000
            val payload = "native-udp-marker".toByteArray()
            socket.send(DatagramPacket(payload, payload.size, InetAddress.getByName(sentinel), 18082))
            val response = DatagramPacket(ByteArray(256), 256)
            socket.receive(response)
            assertEquals("native-udp-marker", String(response.data, 0, response.length))
        }
    }

    @Test fun explicitHostExclusionAndProxyOnlyRemainExplicit() {
        val excluded = config().apply { BLOCKED_APPS = ArrayList(listOf(context.packageName)) }
        start(excluded)
        assertTrue(awaitRequest(useSocks = true).contains(marker))
        assertFalse(runCatching { request() }.getOrDefault("").contains(marker))
        stop()
        start(config(), proxyOnly = true)
        assertTrue(awaitRequest(useSocks = true).contains(marker))
        assertFalse(runCatching { request() }.getOrDefault("").contains(marker))
    }

    @Test fun hostTrafficSurvivesWifiToCellularAndBack() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val manager = context.getSystemService(android.net.ConnectivityManager::class.java)
        fun physical(transport: Int) = manager.allNetworks.any {
            val caps = manager.getNetworkCapabilities(it)
            caps?.hasTransport(transport) == true && !caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) &&
                caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }
        org.junit.Assume.assumeTrue(physical(android.net.NetworkCapabilities.TRANSPORT_WIFI))
        start(config())
        assertTrue(awaitRequest().contains(marker))
        try {
            instrumentation.uiAutomation.executeShellCommand("svc wifi disable").use {
                android.os.ParcelFileDescriptor.AutoCloseInputStream(it).readBytes()
            }
            repeat(50) {
                if (physical(android.net.NetworkCapabilities.TRANSPORT_WIFI)) Thread.sleep(200)
            }
            assertFalse(physical(android.net.NetworkCapabilities.TRANSPORT_WIFI))
            assertTrue("Cellular network unavailable", physical(android.net.NetworkCapabilities.TRANSPORT_CELLULAR))
            assertTrue(awaitRequest().contains(marker))
        } finally {
            for (command in listOf("svc wifi enable", "cmd wifi connect-network AndroidWifi open")) {
                instrumentation.uiAutomation.executeShellCommand(command).use {
                    android.os.ParcelFileDescriptor.AutoCloseInputStream(it).readBytes()
                }
            }
        }
        repeat(150) {
            if (!physical(android.net.NetworkCapabilities.TRANSPORT_WIFI)) Thread.sleep(200)
        }
        assertTrue(physical(android.net.NetworkCapabilities.TRANSPORT_WIFI))
        assertTrue(awaitRequest().contains(marker))
    }

    @Test fun refusedProtectionStopsRuntimeBeforeVPN() {
        XraySocketProtector(VpnService(), protectFd = { false }).use { protector ->
            val builder = ProcessBuilder(File(context.applicationInfo.nativeLibraryDir, "libxray.so").path, "version")
            builder.environment()["FLUTTER_VLESS_PROTECT_SOCKET"] = protector.socketName
            val process = builder.redirectErrorStream(true).start()
            try {
                assertTrue(process.waitFor(5, TimeUnit.SECONDS))
                assertNotEquals(0, process.exitValue())
                assertFalse(protector.awaitVerified())
            } finally { process.destroy() }
        }
    }

    @Test fun physicalNetworkResolverControl() {
        org.junit.Assume.assumeTrue(arguments.getString("checkPhysicalDns") == "true")
        val manager = context.getSystemService(android.net.ConnectivityManager::class.java)
        val network = manager.allNetworks.first {
            val caps = manager.getNetworkCapabilities(it)
            caps?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) == true &&
                !caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)
        }
        assertTrue(network.getAllByName("example.com").isNotEmpty())
        val query = byteArrayOf(0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
            7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1)
        val answer = XrayPhysicalDns.query(network, query)
        assertEquals(0, answer[3].toInt() and 15)
        assertTrue(answer[7].toInt() > 0)
    }

    /** Keeps the native service available for a manual browser acceptance pass. */
    @Test fun browserRoutingSession() {
        val name = arguments.getString("browserProfile")
        org.junit.Assume.assumeTrue(name != null)
        val done = File(context.filesDir, "browser-session-stop")
        done.delete()
        start(XrayConfig(V2RAY_FULL_JSON_CONFIG = File(context.filesDir, name!!).readText(), REMARK = "Browser routing acceptance"))
        val deadline = System.nanoTime() + TimeUnit.MINUTES.toNanos(20)
        while (!done.exists() && System.nanoTime() < deadline) Thread.sleep(500)
        assertTrue("Browser acceptance session timed out", done.exists())
    }

    /** Optional private fixture, supplied only in the test app's files directory. */
    @Test fun suppliedDomainEndpointCarriesHostTraffic() {
        val name = arguments.getString("profile")
        org.junit.Assume.assumeTrue(name != null)
        val raw = File(context.filesDir, name!!).readText()
        val profile = XrayConfig(V2RAY_FULL_JSON_CONFIG = raw, REMARK = "Private native fixture")
        start(profile)
        val manager = context.getSystemService(android.net.ConnectivityManager::class.java)
        var ready = false
        repeat(50) {
            if (manager.getNetworkCapabilities(manager.activeNetwork)?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) == true) ready = true
            if (!ready) Thread.sleep(200)
        }
        assertTrue("Host UID did not join VPN", ready)
        var result = ""
        repeat(3) {
            try {
                result = SSLSocketFactory.getDefault().createSocket().use { socket ->
                    socket.soTimeout = 10000
                    socket.connect(InetSocketAddress("1.1.1.1", 443), 10000)
                    socket.getOutputStream().write("GET /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n".toByteArray())
                    socket.getInputStream().bufferedReader().readText()
                }
                if (result.contains("\nip=")) {
                    println("Native tunnel egress " + result.lineSequence().first { it.startsWith("ip=") })
                    return
                }
            } catch (_: Exception) { }
            Thread.sleep(1000)
        }
        fail("No public trace response through supplied domain endpoint")
    }
}
