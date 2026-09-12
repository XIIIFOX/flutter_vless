package com.github.tfox.flutter_vless.xray.service

import android.content.Intent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.IntentFilter
import android.os.Build
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
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
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean

/** Requires tool/android_dns_fixture.py on emulator host loopback. Positive answers
 * are controlled and unique; fixture observations prove their TCP proxy route.
 * A separate physical-interface capture is needed to rule out all duplicate leaks. */
@RunWith(AndroidJUnit4::class)
class ProtectedSystemDnsTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val manager = context.getSystemService(ConnectivityManager::class.java)
    private val run = UUID.randomUUID().toString().replace("-", "").take(12)
    private fun activeVpn() = manager.getNetworkCapabilities(manager.activeNetwork)
        ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true

    private fun start(protocol: String) {
        assertNull("Authorize ACTIVATE_VPN for test APK", VpnService.prepare(context))
        val port = mapOf("http" to 18280, "socks" to 18281, "vless" to 18282).getValue(protocol)
        val settings = JSONObject().put("address", "10.0.2.2").put("port", port)
        if (protocol == "vless") settings.put("id", "2bddfbd9-7d82-4698-9d39-1b8136b856de").put("encryption", "none")
        val json = JSONObject().put("inbounds", JSONArray())
            .put("outbounds", JSONArray().put(JSONObject().put("tag", "proxy").put("protocol", protocol).put("settings", settings))
                .put(JSONObject().put("tag", "direct").put("protocol", "freedom")))
            .put("routing", JSONObject().put("rules", JSONArray()
                .put(JSONObject().put("type", "field").put("network", "udp").put("outboundTag", "direct"))))
        val connecting = AtomicBoolean(false)
        val connected = CountDownLatch(1)
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                @Suppress("DEPRECATION")
                val state = intent?.getSerializableExtra("STATE") as? AppConfigs.V2RAY_STATES ?: return
                if (state == AppConfigs.V2RAY_STATES.V2RAY_CONNECTING) connecting.set(true)
                if (state == AppConfigs.V2RAY_STATES.V2RAY_CONNECTED && connecting.get()) connected.countDown()
                println("DNS_AUDIT_STATE run=$run epochMs=${System.currentTimeMillis()} state=$state")
            }
        }
        if (Build.VERSION.SDK_INT >= 33) context.registerReceiver(receiver, IntentFilter(AppConfigs.V2RAY_CONNECTION_INFO), Context.RECEIVER_NOT_EXPORTED)
        else @Suppress("DEPRECATION") context.registerReceiver(receiver, IntentFilter(AppConfigs.V2RAY_CONNECTION_INFO))
        try {
            context.startForegroundService(Intent(context, XrayVPNService::class.java)
                .putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE)
                .putExtra("V2RAY_CONFIG", XrayConfig(V2RAY_FULL_JSON_CONFIG = json.toString(),
                    REMARK = "Protected DNS $protocol regression", ANDROID_DNS_POLICY = "proxy")))
            // Network announcement precedes completion of Android's UID routing setup.
            // A new CONNECTING -> CONNECTED transition includes actual captured HTTP bytes.
            assertTrue("New VPN session never reached authenticated captured-path readiness", connected.await(30, TimeUnit.SECONDS))
        } finally { context.unregisterReceiver(receiver) }
        assertTrue("VPN capture did not start", activeVpn())
        val dns = manager.getLinkProperties(manager.activeNetwork)?.dnsServers?.map { it.hostAddress }
        assertEquals(listOf("198.18.0.2"), dns)
        fixtureEvents("ready") // a second real host-UID TUN request; host-clock lifecycle marker
    }

    @After fun stop() {
        if (activeVpn()) runCatching { fixtureEvents("stop-requested") }
        context.startService(Intent(context, XrayVPNService::class.java)
            .putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE))
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (activeVpn() && System.nanoTime() < deadline) Thread.sleep(100)
    }

    private fun name(prefix: String, protocol: String) = "$prefix-$protocol-$run.dns-audit.invalid"

    private fun question(name: String): ByteArray {
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { out ->
            out.writeShort(0x6d42); out.writeShort(0x0100); out.writeShort(1); out.writeShort(0); out.writeInt(0)
            name.split('.').forEach { label -> out.writeByte(label.length); out.write(label.toByteArray(Charsets.US_ASCII)) }
            out.writeByte(0); out.writeShort(1); out.writeShort(1)
        }
        return bytes.toByteArray()
    }

    private fun query(name: String, tcp: Boolean): ByteArray {
        val request = question(name)
        return if (tcp) Socket().use { socket ->
            socket.soTimeout = 3000
            socket.connect(InetSocketAddress("198.18.0.2", 53), 3000)
            DataOutputStream(socket.getOutputStream()).apply { writeShort(request.size); write(request); flush() }
            DataInputStream(socket.getInputStream()).let { input -> ByteArray(input.readUnsignedShort()).also { input.readFully(it) } }
        } else DatagramSocket().use { socket ->
            socket.soTimeout = 3000
            socket.send(DatagramPacket(request, request.size, InetAddress.getByName("198.18.0.2"), 53))
            val response = DatagramPacket(ByteArray(4096), 4096)
            socket.receive(response)
            response.data.copyOf(response.length)
        }
    }

    private fun assertAnswer(response: ByteArray) {
        assertTrue("DNS reply too short", response.size >= 16)
        assertEquals(0x6d, response[0].toInt() and 255)
        assertEquals(0x42, response[1].toInt() and 255)
        assertEquals(0, response[3].toInt() and 15)
        assertTrue("No controlled DNS answer", (response[7].toInt() and 255) > 0)
        assertArrayEquals(byteArrayOf(203.toByte(), 0, 113, 42), response.takeLast(4).toByteArray())
    }

    private fun awaitAnswer(name: String, tcp: Boolean) {
        var last: Exception? = null
        repeat(8) {
            try { assertAnswer(query(name, tcp)); return } catch (error: Exception) { last = error }
            Thread.sleep(250)
        }
        throw AssertionError("No controlled DNS response through proxy", last)
    }

    private fun fixtureEvents(phase: String? = null): JSONArray = Socket().use { socket ->
        socket.soTimeout = 3000
        socket.connect(InetSocketAddress("10.0.2.2", 18283), 3000)
        val path = phase?.let { "/?phase=$it&run=$run" } ?: "/"
        socket.getOutputStream().write("GET $path HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\n\r\n".toByteArray())
        JSONArray(socket.getInputStream().bufferedReader().readText().substringAfter("\r\n\r\n"))
    }

    private fun exercise(protocol: String) {
        start(protocol)
        val udp = name("udp", protocol)
        val tcp = name("tcp", protocol)
        val system = name("system", protocol)
        awaitAnswer(udp, false)
        awaitAnswer(tcp, true)
        assertTrue("System resolver did not use virtual VPN DNS", InetAddress.getAllByName(system).any { it.hostAddress == "203.0.113.42" })
        val events = fixtureEvents()
        for (qname in listOf(udp, tcp, system)) {
            assertTrue("Missing selected-proxy TCP observation for $qname", (0 until events.length()).any {
                val event = events.getJSONObject(it)
                event.optString("qname") == qname && event.optString("transport") == protocol && event.optString("network") == "tcp"
            })
        }
        // A fresh failing name cannot be answered by cached system DNS or the fixture.
        val dropped = name("drop", protocol)
        assertFalse("Unavailable proxy DNS unexpectedly succeeded", runCatching { assertAnswer(query(dropped, false)); true }.getOrDefault(false))
        assertTrue("DNS failure removed VPN capture", activeVpn())
        awaitAnswer(name("after-failure", protocol), false)
    }

    @Test fun httpProxyCarriesSystemUdpAndTcpDnsAheadOfUdpDirect() = exercise("http")
    @Test fun socksProxyCarriesSystemUdpAndTcpDnsAheadOfUdpDirect() = exercise("socks")
    @Test fun vlessProxyCarriesSystemUdpAndTcpDnsAheadOfUdpDirect() = exercise("vless")

    @Test fun systemDnsRemainsProxiedAfterNativeWorkerRecovery() {
        start("socks")
        awaitAnswer(name("before-recovery", "socks"), false)
        fixtureEvents("recovery-start")
        val vpn = manager.activeNetwork
        val kill = ProcessBuilder("pkill", "-9", "-x", "libxray.so").start()
        assertTrue(kill.waitFor(5, TimeUnit.SECONDS))
        assertEquals("Failed to terminate the same-UID native worker", 0, kill.exitValue())
        repeat(12) { assertEquals("Recovery replaced or removed VPN capture", vpn, manager.activeNetwork); Thread.sleep(100) }
        awaitAnswer(name("after-recovery", "socks"), false)
        fixtureEvents("recovery-ready")
        assertEquals(vpn, manager.activeNetwork)
        val events = fixtureEvents()
        assertTrue((0 until events.length()).any {
            events.getJSONObject(it).optString("qname") == name("after-recovery", "socks") && events.getJSONObject(it).optString("transport") == "socks"
        })
    }
}
