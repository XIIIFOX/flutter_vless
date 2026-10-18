package com.github.tfox.flutter_vless.xray.service

import android.content.Intent
import android.net.ConnectivityManager
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.Network
import android.net.NetworkCapabilities
import android.net.RouteInfo
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.ResultReceiver
import android.system.Os
import android.system.OsConstants
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Explicit opt-in actual IPv4 TUN. No ordinary service, SOCKS proxy setting, or host network changes. */
@RunWith(AndroidJUnit4::class)
class NativePreviewVpnDeviceTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val manager = context.getSystemService(ConnectivityManager::class.java)
    private val run = UUID.randomUUID().toString().replace("-", "").take(12)
    private val suffix = "-$run.dns-audit.invalid"
    private val loopbackHost = InetAddress.getByAddress(byteArrayOf(10, 0, 2, 2))
    private val vip = InetAddress.getByAddress(byteArrayOf(198.toByte(), 18, 0, 53))
    private lateinit var physical: Network
    private var started = false
    private var browserLaunched = false
    private var wifiChanged = false
    private var wifiWasEnabled = false

    private fun shell(command: String): String = instrumentation.uiAutomation.executeShellCommand(command).use {
        ParcelFileDescriptor.AutoCloseInputStream(it).use { input ->
            val bytes = input.readNBytes(32769)
            check(bytes.size <= 32768) { "Bounded emulator command output exceeded its limit" }
            String(bytes, Charsets.UTF_8).trim()
        }
    }
    private fun until(ms: Long) = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(ms)
    private fun remaining(end: Long) = (end - System.nanoTime()).also { check(it > 0) { "Preview acceptance deadline exceeded" } }
    private fun await(end: Long = until(15000), description: String, predicate: () -> Boolean) {
        while (System.nanoTime() < end) { if (predicate()) return; Thread.sleep(25) }
        error("Preview did not reach $description before its deadline")
    }
    private fun captured(): Boolean = manager.getNetworkCapabilities(manager.activeNetwork)
        ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    private fun settledWifiDefault(): Network {
        var observed: Pair<Network, String>? = null
        var since = 0L
        var settled: Network? = null
        // Only settle the fixture baseline. Never retry START or a protected
        // socket/query, and never repair a network change inside a test case.
        await(until(10000), "stable physical Wi-Fi default") {
            val network = manager.activeNetwork
            val caps = network?.let(manager::getNetworkCapabilities)
            val links = network?.let(manager::getLinkProperties)
            val routes = links?.routes.orEmpty().filter {
                it.type == RouteInfo.RTN_UNICAST && it.destination.address is Inet4Address && it.matches(loopbackHost)
            }
            if (network == null || caps == null || links == null ||
                !caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) || caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ||
                links.linkAddresses.none { it.address is Inet4Address } || routes.isEmpty()) {
                observed = null
                false
            } else {
                val key = network to (links.linkAddresses.map { it.toString() }.sorted().toString() +
                    routes.map { it.toString() }.sorted().toString())
                if (observed != key) { observed = key; since = System.nanoTime() }
                if (System.nanoTime() - since >= TimeUnit.MILLISECONDS.toNanos(250)) {
                    settled = network; true
                } else false
            }
        }
        return requireNotNull(settled)
    }

    @Before fun dedicatedEmulatorOnly() {
        check(Build.HARDWARE in setOf("ranchu", "goldfish"))
        assertNull("Test VPN consent must be prepared by the dedicated harness", VpnService.prepare(context))
        check(!captured()) { "Another VPN is active on the disposable emulator" }
        assertEquals("null", shell("settings --user 0 get secure always_on_vpn_app"))
        wifiWasEnabled = shell("settings get global wifi_on") == "1"
        check(wifiWasEnabled) { "Dedicated preview fixture requires its restored Wi-Fi baseline" }
        physical = settledWifiDefault()
        assertTrue("A previous owned preview directory survived", ownedDirectories().isEmpty())
    }
    private fun ownedDirectories() = context.noBackupFilesDir.listFiles().orEmpty().filter { it.name.startsWith("native-vpn-") }

    private data class Reply(val code: Int, val state: Bundle)
    private fun command(action: String, end: Long = until(20000), fill: (Intent) -> Unit = {}): Reply {
        val response = ArrayBlockingQueue<Reply>(1)
        val receiver = object : ResultReceiver(Handler(Looper.getMainLooper())) {
            override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
                response.offer(Reply(resultCode, requireNotNull(resultData)))
            }
        }
        val intent = Intent(context, NativePreviewVpnService::class.java).setAction(action).putExtra("receiver", receiver)
        fill(intent)
        context.startForegroundService(intent)
        return response.poll(remaining(end), TimeUnit.NANOSECONDS) ?: error("Preview service did not reply: $action")
    }
    private fun state(end: Long = until(20000)) = command(NativePreviewVpnService.STATE, end).state
    private fun source(): ByteArray {
        val hosts = JSONObject()
        listOf("static-udp", "static-tcp", "static-system", "static-browser").forEach { hosts.put(it + suffix, "10.0.2.2") }
        val domains = JSONArray()
        listOf("caller-udp", "caller-tcp", "caller-system", "caller-browser").forEach { domains.put("full:" + it + suffix) }
        return JSONObject().put("inbounds", JSONArray())
            .put("outbounds", JSONArray().put(JSONObject().put("tag", "direct").put("protocol", "freedom")
                .put("settings", JSONObject().put("domainStrategy", "UseIPv4")))
                .put(JSONObject().put("tag", "physical").put("protocol", "freedom")))
            .put("dns", JSONObject().put("queryStrategy", "UseIPv4").put("hosts", hosts)
                .put("servers", JSONArray().put(JSONObject().put("address", "tcp://10.0.2.2:18285")
                    .put("domains", domains).put("skipFallback", true)).put("localhost")))
            .toString().toByteArray(Charsets.UTF_8)
    }
    private fun start(bytes: ByteArray = source(), browser: Boolean = false): Reply {
        started = true // Even a timed-out start must be followed by an owned Stop.
        val args = InstrumentationRegistry.getArguments()
        return command(NativePreviewVpnService.START) { intent ->
            intent.putExtra("source", bytes).putExtra("sourceSha256", NativePreviewVpnInput.digest(bytes))
                .putExtra("testPackage", instrumentation.context.packageName)
                .putExtra("previewSha256", requireNotNull(args.getString("previewSha256")))
                .putExtra("forwarderSha256", requireNotNull(args.getString("forwarderSha256")))
                .putExtra("resolver", "10.0.2.2:18284").putExtra("egressIndex", 1).putExtra("includeBrowser", browser)
        }.also { if (it.code == 0) assertEquals("Start changed the fixture baseline", physical.networkHandle, it.state.getLong("networkHandle")) }
    }
    private fun running(value: Bundle, bytes: ByteArray) {
        assertEquals("RUNNING", value.getString("state")); assertTrue(value.getBoolean("coreAlive"))
        assertTrue(value.getBoolean("forwarderAlive")); assertTrue(value.getBoolean("tunOwned"))
        assertTrue(value.getBoolean("authorized")); assertTrue(value.getBoolean("generationCurrent"))
        assertFalse(value.getBoolean("hostQualified")); assertFalse(value.getBoolean("countersAvailable"))
        assertEquals(NativePreviewVpnInput.digest(bytes), value.getString("sourceDigest")); assertTrue(captured())
    }
    private fun status(end: Long = until(4000)): JSONObject {
        val timeout = minOf(1000, TimeUnit.NANOSECONDS.toMillis(remaining(end)).toInt().coerceAtLeast(1))
        return physical.socketFactory.createSocket().use { socket ->
            socket.connect(InetSocketAddress(loopbackHost, 18283), timeout); socket.soTimeout = timeout
            socket.getOutputStream().write("GET /native-preview?run=$run HTTP/1.1\r\nHost: 10.0.2.2\r\nConnection: close\r\n\r\n".toByteArray())
            val bytes = socket.getInputStream().readNBytes(65537); check(bytes.size <= 65536)
            JSONObject(String(bytes, Charsets.UTF_8).substringAfter("\r\n\r\n"))
        }
    }
    private fun queried(value: JSONObject, name: String, transport: String? = null): Boolean {
        val events = value.getJSONArray("queries")
        return (0 until events.length()).map(events::getJSONObject).any {
            it.optString("event") == "dns" && it.optString("qname") == name &&
                (transport == null || it.optString("transport") == transport)
        }
    }
    private fun question(name: String, id: Int = 0x71ab): ByteArray = ByteArrayOutputStream().also { bytes ->
        DataOutputStream(bytes).use { out ->
            out.writeShort(id); out.writeShort(0x100); out.writeShort(1); out.writeShort(0); out.writeShort(0); out.writeShort(0)
            name.split('.').forEach { label -> val encoded = label.toByteArray(Charsets.US_ASCII); out.writeByte(encoded.size); out.write(encoded) }
            out.writeByte(0); out.writeShort(1); out.writeShort(1)
        }
    }.toByteArray()
    private fun answer(bytes: ByteArray) {
        assertTrue("DNS response is too short", bytes.size >= 16)
        assertEquals(0x71, bytes[0].toInt() and 255); assertEquals(0xab, bytes[1].toInt() and 255)
        assertTrue(bytes[2].toInt() and 0x80 != 0); assertEquals(0, bytes[3].toInt() and 15)
        assertTrue("DNS answer missing", ((bytes[6].toInt() and 255) shl 8) + (bytes[7].toInt() and 255) > 0)
        assertTrue("DNS did not return the controlled IPv4", bytes.takeLast(4).toByteArray().contentEquals(loopbackHost.address))
    }
    private fun dns(name: String, tcp: Boolean) {
        val query = question(name)
        val response = if (tcp) Socket().use { socket ->
            socket.connect(InetSocketAddress(vip, 53), 2000); socket.soTimeout = 4000
            DataOutputStream(socket.getOutputStream()).let { it.writeShort(query.size); it.write(query); it.flush() }
            DataInputStream(socket.getInputStream()).let { input -> ByteArray(input.readUnsignedShort()).also(input::readFully) }
        } else DatagramSocket().use { socket ->
            socket.soTimeout = 4000; socket.send(DatagramPacket(query, query.size, vip, 53))
            val packet = DatagramPacket(ByteArray(4096), 4096); socket.receive(packet)
            assertEquals(vip, packet.address); assertEquals(53, packet.port); packet.data.copyOf(packet.length)
        }
        answer(response)
    }
    private fun http(name: String, path: String = "/native-vpn-http-$run"): String = Socket().use { socket ->
        socket.connect(InetSocketAddress(name, 18083), 4000); socket.soTimeout = 4000
        socket.getOutputStream().write("GET $path HTTP/1.1\r\nHost: $name:18083\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
        val bytes = socket.getInputStream().readNBytes(8193); check(bytes.size <= 8192)
        String(bytes, Charsets.US_ASCII).also { assertTrue(it.contains("flutter-vless-direct-bypass")) }
    }
    private fun disarmed(old: Bundle, end: Long = until(8000)) {
        val response = command(NativePreviewVpnService.STOP, end)
        assertEquals(0, response.code); assertEquals("STOPPED", response.state.getString("state"))
        assertFalse(response.state.getBoolean("authorized")); assertFalse(response.state.getBoolean("tunOwned"))
        assertFalse(response.state.getBoolean("coreAlive")); assertFalse(response.state.getBoolean("forwarderAlive"))
        assertFalse(response.state.getBoolean("generationCurrent"))
        assertEquals(0, response.state.getInt("retiringOwners")); assertFalse(response.state.getBoolean("retiringChildAlive"))
        assertTrue(ownedDirectories().isEmpty()); await(end, "TUN removed") { !captured() }
        assertOldBrokerDenied(old.getString("brokerName"))
        started = false
    }
    private fun assertOldBrokerDenied(name: String?) {
        require(!name.isNullOrEmpty())
        // This is intentionally an already-revoked/closed endpoint. A refused
        // connection/EOF is valid here; live positive setup errors never pass.
        val descriptor = Os.socket(OsConstants.AF_INET, OsConstants.SOCK_DGRAM, 0)
        try {
            try {
                LocalSocket().use { socket ->
                    socket.connect(LocalSocketAddress(name, LocalSocketAddress.Namespace.ABSTRACT)); socket.soTimeout = 500
                    socket.setFileDescriptorsForSend(arrayOf(descriptor)); socket.outputStream.write('S'.code)
                    socket.setFileDescriptorsForSend(null)
                    assertNotEquals("Old generation acknowledged a new socket", 1, socket.inputStream.read())
                }
            } catch (_: java.io.IOException) { /* Only this intentionally dead endpoint may be unavailable. */ }
        } finally { Os.close(descriptor) }
    }

    @Test fun actualTunDnsDefaultCallerHostsAndSystemHttp() {
        val bytes = source(); val reply = start(bytes); assertEquals(0, reply.code); running(reply.state, bytes)
        for (tcp in listOf(false, true)) {
            val mode = if (tcp) "tcp" else "udp"
            dns("default-$mode$suffix", tcp); dns("caller-$mode$suffix", tcp); dns("static-$mode$suffix", tcp)
        }
        assertEquals(listOf("10.0.2.2"), InetAddress.getAllByName("static-system$suffix").map { it.hostAddress })
        http("default-system$suffix"); http("caller-system$suffix"); http("static-system$suffix")
        val evidence = status()
        for (mode in listOf("udp", "tcp", "system")) {
            assertTrue(queried(evidence, "default-$mode$suffix", "native-default"))
            assertTrue(queried(evidence, "caller-$mode$suffix", "native-caller"))
            assertFalse(queried(evidence, "static-$mode$suffix"))
        }
        disarmed(reply.state)
    }

    @Test fun rejectedCandidateKeepsActualAcceptedTunAndSource() {
        val bytes = source(); val initial = start(bytes); assertEquals(0, initial.code); running(initial.state, bytes)
        val epoch = initial.state.getString("epoch")
        assertEquals(1, start("{}".toByteArray()).code)
        val still = state(); running(still, bytes); assertEquals(epoch, still.getString("epoch"))
        http("default-rejected$suffix")
        assertTrue(queried(status(), "default-rejected$suffix", "native-default"))
        disarmed(still)
    }

    @Test fun exactOwnedCoreAndForwarderLossRetainsTunAndReplacesGeneration() {
        val bytes = source(); var previous = start(bytes).also { assertEquals(0, it.code) }.state
        for (child in listOf("core", "forwarder")) {
            val epoch = previous.getString("epoch"); val old = previous
            command(NativePreviewVpnService.KILL_OWNED) { it.putExtra("child", child) }
            var replacement: Bundle? = null
            await(until(20000), "$child fresh generation") {
                assertTrue("Captured protection was lost during child recovery", captured())
                state().also { replacement = it }.let { it.getString("state") == "RUNNING" && it.getString("epoch") != epoch }
            }
            previous = requireNotNull(replacement); running(previous, bytes); assertOldBrokerDenied(old.getString("brokerName"))
            http("default-$child$suffix")
            assertTrue(queried(status(), "default-$child$suffix", "native-default"))
        }
        disarmed(previous)
    }

    @Test fun actualNetworkHandoverAndStalledDnsStopRevokeOwnerBeforeNaturalTimeout() {
        check(wifiWasEnabled) { "Dedicated handover fixture requires initial emulator Wi-Fi" }
        val bytes = source(); val initial = start(bytes); assertEquals(0, initial.code); running(initial.state, bytes)
        val oldHandle = initial.state.getLong("networkHandle"); val oldEpoch = initial.state.getString("epoch")
        check(manager.getNetworkCapabilities(manager.allNetworks.first { it.networkHandle == oldHandle })
            ?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true)
        check(manager.allNetworks.any {
            val caps = manager.getNetworkCapabilities(it)
            it.networkHandle != oldHandle && caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }) { "Dedicated handover fixture requires a second cellular network" }
        wifiChanged = true; shell("svc wifi disable")
        var changed: Bundle? = null
        await(until(25000), "captured cellular generation") {
            assertTrue("TUN must remain during physical handover", captured())
            state().also { changed = it }.let { it.getString("state") == "RUNNING" && it.getLong("networkHandle") != oldHandle }
        }
        val current = requireNotNull(changed); running(current, bytes); assertNotEquals(oldEpoch, current.getString("epoch"))
        assertOldBrokerDenied(initial.state.getString("brokerName"))
        physical = manager.allNetworks.first { it.networkHandle == current.getLong("networkHandle") }
        http("default-handover$suffix"); assertTrue(queried(status(), "default-handover$suffix", "native-default"))
        Socket().use { socket ->
            socket.connect(InetSocketAddress(vip, 53), 2000); socket.soTimeout = 4000
            val deadline = until(2000) // One causal budget; Core's 4s natural DNS bound cannot satisfy this.
            val query = question("stall$suffix")
            DataOutputStream(socket.getOutputStream()).let { it.writeShort(query.size); it.write(query); it.flush() }
            await(deadline, "real stalled DNS query entered") { status(deadline).getInt("native_stall_start") > 0 }
            disarmed(current, deadline)
            await(deadline, "owned DNS transport EOF") { status(deadline).getInt("native_stall_eof") > 0 }
            assertEquals(0, status(deadline).getInt("native_stall_timeout")); remaining(deadline)
        }
        Thread.sleep(600) // Past the explicit500ms retry slot; Stop cannot resurrect it.
        assertFalse(captured()); assertTrue(ownedDirectories().isEmpty())
    }

    private fun originEvents(): JSONArray = physical.socketFactory.createSocket().use { socket ->
        socket.connect(InetSocketAddress(loopbackHost, 18083), 1000); socket.soTimeout = 1000
        socket.getOutputStream().write("GET /native-tun-events?run=$run HTTP/1.1\r\nHost: 10.0.2.2\r\nConnection: close\r\n\r\n".toByteArray())
        val bytes = socket.getInputStream().readNBytes(32769); check(bytes.size <= 32768)
        JSONArray(String(bytes, Charsets.UTF_8).substringAfter("\r\n\r\n"))
    }
    private fun visibleNodes(node: android.view.accessibility.AccessibilityNodeInfo?): List<android.view.accessibility.AccessibilityNodeInfo> {
        if (node == null) return emptyList()
        return listOf(node) + (0 until node.childCount).flatMap { visibleNodes(node.getChild(it)) }
    }
    @Test fun freshChromeSystemDnsAndOriginBytesThroughActualTun() {
        check(shell("pidof com.android.chrome").isEmpty()) { "Dedicated browser fixture refuses a pre-existing Chrome process" }
        @Suppress("DEPRECATION")
        val chrome = context.packageManager.getPackageInfo("com.android.chrome", 0)
        check(chrome.applicationInfo?.enabled == true) { "Dedicated browser fixture requires installed enabled Chrome" }
        val bytes = source(); val reply = start(bytes, browser = true); assertEquals(0, reply.code); running(reply.state, bytes)
        val host = "caller-browser$suffix"
        val uri = "http://$host:18083/native-tun?run=$run"
        val expected = "NATIVE_TUN_BROWSER_$run"
        browserLaunched = true
        context.startActivity(Intent(Intent.ACTION_VIEW, android.net.Uri.parse(uri)).setPackage("com.android.chrome")
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP))
        await(until(20000), "fresh visible Chrome marker") {
            instrumentation.uiAutomation.rootInActiveWindow?.let { root ->
                if (root.packageName?.toString() != "com.android.chrome") return@let false
                val nodes = visibleNodes(root)
                if (nodes.any { it.text?.toString()?.contains(expected) == true }) return@let true
                // Previously authorized disposable-emulator Chrome setup only;
                // no sign-in, unknown/system dialogs or account selection.
                nodes.firstOrNull { it.isEnabled && it.isClickable && it.text?.toString() in
                    setOf("Use without an account", "Accept & continue", "No thanks", "Got it") }
                    ?.performAction(android.view.accessibility.AccessibilityNodeInfo.ACTION_CLICK)
                false
            } == true
        }
        assertTrue(captured())
        assertTrue("Chrome system DNS must use the caller per-domain TCP server", queried(status(), host, "native-caller"))
        val events = originEvents()
        assertTrue("Visible page requires a matching fresh origin request", (0 until events.length()).map(events::getJSONObject).any {
            it.optString("run") == run && it.optString("host").substringBefore(':') == host &&
                it.optString("path") == "/native-tun?run=$run" && it.optString("event") == "native-tun-http"
        })
        // A resolved address becomes numeric at the managed TUN adapter. This
        // proves DNS/HTTP bytes, not domain-sniffing routing or IPv6 support.
        disarmed(reply.state)
    }

    @After fun cleanup() {
        var primary: Throwable? = null
        fun attempt(block: () -> Unit) { try { block() } catch (error: Throwable) {
            if (primary == null) primary = error else primary!!.addSuppressed(error)
        } }
        if (started) attempt {
            val stopped = command(NativePreviewVpnService.STOP)
            assertEquals(0, stopped.code); assertFalse(stopped.state.getBoolean("tunOwned")); started = false
        }
        if (browserLaunched) attempt { shell("am force-stop com.android.chrome"); browserLaunched = false }
        attempt { await(description = "final owned TUN cleanup") { !captured() }; assertTrue(ownedDirectories().isEmpty()) }
        if (wifiChanged) attempt {
            check(!captured()) { "Stop must finish before restoring fixture Wi-Fi" }
            check(wifiWasEnabled)
            shell("svc wifi enable")
            shell("cmd wifi connect-network AndroidWifi open")
            settledWifiDefault()
            wifiChanged = false
        }
        primary?.let { throw it }
    }
}
