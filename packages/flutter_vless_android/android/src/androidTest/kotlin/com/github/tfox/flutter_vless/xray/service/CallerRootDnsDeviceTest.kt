package com.github.tfox.flutter_vless.xray.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.github.tfox.flutter_vless.xray.core.AndroidTunnelDnsPolicy
import com.github.tfox.flutter_vless.xray.core.BoundedCoreCommand
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** Ordinary production Core/TUN, with synthetic DNS and the existing HTTP fixture.
 * The public-domain control qualifies functional protected default DNS only;
 * it is not a physical-interface capture or a proof of every possible leak path. */
@RunWith(AndroidJUnit4::class)
class CallerRootDnsDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val manager = context.getSystemService(ConnectivityManager::class.java)
    private val run = UUID.randomUUID().toString().replace("-", "").take(12)
    private fun name(prefix: String) = "$prefix-$run.dns-audit.invalid"
    private fun activeVpn() = manager.getNetworkCapabilities(manager.activeNetwork)
        ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true

    private fun start(source: JSONObject, geoAssetsDirectory: String? = null) {
        assertNull("Test APK requires VPN consent", VpnService.prepare(context))
        val connecting = AtomicBoolean(false)
        val connected = CountDownLatch(1)
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                @Suppress("DEPRECATION")
                val state = intent?.getSerializableExtra("STATE") as? AppConfigs.V2RAY_STATES ?: return
                if (state == AppConfigs.V2RAY_STATES.V2RAY_CONNECTING) connecting.set(true)
                if (state == AppConfigs.V2RAY_STATES.V2RAY_CONNECTED && connecting.get()) connected.countDown()
            }
        }
        val filter = IntentFilter(AppConfigs.V2RAY_CONNECTION_INFO)
        if (Build.VERSION.SDK_INT >= 33) context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        else @Suppress("DEPRECATION") context.registerReceiver(receiver, filter)
        try {
            context.startForegroundService(Intent(context, XrayVPNService::class.java)
                .putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE)
                .putExtra("V2RAY_CONFIG", XrayConfig(V2RAY_FULL_JSON_CONFIG = source.toString(),
                    GEO_ASSETS_DIRECTORY = geoAssetsDirectory,
                    ANDROID_DNS_POLICY = "config", REMARK = "Caller DNS regression",
                    PLUGIN_OPTIONS_JSON = """{"reconnect":{"enabled":false}}""")))
            assertTrue("Fresh production session never became ready", connected.await(30, TimeUnit.SECONDS))
        } finally { context.unregisterReceiver(receiver) }
        assertTrue("Production VPN did not capture traffic", activeVpn())
        assertEquals(listOf(AndroidTunnelDnsPolicy.VIRTUAL_SERVER),
            manager.getLinkProperties(manager.activeNetwork)?.dnsServers?.map { it.hostAddress })
        val runtime = context.noBackupFilesDir.listFiles().orEmpty().single {
            it.name.startsWith("xray-") && it.extension == "json"
        }.readText().let(::JSONObject)
        assertEquals("Caller root DNS presence changed", source.has("dns"), runtime.has("dns"))
        if (source.has("dns")) assertEquals(source.getJSONObject("dns").toString(), runtime.getJSONObject("dns").toString())
        for (name in listOf("api", "stats", "policy")) if (source.has(name)) {
            assertTrue("Caller $name root disappeared", runtime.has(name))
            assertEquals("Caller $name subtree changed", source.get(name).toString(), runtime.get(name).toString())
        }
    }

    @After fun stop() {
        if (!activeVpn() && !XrayVPNService.hasAcceptedSession()) return
        context.startService(Intent(context, XrayVPNService::class.java)
            .putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE))
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while ((activeVpn() || XrayVPNService.hasAcceptedSession()) && System.nanoTime() < deadline) Thread.sleep(50)
        assertFalse("Stop retained VPN capture", activeVpn())
        assertFalse("Stop retained session authorization", XrayVPNService.hasAcceptedSession())
    }

    private fun baseSource(blockDefault: Boolean = false): JSONObject {
        val outbounds = JSONArray()
        if (blockDefault) outbounds.put(JSONObject().put("tag", "blocked-default").put("protocol", "blackhole"))
        for (tag in listOf("caller-direct", "caller-root-route", "caller-domain-route"))
            outbounds.put(JSONObject().put("tag", tag).put("protocol", "freedom"))
        return JSONObject().put("inbounds", JSONArray()).put("outbounds", outbounds)
            .put("routing", JSONObject().put("rules", JSONArray()
                .put(JSONObject().put("type", "field").put("inboundTag", JSONArray().put("caller-root-dns"))
                    .put("outboundTag", "caller-root-route"))
                .put(JSONObject().put("type", "field").put("inboundTag", JSONArray().put("caller-per-domain"))
                    .put("outboundTag", "caller-domain-route"))
                .put(JSONObject().put("type", "field").put("ip", JSONArray().put("10.0.2.2/32"))
                    .put("network", "tcp").put("outboundTag", "caller-direct"))))
    }

    private fun question(name: String, type: Int = 1): ByteArray = ByteArrayOutputStream().also { bytes ->
        DataOutputStream(bytes).use { out ->
            out.writeShort(0x446e); out.writeShort(0x100); out.writeShort(1); out.writeShort(0); out.writeInt(0)
            name.split('.').forEach { out.writeByte(it.length); out.write(it.toByteArray(Charsets.US_ASCII)) }
            out.writeByte(0); out.writeShort(type); out.writeShort(1)
        }
    }.toByteArray()

    private fun query(name: String, tcp: Boolean, type: Int = 1): ByteArray {
        val request = question(name, type)
        return if (tcp) Socket().use { socket ->
            socket.soTimeout = 5000
            socket.connect(InetSocketAddress(AndroidTunnelDnsPolicy.VIRTUAL_SERVER, 53), 3000)
            DataOutputStream(socket.getOutputStream()).apply { writeShort(request.size); write(request); flush() }
            DataInputStream(socket.getInputStream()).let { input ->
                val size = input.readUnsignedShort(); require(size in 12..4096)
                ByteArray(size).also(input::readFully)
            }
        } else DatagramSocket().use { socket ->
            socket.soTimeout = 5000
            socket.send(DatagramPacket(request, request.size, InetAddress.getByName(AndroidTunnelDnsPolicy.VIRTUAL_SERVER), 53))
            val response = DatagramPacket(ByteArray(4096), 4096)
            socket.receive(response); response.data.copyOf(response.length)
        }
    }

    private fun assertA(response: ByteArray, controlled: Boolean = true) {
        assertTrue("DNS response too short", response.size >= 16)
        assertEquals(0x44, response[0].toInt() and 255); assertEquals(0x6e, response[1].toInt() and 255)
        assertEquals(0, response[3].toInt() and 15)
        assertTrue("DNS returned no A answer", ((response[6].toInt() and 255) shl 8 or (response[7].toInt() and 255)) > 0)
        if (controlled) assertArrayEquals(byteArrayOf(10, 0, 2, 2), response.takeLast(4).toByteArray())
    }

    private fun http(host: String = "10.0.2.2") = Socket().use { socket ->
        socket.soTimeout = 3000
        socket.connect(InetSocketAddress(host, 18083), 3000)
        socket.getOutputStream().write("GET /?caller-dns=$run HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n".toByteArray())
        val bytes = ByteArrayOutputStream(); val chunk = ByteArray(1024)
        while (bytes.size() < 8192) {
            val size = socket.getInputStream().read(chunk, 0, minOf(chunk.size, 8192 - bytes.size()))
            if (size < 0) break
            bytes.write(chunk, 0, size)
        }
        assertTrue("No real HTTP fixture bytes through TUN", bytes.toString("UTF-8").contains("flutter-vless-direct-bypass"))
    }

    @Test fun callerHostsPerDomainAndDnsTagsResolveViaProductionTun() {
        // A VPN also carries Android background DNS. Prove that declining one
        // unrelated name does not kill this same fixture worker before testing
        // Core/TUN. This separate listener is never counted as VPN evidence.
        DnsFixture().use { fixture ->
            val owned = name("fixture-control")
            val registered = "asset-control-$run.invalid"
            fixture.allowOwnedName(registered)
            for ((qname, expectedCode) in listOf("unrelated.fixture.invalid" to 5, owned to 0, registered to 0)) {
                Socket().use { socket ->
                    socket.soTimeout = 2000
                    socket.connect(InetSocketAddress("127.0.0.1", fixture.port), 2000)
                    val request = question(qname)
                    DataOutputStream(socket.getOutputStream()).apply { writeShort(request.size); write(request); flush() }
                    val input = DataInputStream(socket.getInputStream())
                    val size = input.readUnsignedShort(); require(size in 12..4096)
                    val reply = ByteArray(size).also(input::readFully)
                    assertEquals("Fixture admission returned wrong DNS status", expectedCode, reply[3].toInt() and 15)
                    if (expectedCode == 0) assertA(reply)
                    else assertEquals("Declined fixture query had an answer", 0, reply[7].toInt() and 255)
                }
            }
            assertEquals(listOf(owned to 1, registered to 1), fixture.observations())
        }
        DnsFixture().use { general -> DnsFixture().use { perDomain ->
            val caller = name("caller"); val hosts = name("hosts")
            val assetRoot = File(context.cacheDir, "caller-assets-$run")
            assertTrue("Owned asset fixture directory is unavailable", assetRoot.mkdir())
            val root = JSONObject().put("tag", "caller-root-dns").put("queryStrategy", "UseIPv4")
                .put("disableCache", true).put("hosts", JSONObject().put(hosts, "10.0.2.2"))
                .put("servers", JSONArray().put("tcp://127.0.0.1:${general.port}")
                    .put(JSONObject().put("address", "tcp://127.0.0.1:${perDomain.port}")
                        .put("domains", JSONArray().put("full:$caller")).put("skipFallback", true)
                        .put("tag", "caller-per-domain").put("queryStrategy", "UseIPv4")))
            try {
                val asset = InstrumentationRegistry.getInstrumentation().context.assets.open("asset-files.json")
                    .bufferedReader().use { JSONObject(it.readText()) }
                val bytes = Base64.decode(asset.getString("base64"), Base64.DEFAULT)
                val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
                    .joinToString("") { "%02x".format(it.toInt() and 255) }
                assertEquals("Shared asset fixture changed", asset.getString("sha256"), digest)
                val assetFile = File(assetRoot, asset.getString("file"))
                assetFile.writeBytes(bytes)
                val assetDomain = asset.getString("domain")
                general.allowOwnedName(assetDomain); perDomain.allowOwnedName(assetDomain)
                root.getJSONObject("hosts").put(assetDomain, "10.0.2.2")
                val source = baseSource(blockDefault = true).put("dns", root)
                val apiAddress = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1")).use {
                    "127.0.0.1:${it.localPort}"
                }
                source.put("api", JSONObject().put("tag", "caller-api").put("listen", apiAddress)
                    .put("services", JSONArray().put("StatsService").put("HandlerService")))
                    .put("stats", JSONObject())
                    .put("policy", JSONObject().put("system", JSONObject()
                        .put("statsInboundUplink", false).put("statsInboundDownlink", false)
                        .put("statsOutboundUplink", false).put("statsOutboundDownlink", false)))
                val routing = source.getJSONObject("routing")
                val originalRules = routing.getJSONArray("rules")
                val rules = JSONArray()
                    .put(JSONObject().put("type", "field").put("domain", JSONArray()
                        .put("ext:${asset.getString("file")}:${asset.getString("code")}"))
                        .put("outboundTag", "caller-direct"))
                    .put(JSONObject().put("type", "field").put("domain", JSONArray().put("full:$hosts"))
                        .put("outboundTag", "caller-direct"))
                    // A generic numeric fixture route must not hide a missing
                    // domain match. HTTP needs one of the two rules above.
                    .put(JSONObject().put("type", "field").put("network", "tcp").put("port", "18083")
                        .put("outboundTag", "blocked-default"))
                for (index in 0 until originalRules.length()) rules.put(originalRules.get(index))
                routing.put("rules", rules)
                start(source, assetRoot.absolutePath)
                val udp = name("udp"); val tcp = name("tcp"); val system = name("system")
                assertA(query(udp, false)); assertA(query(tcp, true)); assertA(query(caller, false))
                assertTrue(InetAddress.getAllByName(system).any { it.hostAddress == "10.0.2.2" })
                assertTrue(InetAddress.getAllByName(hosts).any { it.hostAddress == "10.0.2.2" })
                http(hosts)
                http(assetDomain)
                assertEquals("Explicit root received bundled assets", listOf(assetFile.name), assetRoot.listFiles()!!.map { it.name })
                val ipv6 = query(name("ipv6"), false, 28)
                assertEquals(0, ipv6[3].toInt() and 15); assertEquals(0, ipv6[7].toInt() and 255)
                val nonAddress = query(name("txt"), true, 16)
                assertEquals(5, nonAddress[3].toInt() and 15)
                val generalSeen = general.observations(); val domainSeen = perDomain.observations()
                for (expected in listOf(udp, tcp, system)) assertTrue("Missing caller-root-tag DNS bytes", expected to 1 in generalSeen)
                assertTrue("Missing per-server-tag DNS bytes", caller to 1 in domainSeen)
                assertFalse("Per-domain query escaped to fallback", generalSeen.any { it.first == caller })
                assertFalse("Static hosts escaped to a DNS server", (generalSeen + domainSeen).any { it.first == hosts })
                assertFalse("Asset domain static host escaped to a DNS server", (generalSeen + domainSeen).any { it.first == assetDomain })
                assertTrue("IPv4 policy issued another record type", (generalSeen + domainSeen).all { it.second == 1 })
                val command = ProcessBuilder(File(context.applicationInfo.nativeLibraryDir, "libxray.so").absolutePath,
                    "api", "statsquery", "--server=$apiAddress").redirectErrorStream(true).start()
                val output = BoundedCoreCommand.capture(command)?.toString(Charsets.UTF_8)
                assertNotNull("Caller StatsService did not respond", output)
                val counters = JSONObject(output!!).optJSONArray("stat")
                assertTrue("Caller disabled counters were enabled", counters == null || counters.length() == 0)
            } finally {
                stop()
                assertTrue("Owned asset fixture directory survived Stop", assetRoot.deleteRecursively())
            }
        } }
    }

    @Test fun missingAndLocalhostDnsUseProtectedDefaultAndStopCleanly() {
        for (explicit in listOf(false, true)) {
            val source = baseSource()
            if (explicit) source.put("dns", JSONObject().put("servers", JSONArray().put("localhost")).put("queryStrategy", "UseIPv4"))
            try {
                start(source)
                assertA(query("example.com", false), controlled = false)
                assertA(query("www.iana.org", true), controlled = false)
                assertTrue("System resolver default returned no IPv4", InetAddress.getAllByName("example.com").any { it.address.size == 4 })
                http()
            } finally { stop() }
            http() // Stop also restores ordinary emulator HTTP connectivity.
        }
    }

    private inner class DnsFixture : Closeable {
        private val listener = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))
        val port = listener.localPort
        private val lock = Any()
        private var closed = false
        private var active: Socket? = null
        private val seen = mutableListOf<Pair<String, Int>>()
        private val ownedNames = mutableSetOf<String>()
        private val failure = AtomicReference<Throwable?>()
        private val worker = Thread({
            try {
                while (true) {
                    val client = listener.accept()
                    val admitted = synchronized(lock) { if (closed) false else { active = client; true } }
                    if (!admitted) { client.close(); break }
                    try { client.use(::answer) }
                    finally { synchronized(lock) { if (active === client) active = null } }
                }
            } catch (error: Throwable) {
                if (!synchronized(lock) { closed }) failure.compareAndSet(null, error)
            }
        }, "caller-dns-fixture").apply { isDaemon = true }

        init {
            try { worker.start() }
            catch (error: Throwable) {
                try { listener.close() } catch (cleanup: Throwable) { error.addSuppressed(cleanup) }
                throw error
            }
        }

        private fun answer(socket: Socket) {
            socket.soTimeout = 2000
            val input = DataInputStream(socket.getInputStream())
            val size = input.readUnsignedShort(); require(size in 17..4096)
            val question = ByteArray(size).also(input::readFully)
            var offset = 12; val labels = mutableListOf<String>()
            while (true) {
                val count = question[offset++].toInt() and 255
                if (count == 0) break
                require(count in 1..63 && offset + count <= size)
                labels.add(String(question, offset, count, Charsets.US_ASCII)); offset += count
            }
            require(offset + 4 <= size)
            val type = ((question[offset].toInt() and 255) shl 8) or (question[offset + 1].toInt() and 255)
            val qname = labels.joinToString(".")
            val controlled = synchronized(lock) {
                val canonical = qname.lowercase(java.util.Locale.ROOT)
                (qname.endsWith("-$run.dns-audit.invalid", ignoreCase = true) || canonical in ownedNames)
                    .also { if (it) seen.add(canonical to type) }
            }
            val reply = ByteArrayOutputStream()
            DataOutputStream(reply).use { output ->
                // REFUSED is an owned reply, never a resolver fallback or a
                // reason to terminate the worker. Do not retain foreign names.
                output.write(question, 0, 2); output.writeShort(if (controlled) 0x8180 else 0x8185); output.writeShort(1)
                output.writeShort(if (controlled && type == 1) 1 else 0); output.writeInt(0)
                output.write(question, 12, offset + 4 - 12)
                if (controlled && type == 1) {
                    output.writeShort(0xc00c); output.writeShort(1); output.writeShort(1)
                    output.writeInt(0); output.writeShort(4); output.write(byteArrayOf(10, 0, 2, 2))
                }
            }
            DataOutputStream(socket.getOutputStream()).apply { writeShort(reply.size()); write(reply.toByteArray()); flush() }
        }

        fun observations(): List<Pair<String, Int>> = synchronized(lock) { seen.toList() }

        fun allowOwnedName(name: String) = synchronized(lock) {
            require(!closed && name.endsWith(".invalid", ignoreCase = true)) { "Expected an owned synthetic fixture name" }
            ownedNames.add(name.lowercase(java.util.Locale.ROOT))
        }

        override fun close() {
            val socket = synchronized(lock) { closed = true; active }
            var error: Throwable? = null
            for (action in listOf<() -> Unit>({ listener.close() }, { socket?.close() }, { worker.join(2500) })) {
                try { action() } catch (caught: Throwable) { if (error == null) error = caught else error.addSuppressed(caught) }
            }
            if (worker.isAlive) {
                val caught = AssertionError("Owned DNS fixture did not terminate")
                if (error == null) error = caught else error.addSuppressed(caught)
            }
            failure.get()?.let { if (error == null) error = it else error!!.addSuppressed(it) }
            error?.let { throw it }
        }
    }
}
