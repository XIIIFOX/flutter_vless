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
import java.net.SocketException
import java.net.SocketTimeoutException
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
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

    private fun start(source: JSONObject, geoAssetsDirectory: String? = null): JSONObject {
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
        return runtime
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

    private fun httpResponse(host: String): String = Socket().use { socket ->
        socket.soTimeout = 3000
        socket.connect(InetSocketAddress(host, 18083), 3000)
        socket.getOutputStream().write("GET /?caller-dns=$run HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n".toByteArray())
        val bytes = ByteArrayOutputStream(); val chunk = ByteArray(1024)
        while (bytes.size() < 8192) {
            val size = socket.getInputStream().read(chunk, 0, minOf(chunk.size, 8192 - bytes.size()))
            if (size < 0) break
            bytes.write(chunk, 0, size)
        }
        bytes.toString("UTF-8")
    }

    private fun http(host: String = "10.0.2.2") =
        assertTrue("No real HTTP fixture bytes through TUN", httpResponse(host).contains("flutter-vless-direct-bypass"))

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
                .put("disableCache", true).put("useSystemHosts", true)
                .put("hosts", JSONObject().put(hosts, "10.0.2.2").put("allowInsecure", "10.0.2.2")
                    .put("network", "MiXeD.Target.Invalid").put("full:mixed.target.invalid", "10.0.2.2"))
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
                val sourceBefore = source.toString()
                start(source, assetRoot.absolutePath)
                val udp = name("udp"); val tcp = name("tcp"); val system = name("system")
                assertA(query(udp, false)); assertA(query(tcp, true)); assertA(query(caller, false))
                // These static data keys resemble configuration fields. The
                // controlled resolver refuses both bare names if hosts are lost.
                assertA(query("allowInsecure", false)); assertA(query("network", true))
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
                assertEquals("Caller source changed", sourceBefore, source.toString())
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

    @Test fun directOnlyCallerDnsAndBlockingSurviveProductionTun() {
        val corpus = InstrumentationRegistry.getInstrumentation().context.assets.open("direct-only.json")
            .bufferedReader().use { JSONArray(it.readText()) }
        assertEquals("Shared direct-only corpus changed", 2, corpus.length())
        val selectorProfile = InstrumentationRegistry.getInstrumentation().context.assets.open("selector-traffic.json")
            .bufferedReader().use { JSONObject(it.readText()) }
        corpus.put(JSONObject().put("name", "known-nonempty-selector").put("config", selectorProfile))
        for (index in 0 until corpus.length()) {
            val original = corpus.getJSONObject(index).getJSONObject("config"); val originalBytes = original.toString()
            DnsFixture().use { fixture ->
                val source = JSONObject(originalBytes)
                val dns = source.getJSONObject("dns")
                // Both destinations are known reachable. A missing block rule
                // would return the same HTTP marker as the positive control.
                for (host in listOf("direct-only.invalid", "blocked.invalid")) {
                    dns.getJSONObject("hosts").put(host, "10.0.2.2")
                    fixture.allowOwnedName(host)
                }
                dns.put("disableCache", true).put("servers", JSONArray().put("tcp://127.0.0.1:${fixture.port}"))
                val before = source.toString()
                http() // The fixture is reachable before applying either policy.
                try {
                    val runtime = start(source)
                    val originalOutbounds = source.getJSONArray("outbounds")
                    val runtimeOutbounds = runtime.getJSONArray("outbounds")
                    for (outbound in 0 until originalOutbounds.length())
                        assertEquals("Caller outbound order or contents changed", originalOutbounds.get(outbound).toString(),
                            runtimeOutbounds.get(outbound).toString())
                    val balancers = source.getJSONObject("routing").optJSONArray("balancers")
                    if (balancers != null) {
                        assertEquals("Caller selectors changed", balancers.toString(),
                            runtime.getJSONObject("routing").getJSONArray("balancers").toString())
                        val prefix = balancers.getJSONObject(0).getJSONArray("selector").getString(0)
                        for (outbound in originalOutbounds.length() until runtimeOutbounds.length())
                            assertFalse("Private outbound entered caller selection", runtimeOutbounds.getJSONObject(outbound)
                                .getString("tag").startsWith(prefix))
                        assertFalse("Private API entered caller selection", runtime.getJSONObject("api").getString("tag").startsWith(prefix))
                    }
                    val udp = name("direct-only-udp-$index"); val tcp = name("direct-only-tcp-$index")
                    assertA(query(udp, false)); assertA(query(tcp, true))
                    assertTrue(InetAddress.getAllByName("direct-only.invalid").any { it.hostAddress == "10.0.2.2" })
                    assertTrue(InetAddress.getAllByName("blocked.invalid").any { it.hostAddress == "10.0.2.2" })
                    // All four transactions must succeed. This is enough to
                    // expose the old round-robin cycle through DNS/API/probe
                    // handlers; a failed request is never retried.
                    repeat(if (balancers == null) 1 else 4) { http("direct-only.invalid") }
                    var deniedBytes = 0
                    var deniedClosed = false
                    try {
                        Socket().use { socket ->
                            socket.soTimeout = 3000
                            socket.connect(InetSocketAddress("blocked.invalid", 18083), 3000)
                            socket.getOutputStream().write("GET /?caller-dns=$run HTTP/1.1\r\nHost: blocked.invalid\r\nConnection: close\r\n\r\n".toByteArray())
                            val bytes = ByteArray(1024)
                            while (deniedBytes < 8192) {
                                val count = socket.getInputStream().read(bytes, 0, minOf(bytes.size, 8192 - deniedBytes))
                                if (count < 0) { deniedClosed = true; break }
                                deniedBytes += count
                            }
                        }
                    } catch (error: SocketTimeoutException) {
                        throw AssertionError("Caller blocking only timed out without a rejection or closure", error)
                    } catch (_: SocketException) { deniedClosed = true }
                    assertEquals("Caller blocking returned HTTP response bytes", 0, deniedBytes)
                    assertTrue("Caller blocking did not reject or close the connection", deniedClosed)
                    val observed = fixture.observations()
                    for (expected in listOf(udp, tcp)) assertTrue("Caller direct DNS route was not used", expected to 1 in observed)
                    assertFalse("Caller static hosts escaped to DNS", observed.any { it.first in setOf("direct-only.invalid", "blocked.invalid") })
                    assertEquals(before, source.toString())
                    assertEquals(originalBytes, original.toString())
                } finally { stop() }
                http() // Each profile must restore ordinary connectivity before the next starts.
            }
        }
    }

    @Test fun callerAaaaAndIpv6TcpUdpTraverseAnIpv4Proxy() {
        // A documentation address can only reach this owned fixture through
        // the caller's IPv4 SOCKS proxy. No physical IPv6 origin is required.
        val target = InetAddress.getByName("2001:db8:41::42")
        assertEquals(16, target.address.size)
        DnsFixture(target.address).use { general -> DnsFixture(target.address).use { perDomain ->
            Ipv4SocksFixture(target.address).use { proxy ->
                val caller = name("v6-caller"); val hosts = name("v6-hosts"); val system = name("v6-system")
                val root = JSONObject().put("tag", "caller-root-dns").put("queryStrategy", "UseIP")
                    .put("disableCache", true).put("hosts", JSONObject().put(hosts, target.hostAddress))
                    .put("servers", JSONArray().put("tcp://127.0.0.1:${general.port}")
                        .put(JSONObject().put("address", "tcp://127.0.0.1:${perDomain.port}")
                            .put("domains", JSONArray().put("full:$caller")).put("skipFallback", true)
                            .put("tag", "caller-per-domain").put("queryStrategy", "UseIP")))
                val source = baseSource(blockDefault = true).put("dns", root)
                source.getJSONArray("outbounds").put(JSONObject().put("protocol", "socks").put("tag", "caller-ipv6-proxy")
                    .put("settings", JSONObject().put("address", "127.0.0.1").put("port", proxy.port)))
                val routing = source.getJSONObject("routing"); val old = routing.getJSONArray("rules")
                val rules = JSONArray().put(JSONObject().put("type", "field").put("domain", JSONArray().put("full:$hosts"))
                    .put("outboundTag", "caller-ipv6-proxy"))
                    .put(JSONObject().put("type", "field").put("network", "tcp,udp")
                    .put("ip", JSONArray().put("${target.hostAddress}/128")).put("outboundTag", "caller-ipv6-proxy"))
                for (index in 0 until old.length()) rules.put(old.get(index))
                routing.put("rules", rules)
                val before = source.toString()
                try {
                    start(source)
                    val link = requireNotNull(manager.getLinkProperties(manager.activeNetwork))
                    assertTrue("VPN has no IPv6 interface address", link.linkAddresses.any { it.address.address.size == 16 })
                    assertTrue("VPN has no IPv6 default capture route", link.routes.any {
                        it.destination.address.address.size == 16 && it.destination.prefixLength == 0
                    })
                    fun assertAaaa(answer: ByteArray) {
                        assertTrue("AAAA response too short", answer.size >= 28)
                        assertEquals(0, answer[3].toInt() and 15)
                        assertTrue("Core returned no caller AAAA", ((answer[6].toInt() and 255) shl 8 or (answer[7].toInt() and 255)) > 0)
                        assertArrayEquals(target.address, answer.takeLast(16).toByteArray())
                    }
                    val udp = name("v6-udp"); val tcp = name("v6-tcp")
                    assertAaaa(query(udp, false, 28)); assertAaaa(query(tcp, true, 28)); assertAaaa(query(caller, false, 28))
                    assertTrue("Android system DNS lost caller IPv6", InetAddress.getAllByName(system).any { it == target })
                    assertEquals(listOf(target), InetAddress.getAllByName(hosts).toList())
                    Socket().use { socket ->
                        socket.soTimeout = 3000
                        socket.connect(InetSocketAddress(hosts, 18081), 3000)
                        socket.getOutputStream().write("GET /?ipv6=$run HTTP/1.1\r\nHost: $hosts\r\nConnection: close\r\n\r\n".toByteArray())
                        val input = socket.getInputStream(); val response = ByteArrayOutputStream(); val bytes = ByteArray(1024)
                        while (response.size() < 4096) {
                            val count = input.read(bytes, 0, minOf(bytes.size, 4096 - response.size()))
                            if (count < 0) break
                            response.write(bytes, 0, count)
                        }
                        assertTrue("No IPv6 TCP response through IPv4 proxy", response.toString("UTF-8").contains("ipv6-tcp-$run"))
                    }
                    DatagramSocket().use { socket ->
                        socket.soTimeout = 3000
                        val payload = "ipv6-udp-$run".toByteArray()
                        socket.send(DatagramPacket(payload, payload.size, target, 18082))
                        val response = DatagramPacket(ByteArray(512), 512); socket.receive(response)
                        assertEquals(target, response.address); assertEquals(18082, response.port)
                        assertArrayEquals(payload, response.data.copyOf(response.length))
                    }
                    proxy.assertPayloads()
                    val generalSeen = general.observations(); val perDomainSeen = perDomain.observations()
                    for (expected in listOf(udp, tcp, system)) assertTrue("Missing root AAAA query", expected to 28 in generalSeen)
                    assertTrue("Missing per-domain AAAA query", caller to 28 in perDomainSeen)
                    assertFalse("Per-domain AAAA escaped to fallback", generalSeen.any { it.first == caller })
                    assertFalse("Caller IPv6 hosts escaped to DNS", (generalSeen + perDomainSeen).any { it.first == hosts })
                    assertEquals(before, source.toString())
                } finally { stop() }
            }
        } }
    }

    private fun fakeTcpPayload(session: Int) = byteArrayOf(0, 0x91.toByte(), 0x23, 0x42) + "fake-tcp-$run-$session".toByteArray()
    private fun fakeUdpPayload(session: Int) = byteArrayOf(0, 0x92.toByte(), 0x24, 0x43) + "fake-udp-$run-$session".toByteArray()

    @Test fun fakeDnsRestoresOpaqueTcpAndUdpDomainsAcrossFreshSessions() {
        val host = name("fake-payload")
        Ipv4SocksFixture(host.toByteArray(Charsets.US_ASCII), 3).use { proxy ->
            val source = JSONObject().put("inbounds", JSONArray()).put("stats", JSONObject())
                .put("policy", JSONObject().put("system", JSONObject().put("statsInboundUplink", false)
                    .put("statsInboundDownlink", false).put("statsOutboundUplink", false).put("statsOutboundDownlink", false)))
                .put("dns", JSONObject().put("tag", "caller-fake-dns").put("queryStrategy", "UseIPv4")
                    .put("servers", JSONArray().put("fakedns")))
                .put("outbounds", JSONArray().put(JSONObject().put("tag", "fake-proxy").put("protocol", "socks")
                    .put("settings", JSONObject().put("address", "127.0.0.1").put("port", proxy.port)))
                    .put(JSONObject().put("tag", "blocked").put("protocol", "blackhole")))
                // Private DNS/readiness guards must precede this caller block.
                .put("routing", JSONObject().put("rules", JSONArray().put(JSONObject().put("type", "field")
                    .put("port", "1-18080,18083-65535").put("outboundTag", "blocked"))))
            val original = source.toString(); var previousRuntime: String? = null
            for (session in 1..2) {
                try {
                    val runtime = start(source)
                    assertFalse("Implicit FakeDNS engine was rewritten into caller JSON", runtime.has("fakedns"))
                    previousRuntime?.let { assertNotEquals("Restart reused the old finalized probe/auth config", it, runtime.toString()) }
                    previousRuntime = runtime.toString()
                    val sniffing = runtime.getJSONArray("inbounds").getJSONObject(0).getJSONObject("sniffing")
                    assertTrue(sniffing.getBoolean("routeOnly"))
                    assertTrue((0 until sniffing.getJSONArray("destOverride").length()).any {
                        sniffing.getJSONArray("destOverride").getString(it) == "fakedns"
                    })
                    proxy.assertPayloads(session - 1, session - 1)
                    val udpA = query(host, false); val tcpA = query(host, true)
                    assertA(udpA, false); assertA(tcpA, false)
                    val address = udpA.takeLast(4).toByteArray()
                    assertArrayEquals(address, tcpA.takeLast(4).toByteArray())
                    assertEquals(198, address[0].toInt() and 255)
                    assertTrue((address[1].toInt() and 255) in 18..19)
                    val fake = InetAddress.getByAddress(address)
                    for (tcp in listOf(false, true)) {
                        val aaaa = query(host, tcp, 28)
                        assertEquals(0, aaaa[3].toInt() and 15); assertEquals(0, aaaa[6].toInt() or aaaa[7].toInt())
                        val txt = query(host, tcp, 16)
                        assertEquals(5, txt[3].toInt() and 15); assertEquals(0, txt[6].toInt() or txt[7].toInt())
                    }
                    Socket().use { socket ->
                        socket.soTimeout = 3000; socket.connect(InetSocketAddress(fake, 18081), 3000)
                        val payload = fakeTcpPayload(session); socket.getOutputStream().write(payload)
                        val response = ByteArray(payload.size).also { DataInputStream(socket.getInputStream()).readFully(it) }
                        assertArrayEquals(payload, response)
                    }
                    DatagramSocket().use { socket ->
                        socket.soTimeout = 3000; val payload = fakeUdpPayload(session)
                        socket.send(DatagramPacket(payload, payload.size, fake, 18082))
                        val response = DatagramPacket(ByteArray(512), 512); socket.receive(response)
                        assertEquals(fake, response.address); assertEquals(18082, response.port)
                        assertArrayEquals(payload, response.data.copyOf(response.length))
                    }
                    proxy.assertPayloads(session, session)
                    assertEquals(original, source.toString())
                } finally {
                    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
                    stop()
                    fun inputsRemain() = context.noBackupFilesDir.listFiles().orEmpty().any { it.name.startsWith("xray-") }
                    while ((inputsRemain() || !proxy.idle()) && System.nanoTime() < deadline) Thread.sleep(25)
                    assertFalse("Stop retained native runtime input files", inputsRemain())
                    assertTrue("Stop retained the owned SOCKS association", proxy.idle())
                }
            }
        }
    }

    /** Logical IPv6 or FakeDNS domains are checked in SOCKS frames; both actual
     * proxy sockets stay IPv4 loopback. Never connects to the requested target. */
    private inner class Ipv4SocksFixture(private val target: ByteArray, private val targetFamily: Int = 4) : Closeable {
        private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        private val listener = ServerSocket(0, 8, loopback)
        private val relay = try { DatagramSocket(0, loopback) } catch (error: Throwable) { listener.close(); throw error }
        val port = listener.localPort
        private val lock = Any()
        private var closed = false
        private var active: Socket? = null
        private val failure = AtomicReference<Throwable?>()
        private val tcpPayloads = AtomicInteger()
        private val udpPayloads = AtomicInteger()
        private val workers = listOf(
            Thread({
                try {
                    while (true) {
                        val socket = listener.accept()
                        val admitted = synchronized(lock) { if (closed) false else { active = socket; true } }
                        if (!admitted) { socket.close(); break }
                        try { socket.use(::tcp) } finally { synchronized(lock) { if (active === socket) active = null } }
                    }
                } catch (error: Throwable) { recordFailure(error) }
            }, "caller-ipv6-proxy-tcp").apply { isDaemon = true },
            Thread({
                try {
                    while (true) {
                        val packet = DatagramPacket(ByteArray(4096), 4096); relay.receive(packet)
                        val bytes = packet.data.copyOf(packet.length)
                        val input = DataInputStream(bytes.inputStream())
                        require(input.readUnsignedShort() == 0 && input.readUnsignedByte() == 0)
                        require(input.readUnsignedByte() == targetFamily) { "UDP target did not preserve logical ATYP" }
                        val address = socksAddress(input, targetFamily)
                        require(address.contentEquals(target) && input.readUnsignedShort() == 18082)
                        val payload = ByteArray(input.available()).also(input::readFully)
                        val expected = if (targetFamily == 3) fakeUdpPayload(udpPayloads.get() + 1) else "ipv6-udp-$run".toByteArray()
                        require(payload.contentEquals(expected))
                        udpPayloads.incrementAndGet()
                        relay.send(DatagramPacket(bytes, bytes.size, packet.address, packet.port))
                    }
                } catch (error: Throwable) { recordFailure(error) }
            }, "caller-ipv6-proxy-udp").apply { isDaemon = true })

        init {
            try { workers.forEach(Thread::start) }
            catch (error: Throwable) { try { close() } catch (cleanup: Throwable) { error.addSuppressed(cleanup) }; throw error }
        }

        private fun recordFailure(error: Throwable) {
            if (!synchronized(lock) { closed }) failure.compareAndSet(null, error)
        }

        private fun socksAddress(input: DataInputStream, family: Int): ByteArray {
            val size = when (family) { 1 -> 4; 4 -> 16; 3 -> input.readUnsignedByte().also { require(it in 1..253) }; else -> error("Invalid SOCKS address") }
            return ByteArray(size).also(input::readFully)
        }

        private fun tcp(socket: Socket) {
            socket.soTimeout = 3000
            val input = DataInputStream(socket.getInputStream()); val output = socket.getOutputStream()
            require(input.readUnsignedByte() == 5)
            val count = input.readUnsignedByte(); require(count in 1..16)
            val methods = ByteArray(count).also(input::readFully); require(0.toByte() in methods)
            output.write(byteArrayOf(5, 0)); output.flush()
            require(input.readUnsignedByte() == 5)
            val command = input.readUnsignedByte(); require(input.readUnsignedByte() == 0)
            val family = input.readUnsignedByte()
            val address = socksAddress(input, family); val destinationPort = input.readUnsignedShort()
            if (command == 3) {
                // Association control tuple is not the per-datagram target.
                val relayPort = relay.localPort
                output.write(byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, (relayPort shr 8).toByte(), relayPort.toByte())); output.flush()
                while (input.read() >= 0) { /* Control EOF follows owned Core Stop. */ }
                return
            }
            require(command == 1 && family == targetFamily && address.contentEquals(target) && destinationPort == 18081) {
                "TCP target did not preserve exact logical SOCKS destination"
            }
            output.write(byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, 0, 0)); output.flush()
            if (targetFamily == 3) {
                val expected = fakeTcpPayload(tcpPayloads.get() + 1)
                val payload = ByteArray(expected.size).also(input::readFully)
                require(payload.contentEquals(expected))
                tcpPayloads.incrementAndGet(); output.write(payload); output.flush()
                return
            }
            val request = ByteArrayOutputStream()
            while (request.size() < 4096) {
                val value = input.read(); require(value >= 0); request.write(value)
                if (request.toString("US-ASCII").endsWith("\r\n\r\n")) break
            }
            require(request.toString("US-ASCII").startsWith("GET /?ipv6=$run HTTP/1.1\r\n"))
            val body = "ipv6-tcp-$run".toByteArray()
            tcpPayloads.incrementAndGet()
            output.write("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: ${body.size}\r\n\r\n".toByteArray() + body)
            output.flush()
        }

        fun assertPayloads(expectedTcp: Int = 1, expectedUdp: Int? = null) {
            failure.get()?.let { throw AssertionError("Owned IPv6 proxy fixture failed", it) }
            assertEquals("Missing exact logical TCP SOCKS proof", expectedTcp, tcpPayloads.get())
            if (expectedUdp == null) assertTrue("Missing exact IPv6 UDP SOCKS proof", udpPayloads.get() >= 1)
            else assertEquals("Missing exact logical UDP SOCKS proof", expectedUdp, udpPayloads.get())
        }

        fun idle() = synchronized(lock) { active == null }

        override fun close() {
            val socket = synchronized(lock) { closed = true; active }
            var error: Throwable? = null
            val actions = mutableListOf<() -> Unit>({ listener.close() }, { relay.close() }, { socket?.close() })
            workers.forEach { worker -> actions.add { worker.join(1500); check(!worker.isAlive) { "Owned IPv6 proxy worker did not stop" } } }
            actions.forEach { action -> try { action() } catch (caught: Throwable) { if (error == null) error = caught else error!!.addSuppressed(caught) } }
            failure.get()?.let { if (error == null) error = it else error!!.addSuppressed(it) }
            error?.let { throw it }
        }
    }

    private inner class DnsFixture(private val ipv6Answer: ByteArray? = null) : Closeable {
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
                val address = if (!controlled) null else when (type) { 1 -> byteArrayOf(10, 0, 2, 2); 28 -> ipv6Answer; else -> null }
                output.writeShort(if (address != null) 1 else 0); output.writeInt(0)
                output.write(question, 12, offset + 4 - 12)
                if (address != null) {
                    output.writeShort(0xc00c); output.writeShort(type); output.writeShort(1)
                    output.writeInt(0); output.writeShort(address.size); output.write(address)
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
