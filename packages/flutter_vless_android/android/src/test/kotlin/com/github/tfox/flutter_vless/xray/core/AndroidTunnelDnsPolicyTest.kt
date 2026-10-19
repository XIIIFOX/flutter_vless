package com.github.tfox.flutter_vless.xray.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class AndroidTunnelDnsPolicyTest {
    @Test fun fakeDnsBridgeUsesAnAddressOutsideTheDefaultFakePools() {
        val prepared = AndroidTunnelDnsPolicy.prepare(config(outbound()).toString())
        assertEquals(listOf("10.0.85.53"), prepared.systemDnsServers)
        assertEquals("10.0.85.53/32", JSONObject(prepared.configJson).getJSONObject("routing")
            .getJSONArray("rules").getJSONObject(0).getJSONArray("ip").getString(0))
    }

    @Test fun fakeDnsReservedPoolOverlapIsRefusedBeforeProxyBootstrap() {
        for (pool in listOf("10.0.85.0/24", "26.26.26.0/30", "fd26:26:26::/126", "fd00:198:18::/64",
                "::ffff:10.0.85.0/120", "::ffff:26.26.26.0/126", "::ffff:0:0/80")) {
            val input = config(outbound()).put("fakeDns", JSONObject().put("ipPool", pool).put("poolSize", 1))
            val before = input.toString(); var callbacks = 0
            org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
                AndroidTunnelDnsPolicy.prepare(before, "proxy") { callbacks++; listOf("192.0.2.17") }
            }
            assertEquals("Overlapping FakeDNS engine reached physical bootstrap", 0, callbacks)
            assertEquals(before, input.toString())
        }
    }

    private fun outbound(protocol: String = "http", tag: String? = "proxy", address: String = "proxy.test"): JSONObject {
        val endpoint = JSONObject().put("address", address).put("port", 443)
            .put("users", JSONArray().put(JSONObject().put("user", "remote-user").put("pass", "remote-password")
                .put("id", "remote-id").put("encryption", "mlkem768x25519plus.native-value")))
        return JSONObject().put("protocol", protocol)
            .put("settings", JSONObject().put(if (protocol in setOf("vless", "vmess")) "vnext" else "servers", JSONArray().put(endpoint)))
            .also { if (tag != null) it.put("tag", tag) }
    }

    private fun config(vararg proxies: JSONObject) = JSONObject()
        .put("inbounds", JSONArray().put(JSONObject().put("protocol", "socks").put("tag", "socks").put("port", 10808)))
        .put("outbounds", JSONArray(proxies.toList()).put(JSONObject().put("protocol", "freedom").put("tag", "direct")))
        .put("dns", JSONObject().put("servers", JSONArray().put("localhost").put("https+local://resolver.test/dns-query")))
        .put("routing", JSONObject().put("domainStrategy", "IPIfNonMatch").put("rules", JSONArray()
            .put(JSONObject().put("type", "field").put("network", "udp").put("outboundTag", "direct"))
            .put(JSONObject().put("type", "field").put("domain", JSONArray().put("domain:example.test")).put("outboundTag", "direct"))))

    private fun prepare(input: JSONObject, tag: String? = null): AndroidTunnelDnsPolicy.Prepared =
        AndroidTunnelDnsPolicy.prepare(input.toString(), "proxy", tag) { listOf("192.0.2.17") }

    private fun rejected(action: () -> Unit) {
        try { action(); fail("Expected invalid DNS configuration to be rejected") } catch (_: IllegalArgumentException) { }
    }

    @Test fun httpSocksAndVlessKeepCredentialsAndUseSelectedTcpProxyBeforeUserDirectRules() {
        for (protocol in listOf("http", "socks", "vless")) {
            val proxy = outbound(protocol)
            val originalSettings = proxy.getJSONObject("settings").toString()
            val input = config(proxy)
            val originalUserRules = input.getJSONObject("routing").getJSONArray("rules")
            val prepared = prepare(input)
            val output = JSONObject(prepared.configJson)
            assertEquals(listOf("10.0.85.53"), prepared.systemDnsServers)
            assertEquals(setOf("proxy.test"), prepared.bootstrapHostnames)
            assertEquals(setOf("192.0.2.17"), prepared.bootstrapAddresses)
            val outbounds = output.getJSONArray("outbounds")
            assertEquals(originalSettings, outbounds.getJSONObject(0).getJSONObject("settings").toString())
            assertEquals("ForceIP", outbounds.getJSONObject(0).getJSONObject("streamSettings").getJSONObject("sockopt").getString("domainStrategy"))
            val relay = outbounds.getJSONObject(2)
            assertEquals("dns", relay.getString("protocol"))
            assertEquals("tcp", relay.getJSONObject("settings").getString("rewriteNetwork"))
            assertEquals("1.1.1.1", relay.getJSONObject("settings").getString("rewriteAddress"))
            assertFalse(relay.has("proxySettings"))
            val relayRules = relay.getJSONObject("settings").getJSONArray("rules")
            assertEquals(1, relayRules.length())
            assertEquals("direct", relayRules.getJSONObject(0).getString("action"))
            assertEquals("proxy", relay.getJSONObject("streamSettings").getJSONObject("sockopt").getString("dialerProxy"))
            val dns = output.getJSONObject("dns")
            assertEquals("tcp://1.1.1.1", dns.getJSONArray("servers").getString(0))
            assertTrue(dns.getBoolean("disableFallback"))
            assertEquals("192.0.2.17", dns.getJSONObject("hosts").getJSONArray("proxy.test").getString(0))
            val rules = output.getJSONObject("routing").getJSONArray("rules")
            assertEquals("proxy", rules.getJSONObject(0).getString("outboundTag"))
            assertEquals("10.0.85.53/32", rules.getJSONObject(1).getJSONArray("ip").getString(0))
            assertEquals(prepared.managedInboundTag, rules.getJSONObject(1).getJSONArray("inboundTag").getString(0))
            assertEquals("tcp,udp", rules.getJSONObject(1).getString("network"))
            assertEquals(AndroidTunnelDnsPolicy.RELAY_TAG, rules.getJSONObject(1).getString("outboundTag"))
            assertEquals(originalUserRules.getJSONObject(0).toString(), rules.getJSONObject(2).toString())
            assertEquals(originalUserRules.getJSONObject(1).toString(), rules.getJSONObject(3).toString())
            assertEquals("IPIfNonMatch", output.getJSONObject("routing").getString("domainStrategy"))
        }
    }

    @Test fun configModePreservesCallerRootDnsAndEndpointsWithPrivateCoreClientRelay() {
        val callerDns = JSONObject("""{
          "hosts":{"domain:example.test":["192.0.2.8"],"alias.test":"canonical.test"},
          "servers":["localhost","https://resolver.test/dns-query","https+local://local-resolver.test/dns-query",
            "tls://dot-source.test",{"address":"tcp://192.0.2.53","domains":["full:caller.test"],
            "skipFallback":true,"tag":"caller-server","queryStrategy":"UseIPv4","timeoutMs":500}],
          "queryStrategy":"UseIPv6","tag":"caller-dns","disableFallback":true,"clientIp":"192.0.2.9"
        }""")
        val input = config(outbound()).put("dns", callerDns)
        val original = input.toString()
        val prepared = AndroidTunnelDnsPolicy.prepare(original, "config") { error("config mode must not bootstrap endpoints") }
        val output = JSONObject(prepared.configJson)
        assertEquals(original, input.toString())
        assertEquals(callerDns.toString(), output.getJSONObject("dns").toString())
        assertEquals(input.getJSONArray("inbounds").toString(), output.getJSONArray("inbounds").toString())
        assertEquals(input.getJSONArray("outbounds").getJSONObject(0).toString(), output.getJSONArray("outbounds").getJSONObject(0).toString())
        assertEquals(listOf(AndroidTunnelDnsPolicy.VIRTUAL_SERVER), prepared.systemDnsServers)
        assertTrue(prepared.bootstrapHostnames.isEmpty()); assertTrue(prepared.bootstrapAddresses.isEmpty())
        val relay = output.getJSONArray("outbounds").getJSONObject(2)
        assertEquals("dns", relay.getString("protocol"))
        assertFalse(relay.has("streamSettings"))
        val settings = relay.getJSONObject("settings")
        assertFalse(settings.has("rewriteAddress")); assertFalse(settings.has("rewriteNetwork")); assertFalse(settings.has("rewritePort"))
        val dnsRules = settings.getJSONArray("rules")
        assertEquals(3, dnsRules.length())
        assertEquals("hijack", dnsRules.getJSONObject(0).getString("action"))
        assertEquals("28", dnsRules.getJSONObject(0).getString("qType")); assertFalse(dnsRules.getJSONObject(0).has("rCode"))
        assertEquals("hijack", dnsRules.getJSONObject(1).getString("action")); assertEquals("1", dnsRules.getJSONObject(1).getString("qType"))
        assertEquals("return", dnsRules.getJSONObject(2).getString("action")); assertEquals(5, dnsRules.getJSONObject(2).getInt("rCode"))
        val routing = output.getJSONObject("routing"); val rules = routing.getJSONArray("rules")
        assertEquals("IPIfNonMatch", routing.getString("domainStrategy"))
        val bridge = rules.getJSONObject(0)
        assertEquals(prepared.managedInboundTag, bridge.getJSONArray("inboundTag").getString(0))
        assertEquals("10.0.85.53/32", bridge.getJSONArray("ip").getString(0))
        assertEquals("53", bridge.getString("port")); assertEquals("tcp,udp", bridge.getString("network"))
        assertEquals(relay.getString("tag"), bridge.getString("outboundTag"))
        val userRules = input.getJSONObject("routing").getJSONArray("rules")
        assertEquals(userRules.length() + 1, rules.length())
        for (i in 0 until userRules.length()) assertEquals(userRules.getJSONObject(i).toString(), rules.getJSONObject(i + 1).toString())
        rejected { AndroidTunnelDnsPolicy.prepare(original, "invalid") }
        rejected { AndroidTunnelDnsPolicy.prepare(original, "config", "proxy") }
    }

    @Test fun configModeMissingEmptyAndLocalhostDnsKeepProtectedCoreDefaultSemantics() {
        for (dns in listOf<JSONObject?>(null, JSONObject(), JSONObject().put("servers", JSONArray()),
                JSONObject().put("servers", JSONArray().put("localhost")))) {
            val input = config(JSONObject().put("protocol", "freedom").put("tag", "caller-direct"))
            if (dns == null) input.remove("dns") else input.put("dns", dns)
            val prepared = AndroidTunnelDnsPolicy.prepare(input.toString(), "config") { error("no preparer OS fallback") }
            val output = JSONObject(prepared.configJson)
            assertEquals(dns != null, output.has("dns"))
            if (dns != null) assertEquals(dns.toString(), output.getJSONObject("dns").toString())
            assertEquals(listOf(AndroidTunnelDnsPolicy.VIRTUAL_SERVER), prepared.systemDnsServers)
            val settings = output.getJSONArray("outbounds").getJSONObject(2).getJSONObject("settings")
            assertEquals(3, settings.getJSONArray("rules").length()) // A/AAAA use Core; no direct-to-VIP fallback.
            assertEquals("hijack", settings.getJSONArray("rules").getJSONObject(0).getString("action"))
        }
    }

    @Test fun sharedDirectOnlyProfilesPreserveCallerDnsOutboundOrderAndBlockingRules() {
        val cases = JSONArray(requireNotNull(javaClass.getResource("/direct-only.json")).readText())
        assertEquals(2, cases.length())
        for (index in 0 until cases.length()) {
            val item = cases.getJSONObject(index); val label = item.getString("name")
            val input = item.getJSONObject("config"); val before = input.toString()
            val prepared = AndroidTunnelDnsPolicy.prepare(before, "config") {
                error("$label must not require a proxy endpoint or wrapper DNS lookup")
            }
            val profile = com.github.tfox.flutter_vless.xray.dto.XrayConfig(V2RAY_FULL_JSON_CONFIG = prepared.configJson)
            val runtime = XrayCoreManager.buildRuntimeConfigJson(profile, java.io.File("build/test-files/direct-only"),
                LocalProxyCredentials("direct-fixture-user", "direct-fixture-password"), prepared)
            assertEquals(label, input.getJSONObject("dns").toString(), runtime.getJSONObject("dns").toString())
            val expected = input.getJSONArray("outbounds"); val actual = runtime.getJSONArray("outbounds")
            assertEquals(label, expected.length() + 1, actual.length())
            for (outbound in 0 until expected.length())
                assertEquals("$label/outbound$outbound", expected.getJSONObject(outbound).toString(), actual.getJSONObject(outbound).toString())
            val originalRules = input.getJSONObject("routing").getJSONArray("rules")
            val actualRules = runtime.getJSONObject("routing").getJSONArray("rules")
            assertTrue(label, actualRules.length() >= originalRules.length())
            val start = actualRules.length() - originalRules.length()
            for (rule in 0 until originalRules.length())
                assertEquals("$label/rule$rule", originalRules.getJSONObject(rule).toString(), actualRules.getJSONObject(start + rule).toString())
            val relayTag = actual.getJSONObject(expected.length()).getString("tag")
            val bridge = (0 until actualRules.length()).map(actualRules::getJSONObject).single { rule ->
                rule.optString("outboundTag") == relayTag && rule.optString("port") == "53"
            }
            assertEquals(prepared.managedInboundTag, bridge.getJSONArray("inboundTag").getString(0))
            assertEquals("${AndroidTunnelDnsPolicy.VIRTUAL_SERVER}/32", bridge.getJSONArray("ip").getString(0))
            assertTrue(prepared.bootstrapHostnames.isEmpty()); assertTrue(prepared.bootstrapAddresses.isEmpty())
            assertEquals(label, before, input.toString())
        }
    }

    @Test fun configModeReservesPrivateIdentitiesWithoutRenamingCallerDnsOrInputTags() {
        val input = config(outbound(tag = AndroidTunnelDnsPolicy.RELAY_TAG))
        input.getJSONObject("dns").put("tag", "flutter-vless-system-dns-1")
        input.getJSONArray("inbounds").getJSONObject(0).put("tag", "flutter-vless-tun")
        input.getJSONObject("routing").getJSONArray("rules").put(JSONObject().put("inboundTag", JSONArray().put("caller-dns"))
            .put("outboundTag", "flutter-vless-tun-1"))
        val prepared = AndroidTunnelDnsPolicy.prepare(input.toString(), "config")
        val output = JSONObject(prepared.configJson)
        assertEquals("flutter-vless-tun-2", prepared.managedInboundTag)
        assertEquals("flutter-vless-system-dns-2", output.getJSONArray("outbounds").getJSONObject(2).getString("tag"))
        assertEquals(input.getJSONObject("dns").toString(), output.getJSONObject("dns").toString())
        assertEquals(input.getJSONArray("inbounds").toString(), output.getJSONArray("inbounds").toString())
    }

    @Test fun configModeAcceptsFakeDnsAndDoesNotInterpretUnrelatedHostKeysAsAnEngine() {
        for (key in listOf("fakeDns", "FAKEDNS", "fakeDnſ")) {
            for (value in listOf<Any>(JSONObject().put("ipPool", "198.19.0.0/16").put("poolSize", 1024), JSONArray())) {
                val source = config(outbound()).put(key, value).toString()
                assertTrue(AndroidTunnelDnsPolicy.fakeDnsActive(JSONObject(AndroidTunnelDnsPolicy.prepare(source).configJson)))
            }
        }
        for (address in listOf("fakedns", "FakeDNS", "fakednſ")) {
            for (server in listOf<Any>(address, JSONObject().put("Addreſſ", address))) {
                val input = config(outbound()).put("DNS", JSONObject().put("SerVerſ", JSONArray().put(server)))
                input.remove("dns")
                assertTrue(AndroidTunnelDnsPolicy.fakeDnsActive(JSONObject(AndroidTunnelDnsPolicy.prepare(input.toString()).configJson)))
            }
        }
        // A null engine is not a configured Core app. Hosts may legitimately
        // contain this word; do not use arbitrary recursive string matching.
        val allowed = config(outbound()).put("fakeDns", JSONObject.NULL)
        allowed.getJSONObject("dns").put("hosts", JSONObject().put("fakedns", "192.0.2.1"))
        assertFalse(AndroidTunnelDnsPolicy.fakeDnsActive(JSONObject(AndroidTunnelDnsPolicy.prepare(allowed.toString()).configJson)))
    }

    @Test fun fakeDnsPoolShapeCapacityAndNumericCidrValidationRemainStrict() {
        fun input(pool: Any) = config(outbound()).put("fakeDns", pool).toString()
        for (cidr in listOf("pool.invalid/24", "198.19.0.0/33", "[fc00::]/18", "fc00::%en0/18",
                " fc00::/18", "fc00::\u0000/18", "198.019.0.0/16", "::ffff:198.019.0.0/112")) {
            rejected { AndroidTunnelDnsPolicy.prepare(input(JSONObject().put("ipPool", cidr).put("poolSize", 1))) }
        }
        for (size in listOf<Any>(0, -1, "1024", JSONObject.NULL, java.math.BigInteger("9223372036854775808"))) {
            rejected { AndroidTunnelDnsPolicy.prepare(input(JSONObject().put("ipPool", "198.19.0.0/16").put("poolSize", size))) }
        }
        // JSONObject's writer normalizes 1.0 to 1; retain the caller's actual
        // decimal spelling so this exercises Core's int64 decoding boundary.
        rejected { AndroidTunnelDnsPolicy.prepare(input(JSONObject().put("ipPool", "198.19.0.0/16").put("poolSize", 1))
            .replace("\"poolSize\":1", "\"poolSize\":1.0")) }
        for (pool in listOf<Any>("198.19.0.0/16", JSONObject(), JSONArray().put(JSONObject.NULL),
                JSONObject().put("ipPool", "198.19.0.0/30").put("poolSize", 4),
                JSONObject().put("ipPool", "fc00::/65").put("poolSize", Long.MAX_VALUE))) {
            rejected { AndroidTunnelDnsPolicy.prepare(input(pool)) }
        }
        for ((cidr, size) in listOf("198.19.0.0/30" to 3L, "fc00::/65" to (1L shl 62), "198.19.0.0/00024" to 255L)) {
            val source = input(JSONObject().put("ipPool", cidr).put("poolSize", size))
            AndroidTunnelDnsPolicy.prepare(source)
            assertEquals(source, JSONObject(source).toString())
        }
    }

    @Test fun untaggedSingleProxyGetsReservedTagAndAmbiguousProxiesRequireSelection() {
        val single = JSONObject(prepare(config(outbound(tag = null))).configJson)
        assertEquals(AndroidTunnelDnsPolicy.PROXY_TAG, single.getJSONArray("outbounds").getJSONObject(0).getString("tag"))
        val ambiguous = config(outbound(tag = "one"), outbound("socks", "two"))
        rejected { prepare(ambiguous) }
        rejected { prepare(ambiguous, "missing") }
        rejected { prepare(ambiguous, "direct") }
        val chosen = JSONObject(prepare(ambiguous, "two").configJson)
        assertEquals("two", chosen.getJSONArray("outbounds").getJSONObject(3).getJSONObject("streamSettings").getJSONObject("sockopt").getString("dialerProxy"))
        val conventional = JSONObject(prepare(config(outbound(tag = "other"), outbound("vless"))).configJson)
        assertEquals("proxy", conventional.getJSONArray("outbounds").getJSONObject(3).getJSONObject("streamSettings").getJSONObject("sockopt").getString("dialerProxy"))
    }

    @Test fun virtualEndpointRoutingConflictsRejectBeforeResolution() {
        val invalid = mutableListOf<JSONObject>()
        invalid.add(config(outbound(), outbound("socks")))
        invalid.add(config(outbound(address = "10.0.85.53")))
        invalid.add(config(outbound(address = "::ffff:10.0.85.53")))
        invalid.add(config(outbound()).also {
            it.getJSONObject("routing").getJSONArray("rules").put(JSONObject().put("ip", JSONArray().put("10.0.85.53/32")).put("outboundTag", "direct"))
        })
        for (input in invalid) rejected {
            AndroidTunnelDnsPolicy.prepare(input.toString(), "proxy") { error("invalid candidate must not perform bootstrap") }
        }
    }

    @Test fun exclusionsContainingVirtualDnsFailWhileOtherDirectExclusionsRemainAvailable() {
        for (route in listOf("10.0.85.53", "10.0.85.53/32", "10.0.85.0/24", "0.0.0.0/0")) {
            assertFalse(AndroidTunnelDnsPolicy.allowsRouteExclusions(listOf(route)))
            rejected { AndroidTunnelDnsPolicy.prepare(config(outbound()).toString(), "proxy", excludedRoutes = listOf(route)) }
        }
        assertTrue(AndroidTunnelDnsPolicy.allowsRouteExclusions(listOf("192.168.0.0/16", "10.0.85.52/32", "2001:db8::/32")))
    }

    @Test fun bootstrapFailureDoesNotModifyInputOrFallBackToOsDns() {
        val input = config(outbound())
        val original = input.toString()
        rejected { AndroidTunnelDnsPolicy.prepare(original, "proxy") { emptyList() } }
        rejected { AndroidTunnelDnsPolicy.prepare(original, "proxy") { throw java.net.UnknownHostException("sensitive-endpoint") } }
        rejected { AndroidTunnelDnsPolicy.prepare(original, "proxy") { listOf("10.0.85.53") } }
        rejected { AndroidTunnelDnsPolicy.prepare(original, "proxy") { listOf("not-an-ip.test") } }
        assertEquals(original, input.toString())
        AndroidTunnelDnsPolicy.validate(original, "proxy")
    }

    @Test fun ipv6LiteralAndDualStackBootstrapDoNotAlterEndpointOrTlsNames() {
        val ip = "2001:db8::17"
        val literal = AndroidTunnelDnsPolicy.prepare(config(outbound(address = ip)).toString(), "proxy") { error("literal must not resolve") }
        assertTrue(literal.bootstrapHostnames.isEmpty())
        assertEquals(1, literal.bootstrapAddresses.size)
        val proxy = outbound(address = "PrOxY.TeSt.").put("streamSettings", JSONObject()
            .put("tlsSettings", JSONObject().put("serverName", "certificate.test")))
        var calls = 0
        val prepared = AndroidTunnelDnsPolicy.prepare(config(proxy).toString(), "proxy") {
            calls++; assertEquals("proxy.test", it); listOf("192.0.2.17", ip)
        }
        assertEquals(1, calls)
        val output = JSONObject(prepared.configJson)
        val transport = output.getJSONArray("outbounds").getJSONObject(0)
        assertEquals("PrOxY.TeSt.", transport.getJSONObject("settings").getJSONArray("servers").getJSONObject(0).getString("address"))
        assertEquals("certificate.test", transport.getJSONObject("streamSettings").getJSONObject("tlsSettings").getString("serverName"))
        assertEquals(2, output.getJSONObject("dns").getJSONObject("hosts").getJSONArray("proxy.test").length())
    }

    @Test fun xhttpDownloadAndExtraEndpointsArePinnedAndRequireNoSrvFallback() {
        for (transportKey in listOf("xHTTPSettings", "SplitHTTPSettings")) {
            val stream = JSONObject().put("Address", "transport.test").put("network", "xhttp")
                .put(transportKey, JSONObject()
                    .put("downloadSettings", JSONObject().put("Address", "outer-download.test").put("network", "xhttp"))
                    .put("Extra", JSONObject().put("DownloadSettings", JSONObject().put("address", "extra-download.test")
                        .put("network", "xhttp")
                        .put("sockopt", JSONObject().put("DomainStrategy", "AsIs")))))
            val prepared = prepare(config(outbound().put("StreamSettings", stream)))
            assertEquals(setOf("proxy.test", "extra-download.test"), prepared.bootstrapHostnames)
            val outputStream = JSONObject(prepared.configJson).getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")
            val transport = outputStream.getJSONObject(if (transportKey == "xHTTPSettings") "xhttpSettings" else "splithttpSettings")
            assertEquals("ForceIP", transport.getJSONObject("extra").getJSONObject("downloadSettings").getJSONObject("sockopt").getString("domainStrategy"))
            stream.getJSONObject(transportKey).remove("Extra")
            val outerPrepared = prepare(config(outbound().put("streamSettings", stream)))
            assertEquals(setOf("proxy.test", "outer-download.test"), outerPrepared.bootstrapHostnames)
            val outerOutput = JSONObject(outerPrepared.configJson).getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")
                .getJSONObject(if (transportKey == "xHTTPSettings") "xhttpSettings" else "splithttpSettings").getJSONObject("downloadSettings")
            assertEquals("ForceIP", outerOutput.getJSONObject("sockopt").getString("domainStrategy"))
        }
        rejected { prepare(config(outbound().put("streamSettings", JSONObject().put("sockopt", JSONObject().put("AddressPortStrategy", "srv"))))) }
    }

    @Test fun masqueProxyDnsPinsOnlyItsOuterEndpointAndPreservesInternalRecords() {
        val settings = JSONObject().put("address", "masque.test").put("port", 443)
            .put("remoteDNS", JSONArray().put("1.1.1.1").put("2001:4860:4860::8888"))
        val transport = JSONObject().put("user", "synthetic-user").put("pass", "synthetic-password")
            .put("host", "logical-masque.test").put("path", "/masque")
        val masque = JSONObject().put("protocol", "masque").put("tag", "proxy").put("settings", settings)
            .put("streamSettings", JSONObject().put("network", "masque").put("security", "tls")
                .put("tlsSettings", JSONObject().put("serverName", "certificate.test")).put("masqueSettings", transport))
        val loopback = JSONObject().put("protocol", "loopback").put("tag", "caller-loop")
            .put("settings", JSONObject().put("inboundTag", "caller-loop-input"))
        val dns = JSONObject().put("protocol", "dns").put("tag", "caller-dns").put("settings", JSONObject())
        val input = config(masque, loopback, dns)
        val original = input.toString()
        val prepared = AndroidTunnelDnsPolicy.prepare(original, "proxy") {
            assertEquals("masque.test", it); listOf("192.0.2.17")
        }
        assertEquals(setOf("masque.test"), prepared.bootstrapHostnames)
        val outputs = JSONObject(prepared.configJson).getJSONArray("outbounds")
        assertEquals(settings.toString(), outputs.getJSONObject(0).getJSONObject("settings").toString())
        assertEquals(transport.toString(), outputs.getJSONObject(0).getJSONObject("streamSettings").getJSONObject("masqueSettings").toString())
        assertEquals(loopback.toString(), outputs.getJSONObject(1).toString())
        assertEquals(dns.toString(), outputs.getJSONObject(2).toString())
        assertEquals(original, input.toString())
    }

    @Test fun xhttpWinsSplitHttpWhileExtraSelectsOnlyItsOwnDownloadEndpoint() {
        val inactive = JSONObject().put("headers", JSONObject().put("X-Secret", "retained-inactive"))
            .put("downloadSettings", JSONObject().put("address", "inactive-split.test"))
        val outerDownload = JSONObject().put("address", "inactive-outer.test")
        val selected = JSONObject().put("downloadSettings", outerDownload).put("extra", JSONObject()
            .put("headers", JSONObject().put("X-Secret", "active-secret"))
            .put("downloadSettings", JSONObject().put("address", "active-download.test").put("network", "xhttp")))
        val stream = JSONObject().put("network", "splithttp").put("xhttpSettings", selected).put("splithttpSettings", inactive)
        val input = config(outbound().put("streamSettings", stream)); val original = input.toString()
        val prepared = prepare(input)
        assertEquals(setOf("proxy.test", "active-download.test"), prepared.bootstrapHostnames)
        val result = JSONObject(prepared.configJson).getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")
        assertEquals(inactive.toString(), result.getJSONObject("splithttpSettings").toString())
        assertEquals(outerDownload.toString(), result.getJSONObject("xhttpSettings").getJSONObject("downloadSettings").toString())
        assertEquals("active-secret", result.getJSONObject("xhttpSettings").getJSONObject("extra").getJSONObject("headers").getString("X-Secret"))
        assertEquals(original, input.toString())
    }

    @Test fun nullXhttpFallsBackToSplitHttpAndNullExtraReplacesOuterDownloads() {
        val split = JSONObject().put("downloadSettings", JSONObject().put("address", "active-split.test").put("network", "xhttp"))
        val stream = JSONObject().put("network", "splithttp").put("xhttpSettings", JSONObject.NULL).put("splithttpSettings", split)
        assertEquals(setOf("proxy.test", "active-split.test"), prepare(config(outbound().put("streamSettings", stream))).bootstrapHostnames)
        for (extra in listOf<Any>(JSONObject.NULL, JSONObject().put("downloadSettings", JSONObject.NULL))) {
            val xhttp = JSONObject().put("downloadSettings", JSONObject().put("address", "inactive-outer.test")).put("extra", extra)
            val output = prepare(config(outbound().put("streamSettings", JSONObject().put("network", "xhttp").put("xhttpSettings", xhttp))))
            assertEquals(setOf("proxy.test"), output.bootstrapHostnames)
            val retained = JSONObject(output.configJson).getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings").getJSONObject("xhttpSettings")
            assertEquals(xhttp.toString(), retained.toString())
        }
    }

    @Test fun methodOverridesNetworkAndNullMethodRetainsNetworkDefault() {
        val download = JSONObject().put("address", "download.test").put("network", "xhttp")
        for ((network, method, active) in listOf(Triple("tcp", "xhttp", true),
                Triple("splithttp", JSONObject.NULL, true), Triple("xhttp", "tcp", false),
                Triple(JSONObject.NULL, JSONObject.NULL, false))) {
            val xhttp = JSONObject().put("headers", JSONObject().put("X-Token", "unchanged"))
                .put("downloadSettings", JSONObject(download.toString()))
            val stream = JSONObject().put("network", network).put("method", method).put("xhttpSettings", xhttp)
            val prepared = prepare(config(outbound().put("streamSettings", stream)))
            assertEquals(if (active) setOf("proxy.test", "download.test") else setOf("proxy.test"), prepared.bootstrapHostnames)
            if (!active) assertEquals(xhttp.toString(), JSONObject(prepared.configJson).getJSONArray("outbounds").getJSONObject(0)
                .getJSONObject("streamSettings").getJSONObject("xhttpSettings").toString())
        }
    }

    @Test fun dormantPrimaryAddressIsRetainedWhileXdriveAndIndependentDownloadArePinned() {
        val ws = JSONObject().put("network", "ws").put("address", "dormant.invalid")
            .put("wsSettings", JSONObject().put("path", "/preserved"))
        val prepared = AndroidTunnelDnsPolicy.prepare(config(outbound().put("streamSettings", ws)).toString(), "proxy") {
            assertEquals("A dormant primary stream address must not bootstrap", "proxy.test", it)
            listOf("192.0.2.17")
        }
        assertEquals(setOf("proxy.test"), prepared.bootstrapHostnames)
        assertEquals("dormant.invalid", JSONObject(prepared.configJson).getJSONArray("outbounds").getJSONObject(0)
            .getJSONObject("streamSettings").getString("address"))
        val download = JSONObject().put("address", "download.test").put("network", "xhttp")
            .put("xhttpSettings", JSONObject().put("path", "/download"))
        val xhttp = JSONObject().put("network", "xhttp").put("address", "dormant.invalid")
            .put("xhttpSettings", JSONObject().put("downloadSettings", download))
        assertEquals(setOf("proxy.test", "download.test"), prepare(config(outbound().put("streamSettings", xhttp))).bootstrapHostnames)
        val xdrive = JSONObject().put("network", "tcp").put("method", "xdrive").put("address", "xdrive.test")
        assertEquals(setOf("proxy.test", "xdrive.test"), prepare(config(outbound("vless").put("streamSettings", xdrive))).bootstrapHostnames)
    }

    @Test fun downloadSocketNullMatchesAbsenceWithoutEagerParentInheritance() {
        for (penetrate in listOf<Boolean?>(null, false, true)) {
            val parent = JSONObject().put("dialerProxy", "caller-chain").put("interface", "caller-interface")
                .put("tcpKeepAliveIdle", 45).put("mark", 13)
            if (penetrate != null) parent.put("penetrate", penetrate)
            val explicit = JSONObject().put("dialerProxy", "child-chain").put("interface", "child-interface")
                .put("tcpKeepAliveIdle", 9)
            for (child in listOf<Any?>(null, JSONObject.NULL, JSONObject(), explicit)) {
                val download = JSONObject().put("address", "download.test").put("network", "xhttp")
                    .put("xhttpSettings", JSONObject().put("path", "/download"))
                if (child != null) download.put("sockopt", child)
                val stream = JSONObject().put("network", "xhttp").put("sockopt", JSONObject(parent.toString()))
                    .put("xhttpSettings", JSONObject().put("extra", JSONObject().put("downloadSettings", download)))
                val input = config(outbound().put("streamSettings", stream)); val before = input.toString()
                val output = JSONObject(prepare(input).configJson).getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")
                val actualParent = output.getJSONObject("sockopt")
                for (key in listOf("dialerProxy", "interface", "tcpKeepAliveIdle", "mark"))
                    assertEquals(parent.get(key), actualParent.get(key))
                assertEquals(parent.has("penetrate"), actualParent.has("penetrate"))
                if (penetrate != null) assertEquals(penetrate, actualParent.getBoolean("penetrate"))
                val actualDownload = output.getJSONObject("xhttpSettings").getJSONObject("extra")
                    .getJSONObject("downloadSettings")
                if (penetrate == true) {
                    // Core replaces this whole policy at runtime, so even its
                    // original absence/null/object representation stays intact.
                    assertEquals(download.has("sockopt"), actualDownload.has("sockopt"))
                    if (download.has("sockopt"))
                        assertEquals(download.get("sockopt").toString(), actualDownload.get("sockopt").toString())
                } else {
                    val actualChild = actualDownload.getJSONObject("sockopt")
                    assertEquals("ForceIP", actualChild.getString("domainStrategy"))
                    if (child === explicit) {
                        for (key in listOf("dialerProxy", "interface", "tcpKeepAliveIdle"))
                            assertEquals(explicit.get(key), actualChild.get(key))
                    } else {
                        assertEquals("No eager caller/private parent-policy copy is allowed", 1, actualChild.length())
                    }
                }
                // Core, not this JSON preparer, performs its penetrate=true
                // runtime override. The explicit child object must survive too.
                assertEquals(before, input.toString())
            }
        }
    }

    @Test fun nonNullFlatShadowsocksAddressWinsLegacyAndMalformedValuesDoNotFallBack() {
        for (address in listOf<Any>("flat.test", "", 42, JSONObject())) {
            val key = "AAAAAAAAAAAAAAAAAAAAAA=="
            val settings = JSONObject().put("address", address).put("port", 443)
                .put("method", "2022-blake3-aes-128-gcm").put("password", key)
                .put("servers", JSONArray().put(JSONObject().put("address", "inactive-legacy.test")
                    .put("port", 443).put("method", "2022-blake3-aes-128-gcm").put("password", key)))
            val input = config(JSONObject().put("protocol", "shadowsocks").put("tag", "proxy").put("settings", settings))
            val before = input.toString()
            val resolved = mutableListOf<String>()
            val action = {
                AndroidTunnelDnsPolicy.prepare(before, "proxy") { host ->
                    assertEquals("Inactive legacy endpoint was selected", "flat.test", host)
                    resolved.add(host); listOf("192.0.2.17")
                }
            }
            if (address == "flat.test") {
                val prepared = action()
                assertEquals(listOf("flat.test"), resolved)
                assertEquals(settings.toString(), JSONObject(prepared.configJson).getJSONArray("outbounds")
                    .getJSONObject(0).getJSONObject("settings").toString())
            } else {
                rejected { action() }
                assertTrue("Malformed flat address issued a lookup", resolved.isEmpty())
            }
            assertEquals(before, input.toString())
        }
    }

    @Test fun nullSocketAddressPortStrategyRetainsCoreDefault() =
        checkSocketAddressPortStrategyCorpus(setOf("null"), includeRefusals = false)

    @Test fun emptySocketAddressPortStrategyRetainsCoreDefault() =
        checkSocketAddressPortStrategyCorpus(setOf("empty"), includeRefusals = false)

    @Test fun sharedSocketAddressPortNoneFormsAndRefusalsKeepRawCallerPolicy() =
        checkSocketAddressPortStrategyCorpus(null, includeRefusals = true)

    private fun checkSocketAddressPortStrategyCorpus(only: Set<String>?, includeRefusals: Boolean) {
        val corpus = JSONObject(requireNotNull(javaClass.getResource("/transport-none.json")).readText())
        val profiles = corpus.getJSONArray("profiles"); val equivalents = corpus.getJSONArray("equivalentValues")
        val refusals = corpus.getJSONArray("refusalValues")
        assertEquals(2, profiles.length()); assertEquals(5, equivalents.length()); assertEquals(3, refusals.length())
        fun at(root: JSONObject, path: JSONArray): JSONObject {
            var current: Any = root
            for (index in 0 until path.length())
                current = if (current is JSONArray) current.get(path.getString(index).toInt()) else (current as JSONObject).get(path.getString(index))
            return current as JSONObject
        }
        fun retained(label: String, expected: Any?, actual: Any?) {
            when (expected) {
                is JSONObject -> expected.keys().forEach { key ->
                    val output = actual as JSONObject
                    // This existing adapter policy is separate from the raw
                    // address/port strategy spelling under test.
                    if (key != "domainStrategy" || output.opt(key) != "ForceIP") retained(label, expected.get(key), output.get(key))
                }
                is JSONArray -> {
                    assertEquals(label, expected.length(), (actual as JSONArray).length())
                    for (index in 0 until expected.length()) retained(label, expected.get(index), actual.get(index))
                }
                else -> assertEquals(label, expected, actual)
            }
        }
        for (profileIndex in 0 until profiles.length()) {
            val profile = profiles.getJSONObject(profileIndex); val paths = profile.getJSONArray("sockoptPaths")
            for (group in if (includeRefusals) listOf("equivalentValues", "refusalValues") else listOf("equivalentValues")) {
                val variants = corpus.getJSONArray(group)
                for (variantIndex in 0 until variants.length()) {
                    val variant = variants.getJSONObject(variantIndex)
                    if (only != null && variant.getString("name") !in only) continue
                    val label = profile.getString("name") + "/" + variant.getString("name")
                    val input = JSONObject(profile.getJSONObject("config").toString())
                    val pathCount = if (variant.optString("applyTo") == "primary") 1 else paths.length()
                    for (pathIndex in 0 until pathCount) {
                        val options = at(input, paths.getJSONArray(pathIndex))
                        if (variant.getBoolean("present")) options.put("addressPortStrategy", variant.get("value"))
                        else options.remove("addressPortStrategy")
                    }
                    val before = input.toString(); val resolved = mutableListOf<String>()
                    val action = {
                        AndroidTunnelDnsPolicy.prepare(before, "proxy", environment = { error("Literal source has no environment references") }) { name ->
                            resolved.add(name); assertEquals("endpoint.invalid", name); listOf("192.0.2.17")
                        }
                    }
                    if (group == "refusalValues") {
                        rejected { action() }
                        assertTrue("$label queried DNS before rejecting an unsupported strategy", resolved.isEmpty())
                    } else {
                        val prepared = action(); val actual = JSONObject(prepared.configJson)
                        assertEquals(label, listOf("endpoint.invalid"), resolved)
                        assertEquals(label, setOf("endpoint.invalid"), prepared.bootstrapHostnames)
                        for (pathIndex in 0 until paths.length()) {
                            val sourceOptions = at(input, paths.getJSONArray(pathIndex)); val actualOptions = at(actual, paths.getJSONArray(pathIndex))
                            assertEquals(label, sourceOptions.has("addressPortStrategy"), actualOptions.has("addressPortStrategy"))
                            if (sourceOptions.has("addressPortStrategy"))
                                assertEquals(label, sourceOptions.get("addressPortStrategy"), actualOptions.get("addressPortStrategy"))
                        }
                        for (outbound in 0 until input.getJSONArray("outbounds").length())
                            retained(label, input.getJSONArray("outbounds").get(outbound), actual.getJSONArray("outbounds").get(outbound))
                        assertEquals(label, input.getJSONObject("custom").toString(), actual.getJSONObject("custom").toString())
                        assertEquals(label, input.getString("remarks"), actual.getString("remarks"))
                    }
                    // Config mode deliberately retains the caller policy for
                    // Core preflight, including invalid values, without pins.
                    val caller = AndroidTunnelDnsPolicy.prepare(before, "config", environment = { error("No caller environment references") }) {
                        error("Config mode must not bootstrap transport endpoints")
                    }
                    val output = JSONObject(caller.configJson)
                    assertEquals(label, input.getJSONObject("dns").toString(), output.getJSONObject("dns").toString())
                    for (outbound in 0 until input.getJSONArray("outbounds").length())
                        assertEquals(label, input.getJSONArray("outbounds").get(outbound).toString(), output.getJSONArray("outbounds").get(outbound).toString())
                    assertTrue(label, caller.bootstrapHostnames.isEmpty()); assertTrue(label, caller.bootstrapAddresses.isEmpty())
                    assertEquals(label, before, input.toString())
                }
            }
        }
    }

    @Test fun sharedMappedIpv4DnsAndRealIpv6RemainCallerCorePolicy() {
        val corpus = JSONObject(requireNotNull(javaClass.getResource("/dns-mapped-addresses.json")).readText())
        assertEquals(3, corpus.getJSONArray("positiveCases").length())
        assertEquals(2, corpus.getJSONArray("nativeRefusalControls").length())
        for (group in listOf("positiveCases", "nativeRefusalControls")) {
            val cases = corpus.getJSONArray(group)
            for (index in 0 until cases.length()) {
                val item = cases.getJSONObject(index); val label = item.getString("name")
                val input = item.getJSONObject("config"); val before = input.toString()
                val prepared = AndroidTunnelDnsPolicy.prepare(before, "config", environment = {
                    error("Literal caller DNS must not read environment")
                }) { error("Mapped or actual IPv6 DNS must not bootstrap transport endpoints") }
                val actual = JSONObject(prepared.configJson)
                for (field in listOf("dns", "inbounds", "remarks", "custom"))
                    assertEquals(label, input.get(field).toString(), actual.get(field).toString())
                val sourceOutbounds = input.getJSONArray("outbounds")
                assertEquals(sourceOutbounds.length() + 1, actual.getJSONArray("outbounds").length())
                for (outbound in 0 until sourceOutbounds.length())
                    assertEquals(label, sourceOutbounds.get(outbound).toString(), actual.getJSONArray("outbounds").get(outbound).toString())
                assertTrue(label, prepared.bootstrapHostnames.isEmpty())
                assertTrue(label, prepared.bootstrapAddresses.isEmpty())
                assertEquals(label, before, input.toString())
                // The two refusal controls apply only to the current desktop
                // family boundary. Android retains its existing Core policy.
            }
        }
    }

    @Test fun sharedLogicalAddressEnvironmentFreezesOnlyEffectiveTypedFields() {
        val cases = JSONArray(requireNotNull(javaClass.getResource("/logical-addresses.json")).readText())
        assertEquals(4, cases.length())
        for (index in 0 until cases.length()) for (policy in listOf("config", "proxy")) {
            val item = cases.getJSONObject(index); val label = item.getString("name") + "/" + policy
            val original = item.getJSONObject("config"); val originalBefore = original.toString()
            val input = JSONObject(originalBefore)
            // The corpus is direct-only. This literal proxy supplies only the
            // explicit override's transport, never the logical destination.
            if (policy == "proxy") input.getJSONArray("outbounds").put(outbound(address = "192.0.2.17"))
            val before = input.toString(); val expected = JSONObject(before)
            val bindings = item.getJSONArray("bindings")
            for (bindingIndex in 0 until bindings.length()) {
                val binding = bindings.getJSONObject(bindingIndex); val path = binding.getJSONArray("path")
                var parent: Any = expected
                for (part in 0 until path.length() - 1)
                    parent = if (parent is JSONArray) parent.get(path.getString(part).toInt()) else (parent as JSONObject).get(path.getString(part))
                (parent as JSONObject).put(path.getString(path.length() - 1), binding.getString("value"))
            }
            val environment = item.getJSONObject("environment"); val lookups = mutableListOf<String>()
            val prepared = AndroidTunnelDnsPolicy.prepare(before, policy, environment = { name ->
                lookups.add(name); if (environment.has(name)) environment.getString(name) else null
            }) { error("Logical destinations must not bootstrap physical endpoints") }
            val actual = JSONObject(prepared.configJson)
            for (collection in listOf("inbounds", "outbounds")) {
                // Explicit proxy preparation owns only the appended proxy's
                // stream options; the original imported objects stay exact.
                val source = original.getJSONArray(collection)
                for (entry in 0 until source.length())
                    assertEquals(label, expected.getJSONArray(collection).get(entry).toString(), actual.getJSONArray(collection).get(entry).toString())
            }
            val expectedRules = input.getJSONObject("routing").getJSONArray("rules")
            val actualRules = actual.getJSONObject("routing").getJSONArray("rules")
            for (rule in 0 until expectedRules.length())
                assertEquals(label, expectedRules.get(rule).toString(), actualRules.get(actualRules.length() - expectedRules.length() + rule).toString())
            if (policy == "config") assertEquals(label, input.getJSONObject("dns").toString(), actual.getJSONObject("dns").toString())
            assertEquals(label, input.getJSONObject("custom").toString(), actual.getJSONObject("custom").toString())
            assertEquals(label, input.getString("remarks"), actual.getString("remarks"))
            assertEquals(label, listOf("FLUTTER_VLESS_FIXTURE_LOGICAL_TARGET"), lookups)
            assertTrue(label, prepared.bootstrapHostnames.isEmpty())
            assertEquals(label, if (policy == "proxy") setOf("192.0.2.17") else emptySet<String>(), prepared.bootstrapAddresses)
            assertEquals(label, before, input.toString())
            assertEquals(label, originalBefore, original.toString())
        }
    }

    @Test fun logicalAddressSelectionKeepsSchemaAliasesAndOneSnapshot() {
        val raw = "[ \u00a0127.0.0.1\u3000]"
        for (policy in listOf("config", "proxy")) {
            val input = config(outbound(address = "192.0.2.17"))
            val inboundSettings = JSONObject().put("AdDrEſS", "env:SHARED").put("RewriteAddress", "env:DORMANT")
                .put("port", 18083).put("network", "tcp").put("custom", JSONObject().put("address", "env:OPAQUE"))
            input.getJSONArray("inbounds").put(JSONObject().put("protocol", "DoKoDeMo-DoOr").put("tag", "logical-input")
                .put("settings", inboundSettings).put("sniffing", JSONObject().put("enabled", true)))
            val outboundSettings = JSONObject().put("address", JSONObject.NULL).put("ReWriteAddreſs", "env:SHARED")
                .put("rewritePort", 5353).put("rules", JSONArray().put(JSONObject().put("action", "direct")))
            input.getJSONArray("outbounds").put(JSONObject().put("protocol", "DnS").put("tag", "logical-dns").put("settings", outboundSettings))
            val before = input.toString(); val lookups = mutableListOf<String>()
            val prepared = AndroidTunnelDnsPolicy.prepare(before, policy, environment = { name ->
                lookups.add(name); assertEquals("SHARED", name); assertEquals(1, lookups.size); raw
            }) { error("Logical Address must not issue DNS") }
            val actual = JSONObject(prepared.configJson)
            assertEquals(JSONObject(inboundSettings.toString()).put("AdDrEſS", raw).toString(),
                actual.getJSONArray("inbounds").getJSONObject(1).getJSONObject("settings").toString())
            assertEquals(JSONObject(outboundSettings.toString()).put("ReWriteAddreſs", raw).toString(),
                actual.getJSONArray("outbounds").getJSONObject(2).getJSONObject("settings").toString())
            assertEquals(listOf("SHARED"), lookups)
            assertTrue(prepared.bootstrapHostnames.isEmpty())
            assertEquals(before, input.toString())
        }
    }

    @Test fun logicalAddressesKeepEmptyMissingNestedAndMalformedPrimarySemantics() {
        for (policy in listOf("config", "proxy")) {
            for ((token, values) in listOf("env:logical.address" to mapOf("logical.address" to "", "LOGICAL_ADDRESS" to "wrong.invalid"),
                    "env:MISSING" to emptyMap())) {
                val input = config(outbound(address = "192.0.2.17"))
                val settings = JSONObject().put("address", token).put("rewriteAddress", "env:DORMANT")
                input.getJSONArray("outbounds").put(JSONObject().put("protocol", "dns").put("settings", settings))
                val before = input.toString(); val lookups = mutableListOf<String>()
                val output = JSONObject(AndroidTunnelDnsPolicy.prepare(before, policy, environment = { name -> lookups.add(name); values[name] }) {
                    error("Logical Address must not issue DNS")
                }.configJson)
                val actual = output.getJSONArray("outbounds").getJSONObject(2).getJSONObject("settings")
                assertEquals("", actual.getString("address")); assertEquals("env:DORMANT", actual.getString("rewriteAddress"))
                if (token == "env:logical.address") assertEquals(listOf("logical.address"), lookups)
                assertFalse(lookups.contains("DORMANT")); assertEquals(before, input.toString())
            }
            for (primary in listOf<Any>(42, JSONObject(), "", "ENV:OPAQUE")) {
                val input = config(outbound(address = "192.0.2.17"))
                val settings = JSONObject().put("address", primary).put("rewriteAddress", "env:DORMANT")
                input.getJSONArray("inbounds").put(JSONObject().put("protocol", "tunnel").put("settings", settings))
                val before = input.toString()
                val output = JSONObject(AndroidTunnelDnsPolicy.prepare(before, policy, environment = { error("Nonnull primary must not expand the dormant alias") }).configJson)
                assertEquals(settings.toString(), output.getJSONArray("inbounds").getJSONObject(1).getJSONObject("settings").toString())
                assertEquals(before, input.toString())
            }
            val nested = config(outbound(address = "192.0.2.17"))
            nested.getJSONArray("inbounds").put(JSONObject().put("protocol", "tunnel")
                .put("settings", JSONObject().put("address", JSONObject.NULL).put("rewriteAddress", "env:FIRST")))
            val before = nested.toString(); val lookups = mutableListOf<String>()
            rejected { AndroidTunnelDnsPolicy.prepare(before, policy, environment = { name -> lookups.add(name); "env:SECOND" }) }
            assertEquals(listOf("FIRST"), lookups); assertEquals(before, nested.toString())
        }
    }

    @Test fun sharedRootDnsAddressEnvironmentMatchesLiteralDnsAndKeepsOpaqueFields() {
        val cases = JSONArray(requireNotNull(javaClass.getResource("/dns-addresses.json")).readText())
        assertEquals(3, cases.length())
        for (index in 0 until cases.length()) {
            val item = cases.getJSONObject(index); val label = item.getString("name")
            val input = item.getJSONObject("config"); val before = input.toString()
            val expected = JSONObject(before); val bindings = item.getJSONArray("bindings")
            for (bindingIndex in 0 until bindings.length()) {
                val binding = bindings.getJSONObject(bindingIndex); val path = binding.getJSONArray("path")
                var parent: Any = expected
                for (part in 0 until path.length() - 1)
                    parent = if (parent is JSONArray) parent.get(path.getString(part).toInt()) else (parent as JSONObject).get(path.getString(part))
                if (parent is JSONArray) parent.put(path.getString(path.length() - 1).toInt(), binding.getString("value"))
                else (parent as JSONObject).put(path.getString(path.length() - 1), binding.getString("value"))
            }
            val environment = item.getJSONObject("environment"); val lookups = mutableListOf<String>()
            val prepared = AndroidTunnelDnsPolicy.prepare(before, "config", environment = { name ->
                lookups.add(name); if (environment.has(name)) environment.getString(name) else null
            }) { error("Root DNS binding must not bootstrap endpoints") }
            val actual = JSONObject(prepared.configJson)
            assertEquals(label, expected.getJSONObject("dns").toString(), actual.getJSONObject("dns").toString())
            assertEquals(label, input.getJSONObject("custom").toString(), actual.getJSONObject("custom").toString())
            assertEquals(label, input.getString("remarks"), actual.getString("remarks"))
            for (outboundIndex in 0 until input.getJSONArray("outbounds").length())
                assertEquals(label, input.getJSONArray("outbounds").get(outboundIndex).toString(), actual.getJSONArray("outbounds").get(outboundIndex).toString())
            assertTrue(label, prepared.bootstrapHostnames.isEmpty())
            assertTrue(label, prepared.bootstrapAddresses.isEmpty())
            assertTrue(label, lookups.groupingBy { it }.eachCount().values.all { it == 1 })
            assertFalse("Embedded env: URL/tag/remarks/custom text is opaque", lookups.contains("FLUTTER_VLESS_FIXTURE_DNS_OPAQUE"))
            assertEquals(label, before, input.toString())
        }
    }

    @Test fun rootDnsAddressBindingKeepsSchemaSpellingHostKeysOrderAndOneSnapshot() {
        val dns = JSONObject().put("ClIeNtIp", "env:SHARED")
            .put("serverſ", JSONArray().put("env:SHARED").put(JSONObject().put("AdDrEsS", "env:SHARED")
                .put("ClientIP", "env:SHARED").put("tag", "env:OPAQUE")))
            .put("Hoſts", JSONObject().put("full:first.invalid", "env:SHARED")
                .put("env:OPAQUE", JSONArray().put("env:SHARED").put("alias.invalid")))
            .put("custom", JSONObject().put("address", "env:OPAQUE"))
        val input = config(outbound(address = "env:OUTBOUND_OPAQUE")).apply { remove("dns"); put("dNſ", dns) }
        val before = input.toString(); val lookups = mutableListOf<String>()
        val prepared = AndroidTunnelDnsPolicy.prepare(before, "config", environment = { name ->
            lookups.add(name); assertEquals("SHARED", name); assertEquals(1, lookups.size); "127.0.0.1"
        }) { error("No endpoint lookup in config mode") }
        val expected = JSONObject(dns.toString()).put("ClIeNtIp", "127.0.0.1")
        expected.getJSONArray("serverſ").put(0, "127.0.0.1").getJSONObject(1)
            .put("AdDrEsS", "127.0.0.1").put("ClientIP", "127.0.0.1")
        expected.getJSONObject("Hoſts").put("full:first.invalid", "127.0.0.1")
            .getJSONArray("env:OPAQUE").put(0, "127.0.0.1")
        val actual = JSONObject(prepared.configJson)
        assertEquals(expected.toString(), actual.getJSONObject("dNſ").toString())
        assertEquals(listOf("SHARED"), lookups)
        assertEquals(input.getJSONArray("outbounds").getJSONObject(0).toString(), actual.getJSONArray("outbounds").getJSONObject(0).toString())
        assertEquals(before, input.toString())
    }

    @Test fun rootDnsEmptyMissingAndNestedEnvironmentKeepsCoreOnePassSemantics() {
        for ((token, values) in listOf("env:dns.address" to mapOf("dns.address" to "", "DNS_ADDRESS" to "wrong.invalid"),
                "env:MISSING" to emptyMap())) {
            val input = config(outbound()).put("dns", JSONObject().put("servers", JSONArray().put(token)))
            val before = input.toString(); val lookups = mutableListOf<String>()
            val output = JSONObject(AndroidTunnelDnsPolicy.prepare(before, "config", environment = { name -> lookups.add(name); values[name] }).configJson)
            assertEquals("", output.getJSONObject("dns").getJSONArray("servers").getString(0))
            if (token == "env:dns.address") assertEquals(listOf("dns.address"), lookups)
            assertEquals(before, input.toString())
        }
        val nested = config(outbound()).put("dns", JSONObject().put("hosts", JSONObject().put("full:owned.invalid", "env:FIRST")))
        val before = nested.toString(); val lookups = mutableListOf<String>()
        rejected { AndroidTunnelDnsPolicy.prepare(before, "config", environment = { name -> lookups.add(name); "env:SECOND" }) }
        assertEquals(listOf("FIRST"), lookups)
        assertEquals(before, nested.toString())
        // Explicit proxy mode intentionally discards caller root DNS.
        val proxy = AndroidTunnelDnsPolicy.prepare(before, "proxy", environment = { error("Discarded DNS must not read environment") }) { listOf("192.0.2.17") }
        assertEquals(setOf("proxy.test"), proxy.bootstrapHostnames)
        assertEquals(before, nested.toString())
    }

    @Test fun environmentFakeDnsIsBoundBeforeActiveDetectionForScalarAndObjectServers() {
        for (resolved in listOf("fakedns", "FakeDNS", "fakednſ", " \u00a0fakedns\u3000", "[ \u00a0fakedns\u3000]")) {
            for (server in listOf<Any>("env:ENGINE", JSONObject().put("AdDrEsS", "env:ENGINE"))) {
                val input = config(outbound()).put("dns", JSONObject().put("servers", JSONArray().put(server)))
                val before = input.toString()
                val prepared = AndroidTunnelDnsPolicy.prepare(before, "config", environment = { resolved }) { error("No physical lookup for FakeDNS") }
                assertTrue(AndroidTunnelDnsPolicy.fakeDnsActive(JSONObject(prepared.configJson)))
                assertEquals(before, input.toString())
            }
        }
    }

    @Test fun sharedEndpointAddressEnvironmentFreezesOnlySelectedTypedAddresses() {
        val cases = JSONArray(requireNotNull(javaClass.getResource("/endpoint-addresses.json")).readText())
        assertEquals(3, cases.length())
        fun value(root: Any, path: List<String>): Any = path.fold(root) { item, part ->
            if (item is JSONArray) item.get(part.toInt()) else (item as JSONObject).get(part)
        }
        fun retained(expected: Any?, actual: Any?) {
            when (expected) {
                is JSONObject -> expected.keys().forEach { key -> retained(expected.get(key), (actual as JSONObject).get(key)) }
                is JSONArray -> {
                    assertEquals(expected.length(), (actual as JSONArray).length())
                    for (index in 0 until expected.length()) retained(expected.get(index), actual.get(index))
                }
                else -> assertEquals(expected, actual)
            }
        }
        for (index in 0 until cases.length()) {
            val item = cases.getJSONObject(index); val label = item.getString("name")
            val input = item.getJSONObject("config"); val before = input.toString()
            val environment = item.getJSONObject("environment"); val lookups = mutableListOf<String>()
            val resolved = mutableListOf<String>()
            val prepared = AndroidTunnelDnsPolicy.prepare(before, "proxy", environment = { name ->
                lookups.add(name); if (environment.has(name)) environment.getString(name) else null
            }) { name -> resolved.add(name); listOf("192.0.2.17") }
            assertEquals(label, listOf("endpoint.invalid"), resolved)
            assertEquals(label, setOf("endpoint.invalid"), prepared.bootstrapHostnames)
            assertTrue("Structural/resolving passes must share a lookup snapshot", lookups.groupingBy { it }.eachCount().values.all { it == 1 })
            val expected = JSONObject(before)
            val addresses = item.getJSONObject("resolvedAddresses")
            addresses.keys().forEach { path ->
                val parts = path.split('.')
                (value(expected, parts.dropLast(1)) as JSONObject).put(parts.last(), addresses.getString(path))
            }
            val actual = JSONObject(prepared.configJson)
            val expectedOutbounds = expected.getJSONArray("outbounds")
            for (outboundIndex in 0 until expectedOutbounds.length())
                retained(expectedOutbounds.get(outboundIndex), actual.getJSONArray("outbounds").get(outboundIndex))
            assertEquals(label, input.getJSONObject("custom").toString(), actual.getJSONObject("custom").toString())
            assertEquals(label, input.getString("remarks"), actual.getString("remarks"))
            val caller = AndroidTunnelDnsPolicy.prepare(before, "config", environment = { error("Config mode must not read endpoint environment") }) {
                error("Config mode must not bootstrap endpoints")
            }
            val callerJson = JSONObject(caller.configJson)
            assertEquals(label, input.getJSONObject("dns").toString(), callerJson.getJSONObject("dns").toString())
            for (outboundIndex in 0 until expectedOutbounds.length())
                assertEquals(label, input.getJSONArray("outbounds").get(outboundIndex).toString(),
                    callerJson.getJSONArray("outbounds").get(outboundIndex).toString())
            assertEquals(label, before, input.toString())
        }
    }

    @Test fun endpointEnvironmentSnapshotPreservesRawValueAndIgnoresUntypedStrings() {
        val stream = JSONObject().put("network", "ws").put("address", "env:DORMANT")
            .put("tlsSettings", JSONObject().put("serverName", "env:SNI"))
            .put("wsSettings", JSONObject().put("path", "/env:PATH").put("headers", JSONObject().put("Host", "env:HOST")))
        val input = config(outbound(address = "env:ENDPOINT").put("streamSettings", stream))
        val before = input.toString(); val lookups = mutableListOf<String>(); val resolved = mutableListOf<String>()
        val prepared = AndroidTunnelDnsPolicy.prepare(before, "proxy", environment = { name ->
            lookups.add(name); if (name == "ENDPOINT" && lookups.size == 1) "Endpoint.Invalid." else error("Repeated or untyped environment lookup")
        }) { name -> resolved.add(name); listOf("192.0.2.17") }
        val output = JSONObject(prepared.configJson).getJSONArray("outbounds").getJSONObject(0)
        assertEquals(listOf("ENDPOINT"), lookups)
        assertEquals(listOf("endpoint.invalid"), resolved)
        assertEquals("Endpoint.Invalid.", output.getJSONObject("settings").getJSONArray("servers").getJSONObject(0).getString("address"))
        for (key in listOf("address", "tlsSettings", "wsSettings"))
            assertEquals(stream.get(key).toString(), output.getJSONObject("streamSettings").get(key).toString())
        assertEquals(before, input.toString())
        val wireguard = JSONObject().put("tag", "proxy").put("protocol", "wireguard")
            .put("settings", JSONObject().put("peers", JSONArray().put(JSONObject().put("endpoint", "env:WIREGUARD"))))
        rejected {
            AndroidTunnelDnsPolicy.prepare(config(wireguard).toString(), "proxy", environment = { error("WireGuard endpoint is a plain String") }) {
                error("No invented WireGuard target may be resolved")
            }
        }
    }

    @Test fun typedEndpointCoreAddressViewKeepsRawBracketsAndGoWhitespace() {
        val raw = "[ \u00a0127.0.0.1\u3000]"
        for (sourceAddress in listOf(raw, "env:PHYSICAL")) {
            val download = JSONObject().put("address", sourceAddress).put("network", "xhttp")
                .put("xhttpSettings", JSONObject().put("path", "/download"))
            val stream = JSONObject().put("network", "xhttp")
                .put("xhttpSettings", JSONObject().put("downloadSettings", download))
            val input = config(outbound(address = sourceAddress).put("streamSettings", stream))
            val before = input.toString()
            val prepared = AndroidTunnelDnsPolicy.prepare(before, "proxy", environment = { name ->
                assertEquals("PHYSICAL", name); raw
            }) { error("Core parsed IP literals must not invoke DNS") }
            assertTrue(prepared.bootstrapHostnames.isEmpty())
            assertEquals(setOf("127.0.0.1"), prepared.bootstrapAddresses)
            val output = JSONObject(prepared.configJson).getJSONArray("outbounds").getJSONObject(0)
            assertEquals(raw, output.getJSONObject("settings").getJSONArray("servers").getJSONObject(0).getString("address"))
            assertEquals(raw, output.getJSONObject("streamSettings").getJSONObject("xhttpSettings")
                .getJSONObject("downloadSettings").getString("address"))
            assertEquals(before, input.toString())
        }
    }

    @Test fun typedAddressDoesNotStripBracketsAgainAfterGoWhitespaceTrim() {
        for (raw in listOf(" [127.0.0.1] ", " [::1] ")) {
            for (sourceAddress in listOf(raw, "env:PHYSICAL")) {
                val input = config(outbound(address = sourceAddress)); val before = input.toString()
                rejected {
                    AndroidTunnelDnsPolicy.prepare(before, "proxy", environment = { raw }) {
                        error("Core parsed a bracketed DOMAIN; never reinterpret it as an IP")
                    }
                }
                assertEquals(before, input.toString())
            }
        }
    }

    @Test fun missingEmptyAndNestedEndpointEnvironmentNeverInventsFallbackOrRecurses() {
        for ((raw, environment) in listOf(
            "env:endpoint.name" to mapOf("endpoint.name" to "", "ENDPOINT_NAME" to "wrong.invalid"),
            "env:MISSING" to emptyMap(), "env:FIRST" to mapOf("FIRST" to "env:SECOND", "SECOND" to "wrong.invalid"),
            "ENV:ENDPOINT" to mapOf("ENDPOINT" to "wrong.invalid"),
            " env:ENDPOINT" to mapOf("ENDPOINT" to "wrong.invalid"))) {
            val input = config(outbound(address = raw)); val before = input.toString(); val lookups = mutableListOf<String>()
            rejected {
                AndroidTunnelDnsPolicy.prepare(before, "proxy", environment = { name -> lookups.add(name); environment[name] }) {
                    error("Invalid effective endpoint must fail before DNS")
                }
            }
            assertFalse(lookups.contains("SECOND"))
            if (raw == "env:endpoint.name") assertEquals(listOf("endpoint.name"), lookups)
            if (!raw.startsWith("env:")) assertTrue(lookups.isEmpty())
            val caller = JSONObject(AndroidTunnelDnsPolicy.prepare(before, "config", environment = { error("No config-mode environment lookup") }).configJson)
            assertEquals(input.getJSONArray("outbounds").getJSONObject(0).toString(), caller.getJSONArray("outbounds").getJSONObject(0).toString())
            assertEquals(before, input.toString())
        }
    }

    @Test fun sharedPinnedCoreProtocolCorpusPreservesCallerOutboundsAndTransportFields() {
        val cases = JSONArray(requireNotNull(javaClass.getResource("/protocols.json")).readText())
        assertEquals("Expected the complete shared protocol corpus", 9, cases.length())
        fun retained(label: String, expected: Any?, actual: Any?) {
            when (expected) {
                is JSONObject -> {
                    assertTrue(label, actual is JSONObject)
                    expected.keys().forEach { key ->
                        assertTrue("$label/$key missing", (actual as JSONObject).has(key))
                        retained("$label/$key", expected.get(key), actual.get(key))
                    }
                }
                is JSONArray -> {
                    assertTrue(label, actual is JSONArray)
                    assertEquals(label, expected.length(), (actual as JSONArray).length())
                    for (index in 0 until expected.length()) retained("$label/$index", expected.get(index), actual.get(index))
                }
                else -> assertEquals(label, expected, actual)
            }
        }
        for (index in 0 until cases.length()) {
            val item = cases.getJSONObject(index); val label = item.getString("name")
            val input = item.getJSONObject("config"); val before = input.toString()
            val resolved = mutableListOf<String>()
            val prepared = AndroidTunnelDnsPolicy.prepare(before, "proxy") { hostname ->
                assertEquals("$label attempted to bootstrap an inactive or logical name", "endpoint.invalid", hostname)
                resolved.add(hostname); listOf("192.0.2.17")
            }
            assertEquals(label, listOf("endpoint.invalid"), resolved)
            val expected = input.getJSONArray("outbounds")
            val actual = JSONObject(prepared.configJson).getJSONArray("outbounds")
            for (outboundIndex in 0 until expected.length()) {
                val original = expected.getJSONObject(outboundIndex)
                val output = actual.getJSONObject(outboundIndex)
                assertEquals(label, original.opt("protocol"), output.opt("protocol"))
                assertEquals(label, original.opt("tag"), output.opt("tag"))
                assertEquals(label, original.optJSONObject("settings")?.toString(), output.optJSONObject("settings")?.toString())
                // Every imported TLS, Host, credential and transport field must
                // survive. Only new native protection fields may be appended.
                retained(label, original, output)
                val stream = original.optJSONObject("streamSettings") ?: continue
                if (!stream.isNull("xhttpSettings") && stream.has("splithttpSettings"))
                    assertEquals(label, stream.get("splithttpSettings").toString(),
                        output.getJSONObject("streamSettings").get("splithttpSettings").toString())
                val xhttp = stream.optJSONObject("xhttpSettings")
                if (xhttp != null && xhttp.has("extra") && xhttp.isNull("extra"))
                    assertEquals(label, xhttp.toString(), output.getJSONObject("streamSettings").getJSONObject("xhttpSettings").toString())
            }
            if (label == "vless_xhttp_penetrating_download") {
                assertEquals(label, setOf("endpoint.invalid"), prepared.bootstrapHostnames)
                assertEquals(label, setOf("192.0.2.17"), prepared.bootstrapAddresses)
                val stream = actual.getJSONObject(0).getJSONObject("streamSettings")
                val parent = stream.getJSONObject("sockopt")
                val child = stream.getJSONObject("xhttpSettings").getJSONObject("extra")
                    .getJSONObject("downloadSettings").getJSONObject("sockopt")
                assertTrue(label, parent.getBoolean("penetrate"))
                assertEquals(label, 30, parent.getInt("tcpKeepAliveIdle"))
                assertFalse("Parent policy must not be copied into the source child", child.has("penetrate"))
                assertEquals(label, "dormant-download-handler", child.getString("dialerProxy"))
                assertEquals(label, 7, child.getInt("tcpKeepAliveIdle"))
                // Config mode preserves the caller DNS root; the explicit proxy
                // mode above intentionally owns its DNS override and bootstrap.
                val callerRoot = AndroidTunnelDnsPolicy.prepare(before, "config") {
                    fail("Config mode must not bootstrap XHTTP endpoints")
                    emptyList()
                }
                val callerOutput = JSONObject(callerRoot.configJson)
                assertEquals(label, input.getJSONObject("dns").toString(), callerOutput.getJSONObject("dns").toString())
                for (outboundIndex in 0 until expected.length())
                    assertEquals(label, expected.get(outboundIndex).toString(),
                        callerOutput.getJSONArray("outbounds").get(outboundIndex).toString())
                assertTrue(label, callerRoot.bootstrapHostnames.isEmpty())
                assertTrue(label, callerRoot.bootstrapAddresses.isEmpty())
            }
            assertEquals(label, before, input.toString())
        }
    }

    @Test fun conflictingNativeCaseAliasesAreRejected() {
        val variants = listOf(
            config(outbound()).put("Outbounds", JSONArray().put(outbound(address = "hidden.test"))),
            config(outbound().put("Settings", JSONObject().put("address", "hidden.test"))),
            config(outbound().put("streamSettings", JSONObject().put("sockopt", JSONObject().put("domainStrategy", "ForceIP").put("DomainStrategy", "AsIs")))),
            config(outbound().put("streamSettings", JSONObject().put("xhttpSettings", JSONObject()).put("xHTTPSettings", JSONObject()))),
            config(outbound().put("streamSettings", JSONObject().put("network", "xhttp").put("xhttpSettings", JSONObject().put("extra", JSONObject()).put("Extra", JSONObject()))))
        )
        variants.forEach { rejected { prepare(it) } }
        val capitalized = config(outbound()).also { it.put("Outbounds", it.remove("outbounds")) }
        assertEquals(listOf("10.0.85.53"), prepare(capitalized).systemDnsServers)
    }

    @Test fun malformedEndpointsNeverTriggerImplicitResolution() {
        for (host in listOf("", "bad host.test", "https://proxy.test", "192.168.001.1", "2130706433", "[2001:db8::1", "fe80::1%wlan0")) {
            rejected { AndroidTunnelDnsPolicy.prepare(config(outbound(address = host)).toString(), "proxy") { error("invalid hostname resolved") } }
        }
    }
}
