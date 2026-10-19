package com.github.tfox.flutter_vless.xray.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class AndroidTunnelDnsPolicyTest {
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
            assertEquals(listOf("198.18.0.2"), prepared.systemDnsServers)
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
            assertEquals("198.18.0.2/32", rules.getJSONObject(1).getJSONArray("ip").getString(0))
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
        assertEquals("198.18.0.2/32", bridge.getJSONArray("ip").getString(0))
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

    @Test fun configModeRejectsFakeDnsBeforeInstallingAnIncompatibleIpv4Bridge() {
        for (key in listOf("fakeDns", "FAKEDNS", "fakeDnſ")) {
            for (value in listOf<Any>(JSONObject(), JSONArray())) {
                val source = config(outbound()).put(key, value).toString()
                rejected { AndroidTunnelDnsPolicy.prepare(source) }
            }
        }
        for (address in listOf("fakedns", "FakeDNS", "fakednſ")) {
            for (server in listOf<Any>(address, JSONObject().put("Addreſſ", address))) {
                val input = config(outbound()).put("DNS", JSONObject().put("SerVerſ", JSONArray().put(server)))
                input.remove("dns")
                rejected { AndroidTunnelDnsPolicy.prepare(input.toString()) }
            }
        }
        // A null engine is not a configured Core app. Hosts may legitimately
        // contain this word; do not use arbitrary recursive string matching.
        val allowed = config(outbound()).put("fakeDns", JSONObject.NULL)
        allowed.getJSONObject("dns").put("hosts", JSONObject().put("fakedns", "192.0.2.1"))
        AndroidTunnelDnsPolicy.prepare(allowed.toString())
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
        invalid.add(config(outbound(address = "198.18.0.2")))
        invalid.add(config(outbound(address = "::ffff:198.18.0.2")))
        invalid.add(config(outbound()).also {
            it.getJSONObject("routing").getJSONArray("rules").put(JSONObject().put("ip", JSONArray().put("198.18.0.2/32")).put("outboundTag", "direct"))
        })
        for (input in invalid) rejected {
            AndroidTunnelDnsPolicy.prepare(input.toString(), "proxy") { error("invalid candidate must not perform bootstrap") }
        }
    }

    @Test fun exclusionsContainingVirtualDnsFailWhileOtherDirectExclusionsRemainAvailable() {
        for (route in listOf("198.18.0.2", "198.18.0.2/32", "198.18.0.0/15", "0.0.0.0/0")) {
            assertFalse(AndroidTunnelDnsPolicy.allowsRouteExclusions(listOf(route)))
            rejected { AndroidTunnelDnsPolicy.prepare(config(outbound()).toString(), "proxy", excludedRoutes = listOf(route)) }
        }
        assertTrue(AndroidTunnelDnsPolicy.allowsRouteExclusions(listOf("192.168.0.0/16", "198.18.0.1/32", "2001:db8::/32")))
    }

    @Test fun bootstrapFailureDoesNotModifyInputOrFallBackToOsDns() {
        val input = config(outbound())
        val original = input.toString()
        rejected { AndroidTunnelDnsPolicy.prepare(original, "proxy") { emptyList() } }
        rejected { AndroidTunnelDnsPolicy.prepare(original, "proxy") { throw java.net.UnknownHostException("sensitive-endpoint") } }
        rejected { AndroidTunnelDnsPolicy.prepare(original, "proxy") { listOf("198.18.0.2") } }
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
                    .put("downloadSettings", JSONObject().put("Address", "outer-download.test"))
                    .put("Extra", JSONObject().put("DownloadSettings", JSONObject().put("address", "extra-download.test")
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
            .put("downloadSettings", JSONObject().put("address", "active-download.test")))
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
        val split = JSONObject().put("downloadSettings", JSONObject().put("address", "active-split.test"))
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
        val download = JSONObject().put("address", "download.test")
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
                val actualChild = output.getJSONObject("xhttpSettings").getJSONObject("extra")
                    .getJSONObject("downloadSettings").getJSONObject("sockopt")
                assertEquals("ForceIP", actualChild.getString("domainStrategy"))
                if (child === explicit) {
                    for (key in listOf("dialerProxy", "interface", "tcpKeepAliveIdle"))
                        assertEquals(explicit.get(key), actualChild.get(key))
                } else {
                    assertEquals("No eager caller/private parent-policy copy is allowed", 1, actualChild.length())
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

    @Test fun sharedPinnedCoreProtocolCorpusPreservesCallerOutboundsAndTransportFields() {
        val cases = JSONArray(requireNotNull(javaClass.getResource("/protocols.json")).readText())
        assertEquals("Expected the complete shared protocol corpus", 8, cases.length())
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
        assertEquals(listOf("198.18.0.2"), prepare(capitalized).systemDnsServers)
    }

    @Test fun malformedEndpointsNeverTriggerImplicitResolution() {
        for (host in listOf("", "bad host.test", "https://proxy.test", "192.168.001.1", "2130706433", "[2001:db8::1", "fe80::1%wlan0")) {
            rejected { AndroidTunnelDnsPolicy.prepare(config(outbound(address = host)).toString(), "proxy") { error("invalid hostname resolved") } }
        }
    }
}
