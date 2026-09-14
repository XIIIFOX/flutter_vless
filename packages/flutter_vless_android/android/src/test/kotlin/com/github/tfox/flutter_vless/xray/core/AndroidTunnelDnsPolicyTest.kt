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
            assertEquals(2, relayRules.length())
            assertEquals("return", relayRules.getJSONObject(0).getString("action"))
            assertEquals("28", relayRules.getJSONObject(0).getString("qType"))
            assertEquals(0, relayRules.getJSONObject(0).getInt("rCode"))
            assertEquals("direct", relayRules.getJSONObject(1).getString("action"))
            assertEquals("proxy", relay.getJSONObject("streamSettings").getJSONObject("sockopt").getString("dialerProxy"))
            val dns = output.getJSONObject("dns")
            assertEquals("tcp://1.1.1.1", dns.getJSONArray("servers").getString(0))
            assertTrue(dns.getBoolean("disableFallback"))
            assertEquals("192.0.2.17", dns.getJSONObject("hosts").getJSONArray("proxy.test").getString(0))
            val rules = output.getJSONObject("routing").getJSONArray("rules")
            assertEquals("proxy", rules.getJSONObject(0).getString("outboundTag"))
            assertEquals("198.18.0.2/32", rules.getJSONObject(1).getJSONArray("ip").getString(0))
            assertEquals("tcp,udp", rules.getJSONObject(1).getString("network"))
            assertEquals(AndroidTunnelDnsPolicy.RELAY_TAG, rules.getJSONObject(1).getString("outboundTag"))
            assertEquals(originalUserRules.getJSONObject(0).toString(), rules.getJSONObject(2).toString())
            assertEquals(originalUserRules.getJSONObject(1).toString(), rules.getJSONObject(3).toString())
            assertEquals("IPIfNonMatch", output.getJSONObject("routing").getString("domainStrategy"))
        }
    }

    @Test fun configModePreservesExactOriginalDnsAndSkipsBootstrap() {
        val original = "  " + config(outbound()).toString(2) + "\n"
        for (policy in listOf("config")) {
            val prepared = AndroidTunnelDnsPolicy.prepare(original, policy) { error("config mode must not resolve endpoints") }
            assertEquals(original, prepared.configJson)
            assertEquals(listOf("8.8.8.8", "1.1.1.1"), prepared.systemDnsServers)
            assertTrue(prepared.bootstrapHostnames.isEmpty())
        }
        rejected { AndroidTunnelDnsPolicy.prepare(original, "invalid") }
        rejected { AndroidTunnelDnsPolicy.prepare(original, "config", "proxy") }
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

    @Test fun reservedTagsAndVirtualEndpointRoutingConflictsRejectBeforeResolution() {
        val invalid = mutableListOf<JSONObject>()
        for (tag in listOf(AndroidTunnelDnsPolicy.PROXY_TAG, AndroidTunnelDnsPolicy.RELAY_TAG, AndroidTunnelDnsPolicy.UPSTREAM_TAG)) {
            invalid.add(config(outbound(tag = tag)))
            invalid.add(config(outbound()).also { it.getJSONArray("inbounds").getJSONObject(0).put("tag", tag) })
        }
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
            val stream = JSONObject().put("Address", "transport.test")
                .put(transportKey, JSONObject()
                    .put("downloadSettings", JSONObject().put("Address", "outer-download.test"))
                    .put("Extra", JSONObject().put("DownloadSettings", JSONObject().put("address", "extra-download.test")
                        .put("sockopt", JSONObject().put("DomainStrategy", "AsIs")))))
            val prepared = prepare(config(outbound().put("StreamSettings", stream)))
            assertEquals(setOf("proxy.test", "transport.test", "extra-download.test"), prepared.bootstrapHostnames)
            val outputStream = JSONObject(prepared.configJson).getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")
            val transport = outputStream.getJSONObject(if (transportKey == "xHTTPSettings") "xhttpSettings" else "splithttpSettings")
            assertEquals("ForceIP", transport.getJSONObject("extra").getJSONObject("downloadSettings").getJSONObject("sockopt").getString("domainStrategy"))
            stream.getJSONObject(transportKey).remove("Extra")
            val outerPrepared = prepare(config(outbound().put("streamSettings", stream)))
            assertEquals(setOf("proxy.test", "transport.test", "outer-download.test"), outerPrepared.bootstrapHostnames)
            val outerOutput = JSONObject(outerPrepared.configJson).getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")
                .getJSONObject(if (transportKey == "xHTTPSettings") "xhttpSettings" else "splithttpSettings").getJSONObject("downloadSettings")
            assertEquals("ForceIP", outerOutput.getJSONObject("sockopt").getString("domainStrategy"))
        }
        rejected { prepare(config(outbound().put("streamSettings", JSONObject().put("sockopt", JSONObject().put("AddressPortStrategy", "srv"))))) }
    }

    @Test fun conflictingNativeCaseAndXhttpAliasesAreRejected() {
        val variants = listOf(
            config(outbound()).put("Outbounds", JSONArray().put(outbound(address = "hidden.test"))),
            config(outbound().put("Settings", JSONObject().put("address", "hidden.test"))),
            config(outbound().put("streamSettings", JSONObject().put("sockopt", JSONObject().put("domainStrategy", "ForceIP").put("DomainStrategy", "AsIs")))),
            config(outbound().put("streamSettings", JSONObject().put("xhttpSettings", JSONObject()).put("xHTTPSettings", JSONObject()))),
            config(outbound().put("streamSettings", JSONObject().put("xhttpSettings", JSONObject()).put("splithttpSettings", JSONObject()))),
            config(outbound().put("streamSettings", JSONObject().put("xhttpSettings", JSONObject().put("extra", JSONObject()).put("Extra", JSONObject()))))
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
