package com.github.tfox.flutter_vless.xray.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** The wrapper must not answer AAAA on behalf of Core's unchanged root client. */
class AndroidTunnelDnsIpv6PolicyTest {
    private fun source(strategy: String): JSONObject = JSONObject("""{
      "inbounds":[],"outbounds":[{"protocol":"freedom","tag":"caller-direct"}],
      "dns":{"hosts":{"ipv6-fixture.invalid":"fd26:26:26::2"},
        "servers":[{"address":"tcp://192.0.2.53","domains":["full:ipv6-fixture.invalid"],
          "tag":"caller-server","queryStrategy":"UseIP"}],"tag":"caller-root","queryStrategy":"$strategy"},
      "routing":{"rules":[{"inboundTag":["caller-root","caller-server"],"outboundTag":"caller-direct"}]}
    }""")

    private fun actionFor(rules: JSONArray, type: Int): JSONObject =
        (0 until rules.length()).map(rules::getJSONObject).first { rule ->
            !rule.has("qType") || type.toString() in rule.getString("qType").split(',')
        }

    @Test(timeout = 5000) fun configModeRelaysCallerAaaaThroughCoreWithoutPhysicalFallback() {
        val input = source("UseIP"); val before = input.toString()
        val prepared = AndroidTunnelDnsPolicy.prepare(before, "config") { error("No preparer DNS lookup is permitted") }
        val output = JSONObject(prepared.configJson)
        assertEquals(input.getJSONObject("dns").toString(), output.getJSONObject("dns").toString())
        val relay = output.getJSONArray("outbounds").getJSONObject(1)
        val settings = relay.getJSONObject("settings"); val rules = settings.getJSONArray("rules")
        assertEquals("hijack", actionFor(rules, 1).getString("action"))
        assertEquals("Caller AAAA must reach Core's root client", "hijack", actionFor(rules, 28).getString("action"))
        assertEquals("return", actionFor(rules, 16).getString("action"))
        assertEquals(5, actionFor(rules, 16).getInt("rCode"))
        assertFalse(settings.has("rewriteAddress")); assertFalse(relay.has("streamSettings"))
        assertFalse((0 until rules.length()).any { rules.getJSONObject(it).optString("action") == "direct" })
        assertEquals(before, input.toString())
    }

    @Test(timeout = 5000) fun callerUseIpv4AndUseIpv6StayCoreOwnedRatherThanWrapperAaaaOverrides() {
        for (strategy in listOf("UseIPv4", "UseIPv6")) {
            val input = source(strategy); val before = input.toString()
            val output = JSONObject(AndroidTunnelDnsPolicy.prepare(before).configJson)
            assertEquals(strategy, output.getJSONObject("dns").getString("queryStrategy"))
            assertEquals(input.getJSONObject("dns").toString(), output.getJSONObject("dns").toString())
            val rules = output.getJSONArray("outbounds").getJSONObject(1).getJSONObject("settings").getJSONArray("rules")
            assertEquals("Core must apply $strategy itself", "hijack", actionFor(rules, 28).getString("action"))
            assertEquals(before, input.toString())
        }
    }

    @Test(timeout = 5000) fun explicitProxyRelaysAaaaOnlyThroughItsSelectedProxy() {
        val input = JSONObject("""{"inbounds":[],"outbounds":[{"protocol":"socks","tag":"proxy",
          "settings":{"servers":[{"address":"192.0.2.17","port":1080}]}}],
          "dns":{"queryStrategy":"UseIPv4","servers":["localhost"]}}""")
        val before = input.toString()
        val output = JSONObject(AndroidTunnelDnsPolicy.prepare(before, "proxy", "proxy") {
            error("Literal IPv4 proxy must not invoke DNS bootstrap")
        }.configJson)
        val relay = output.getJSONArray("outbounds").getJSONObject(1)
        val settings = relay.getJSONObject("settings"); val rules = settings.getJSONArray("rules")
        assertEquals("tcp", settings.getString("rewriteNetwork"))
        assertEquals("1.1.1.1", settings.getString("rewriteAddress"))
        assertEquals("proxy", relay.getJSONObject("streamSettings").getJSONObject("sockopt").getString("dialerProxy"))
        assertEquals("Explicit proxy policy must relay AAAA rather than suppress it", "direct", actionFor(rules, 28).getString("action"))
        assertEquals("UseIP", output.getJSONObject("dns").getString("queryStrategy"))
        assertEquals(before, input.toString())
    }

    @Test(timeout = 5000) fun sharedIpv6PayloadCorpusPreservesEachCallerDnsStrategy() {
        val cases = JSONArray(requireNotNull(javaClass.getResource("/ipv6-payload.json")).readText())
        assertEquals(2, cases.length())
        for (index in 0 until cases.length()) {
            val item = cases.getJSONObject(index); val input = item.getJSONObject("config"); val before = input.toString()
            val output = JSONObject(AndroidTunnelDnsPolicy.prepare(before).configJson)
            assertEquals(item.getString("name"), input.getJSONObject("dns").toString(), output.getJSONObject("dns").toString())
            for (outbound in 0 until input.getJSONArray("outbounds").length())
                assertEquals(input.getJSONArray("outbounds").getJSONObject(outbound).toString(), output.getJSONArray("outbounds").getJSONObject(outbound).toString())
            val relay = output.getJSONArray("outbounds").getJSONObject(input.getJSONArray("outbounds").length())
            assertEquals("hijack", actionFor(relay.getJSONObject("settings").getJSONArray("rules"), 28).getString("action"))
            assertEquals(before, input.toString())
        }
    }
}
