package com.github.tfox.flutter_vless.xray.core

import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import java.io.File
import java.util.Locale
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Actual file-only prepare/build path; callbacks cannot create a socket or resolve DNS. */
class XrayRoutingAttrsDataTest {
    private fun field(value: JSONObject, name: String): String? = value.keys().asSequence().singleOrNull {
        it.replace('ſ', 's').replace('K', 'k').lowercase(Locale.ROOT) == name
    }

    private fun source(): JSONObject = JSONObject(requireNotNull(javaClass.getResource("/routing-attrs.json")).readText())
        .getJSONObject("config")

    private fun rules(config: JSONObject): JSONArray {
        val routing = config.getJSONObject(requireNotNull(field(config, "routing")))
        return routing.getJSONArray(requireNotNull(field(routing, "rules")))
    }

    private fun attrs(config: JSONObject): JSONObject = (0 until rules(config).length()).map {
        rules(config).getJSONObject(it)
    }.mapNotNull { rule -> field(rule, "attrs")?.let(rule::getJSONObject) }.single()

    private fun build(source: JSONObject): JSONObject {
        val before = source.toString()
        val prepared = AndroidTunnelDnsPolicy.prepare(before,
            environment = { error("Routing attrs must not bind endpoint environment") },
            resolveEndpoint = { error("Routing attrs must not resolve a physical endpoint") })
        assertTrue(prepared.bootstrapHostnames.isEmpty())
        assertTrue(prepared.bootstrapAddresses.isEmpty())
        assertEquals(attrs(source).toString(), attrs(JSONObject(prepared.configJson)).toString())
        val profile = XrayConfig(V2RAY_FULL_JSON_CONFIG = prepared.configJson)
        try {
            return XrayCoreManager.buildRuntimeConfigJson(profile, File("."),
                LocalProxyCredentials("attrs-user", "attrs-secret"), prepared,
                tcpAvailable = { true }, environment = { error("Routing attrs must not bind listener environment") })
        } finally {
            assertEquals("Caller routing source changed", before, source.toString())
            assertEquals(prepared.configJson, profile.V2RAY_FULL_JSON_CONFIG)
        }
    }

    @Test fun sharedRoutingAttrsAreDataThroughActualPreparationAndRuntimeBuild() {
        val source = source()
        val expected = attrs(source).toString()
        assertEquals(expected, attrs(build(source)).toString())
    }

    @Test fun routingAttributeNamesAndRegexCaseDoNotReceiveStreamNormalization() {
        val source = source()
        attrs(source).apply { remove("type"); remove("Origin") }
        val expected = attrs(source).toString()
        val actual = attrs(build(source))
        assertEquals(expected, actual.toString())
        assertEquals("^required$", actual.getString("allowInsecure"))
        assertEquals("^MiXeD$", actual.getString("network"))
        assertEquals("^Alias$", actual.getString("xHTTPSettings"))
    }

    @Test fun foldedRootRulesAndAttrsStillIdentifyOnlyTheCallerDictionary() {
        val source = source()
        val routing = source.remove("routing") as JSONObject
        val rules = routing.remove("rules") as JSONArray
        val rule = rules.getJSONObject(0)
        rule.put("AtTrſ", rule.remove("attrs"))
        routing.put("RuLeſ", rules)
        source.put("RoUtInG", routing)
        val expected = attrs(source).toString()
        assertEquals(expected, attrs(build(source)).toString())
    }

    private fun controlSource(): JSONObject = source().also {
        rules(it).getJSONObject(0).put("attrs", JSONObject().put("user-agent", "^fixture$"))
    }

    @Test fun routingAttrsBoundaryKeepsActualTlsCleanup() {
        val source = controlSource()
        source.getJSONArray("outbounds").getJSONObject(0).put("streamSettings", JSONObject()
            .put("network", "tcp").put("security", "tls")
            .put("tlsSettings", JSONObject().put("serverName", "tls.invalid").put("allowInsecure", true)))
        val tls = build(source).getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")
            .getJSONObject("tlsSettings")
        assertFalse(tls.has("allowInsecure"))
        assertEquals("tls.invalid", tls.getString("serverName"))
    }

    @Test fun actualXicmpAndQuicLocalDnsRemainRefusedOutsideAttrs() {
        val mask = controlSource()
        mask.getJSONArray("outbounds").getJSONObject(0).put("streamSettings", JSONObject()
            .put("network", "tcp").put("finalmask", JSONObject().put("udp", JSONArray().put(
                JSONObject().put("type", "xicmp").put("settings", JSONObject().put("ips", JSONArray().put("192.0.2.9")))))))
        val maskError = assertThrows(IllegalArgumentException::class.java) { build(mask) }
        assertTrue(maskError.message.orEmpty().contains("xicmp"))

        val dns = controlSource()
        dns.getJSONObject("dns").put("servers", JSONArray().put("quic+local://192.0.2.53"))
        val dnsError = assertThrows(IllegalArgumentException::class.java) { build(dns) }
        assertTrue(dnsError.message.orEmpty().contains("quic+local"))
    }

    @Test fun unrelatedAttrsLookalikesRemainUnknownMetadata() {
        val forbidden = JSONObject().put("attrs", JSONObject().put("type", "xicmp"))
        val root = controlSource().put("extension", forbidden)
        assertEquals(root.getJSONObject("extension").toString(), build(root).getJSONObject("extension").toString())

        val routing = controlSource()
        routing.getJSONObject("routing").put("attrs", JSONObject().put("type", "xicmp"))
        assertEquals(routing.getJSONObject("routing").getJSONObject("attrs").toString(),
            build(routing).getJSONObject("routing").getJSONObject("attrs").toString())

        val rule = controlSource()
        rules(rule).getJSONObject(0).put("extension", forbidden)
        val runtime = build(rule)
        assertEquals(rules(rule).length() + 2, rules(runtime).length())
        assertEquals(rules(rule).getJSONObject(0).getJSONObject("extension").toString(),
            rules(runtime).getJSONObject(2).getJSONObject("extension").toString())
    }
}
