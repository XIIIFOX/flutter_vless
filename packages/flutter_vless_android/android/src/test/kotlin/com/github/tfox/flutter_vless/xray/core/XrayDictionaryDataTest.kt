package com.github.tfox.flutter_vless.xray.core

import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import java.io.File
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Actual prepare/build data paths only: no Core, commands, listener or service. */
class XrayDictionaryDataTest {
    private val credentials = LocalProxyCredentials("dictionaryuser", "dictionarysecret")

    private fun source(): JSONObject = JSONObject("""{
      "dns":{"servers":["tcp://192.0.2.53:53"],"hosts":{"control.invalid":"192.0.2.8"}},
      "inbounds":[],
      "outbounds":[{"tag":"proxy","protocol":"vless",
        "settings":{"address":"192.0.2.7","port":443,"id":"11111111-1111-4111-8111-111111111111","encryption":"none"},
        "streamSettings":{"network":"ws","wsSettings":{"path":"/dictionary-fixture","headers":{}}}},
        {"tag":"direct","protocol":"freedom"}]
    }""")

    private fun stream(source: JSONObject): JSONObject =
        source.getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")

    private fun build(source: JSONObject): JSONObject {
        val before = source.toString()
        val prepared = AndroidTunnelDnsPolicy.prepare(before,
            environment = { error("Dictionary data must not read endpoint environment") },
            resolveEndpoint = { error("Dictionary data must not resolve an endpoint") })
        assertTrue(prepared.bootstrapHostnames.isEmpty())
        assertTrue(prepared.bootstrapAddresses.isEmpty())
        assertEquals(source.getJSONObject("dns").toString(), JSONObject(prepared.configJson).getJSONObject("dns").toString())
        val profile = XrayConfig(V2RAY_FULL_JSON_CONFIG = prepared.configJson)
        try {
            return XrayCoreManager.buildRuntimeConfigJson(profile, File("."), credentials, prepared,
                tcpAvailable = { true }, environment = { error("Dictionary data must not bind listener environment") })
        } finally {
            assertEquals("The source document must stay immutable on success or refusal", before, source.toString())
            assertEquals(prepared.configJson, profile.V2RAY_FULL_JSON_CONFIG)
        }
    }

    @Test fun dnsHostAliasNamedTypeIsNotAnActiveXicmpMask() {
        val source = source()
        source.getJSONObject("dns").put("hosts", JSONObject("""{"type":"xicmp","xicmp":"192.0.2.9"}"""))
        val expectedDns = source.getJSONObject("dns").toString()
        val runtime = build(source)
        assertEquals(expectedDns, runtime.getJSONObject("dns").toString())
    }

    @Test fun websocketHeadersAreDataEvenWhenTheyLookLikeProtectedFeatures() {
        val source = source()
        val headers = JSONObject("""{"type":"xicmp","Origin":"quic+local://literal.invalid","allowInsecure":"literal-header","network":"MiXeD-CaSe"}""")
        stream(source).getJSONObject("wsSettings").put("headers", headers)
        val runtime = build(source)
        assertEquals(headers.toString(), stream(runtime).getJSONObject("wsSettings").getJSONObject("headers").toString())
    }

    @Test fun websocketOriginIsNotAQuicLocalDnsServer() {
        val source = source()
        val headers = JSONObject().put("Origin", "quic+local://literal.invalid")
        stream(source).getJSONObject("wsSettings").put("headers", headers)
        val runtime = build(source)
        assertEquals(headers.toString(), stream(runtime).getJSONObject("wsSettings").getJSONObject("headers").toString())
    }

    @Test fun websocketHeaderKeysAndValuesDoNotReceiveStreamNormalization() {
        val source = source()
        val headers = JSONObject("""{"allowInsecure":"literal-header","network":"MiXeD-CaSe"}""")
        stream(source).getJSONObject("wsSettings").put("headers", headers)
        val actual = stream(build(source)).getJSONObject("wsSettings").getJSONObject("headers")
        assertTrue("A header named allowInsecure is caller data", actual.has("allowInsecure"))
        assertEquals("literal-header", actual.getString("allowInsecure"))
        assertEquals("MiXeD-CaSe", actual.getString("network"))
        assertEquals(headers.toString(), actual.toString())
    }

    @Test fun foldedWebsocketHeaderPathsOnCallerInputsAndOutputsRemainData() {
        for (inbound in listOf(false, true)) {
            val source = source()
            val headers = JSONObject("""{"type":"xicmp","Origin":"quic+local://literal.invalid","allowInsecure":"literal-header","network":"MiXeD-CaSe"}""")
            val transport = JSONObject().put("network", "ws").put("WſSettings",
                JSONObject().put("path", "/folded-headers").put("HEADERſ", headers))
            if (inbound) {
                source.getJSONArray("inbounds").put(JSONObject()
                    .put("tag", "caller-input").put("listen", "127.0.0.1").put("port", 18081).put("protocol", "vless")
                    .put("settings", JSONObject().put("decryption", "none").put("clients", JSONArray()))
                    .put("ſtreamſettings", transport))
            } else {
                source.getJSONArray("outbounds").getJSONObject(0).apply {
                    remove("streamSettings"); put("ſtreamſettings", transport)
                }
            }
            val runtime = build(source)
            val owner = runtime.getJSONArray(if (inbound) "inbounds" else "outbounds").getJSONObject(0)
            val key = owner.keys().asSequence().single { it.replace('ſ', 's').lowercase() == "streamsettings" }
            val actual = owner.getJSONObject(key).getJSONObject("WſSettings").getJSONObject("HEADERſ")
            assertEquals(headers.toString(), actual.toString())
        }
    }

    @Test fun realStreamAndTlsFieldsStillReceiveCompatibilityNormalization() {
        val source = source()
        stream(source).put("network", "WS").put("security", "tls")
            .put("tlsSettings", JSONObject().put("serverName", "tls.invalid").put("allowInsecure", false))
        val actual = stream(build(source))
        assertEquals("ws", actual.getString("network"))
        assertEquals("tls.invalid", actual.getJSONObject("tlsSettings").getString("serverName"))
        assertFalse(actual.getJSONObject("tlsSettings").has("allowInsecure"))
    }

    @Test fun realXicmpFinalMaskAndQuicLocalDnsRemainRefused() {
        val maskSource = source()
        stream(maskSource).put("finalmask", JSONObject().put("udp", JSONArray().put(
            JSONObject().put("type", "xicmp").put("settings", JSONObject().put("ips", JSONArray().put("192.0.2.9"))))))
        val maskError = assertThrows(IllegalArgumentException::class.java) { build(maskSource) }
        assertTrue(maskError.message.orEmpty().contains("xicmp"))

        val dnsSource = source()
        dnsSource.getJSONObject("dns").put("servers", JSONArray().put("quic+local://192.0.2.53"))
        val dnsError = assertThrows(IllegalArgumentException::class.java) { build(dnsSource) }
        assertTrue(dnsError.message.orEmpty().contains("quic+local"))
    }

    @Test fun unrelatedHeaderLookalikesRemainUnknownMetadata() {
        val forbidden = JSONObject().put("type", "xicmp")
        val nonStreamOwner = source().put("extension", JSONObject().put("headers", forbidden))
        assertEquals(nonStreamOwner.getJSONObject("extension").toString(), build(nonStreamOwner).getJSONObject("extension").toString())

        val wrongTransportPath = source()
        stream(wrongTransportPath).getJSONObject("wsSettings")
            .put("extra", JSONObject().put("headers", forbidden))
        assertEquals(stream(wrongTransportPath).getJSONObject("wsSettings").getJSONObject("extra").toString(),
            stream(build(wrongTransportPath)).getJSONObject("wsSettings").getJSONObject("extra").toString())

        val repeatedExtra = source()
        stream(repeatedExtra).put("xhttpSettings", JSONObject().put("extra", JSONObject()
            .put("extra", JSONObject().put("headers", forbidden))))
        assertEquals(stream(repeatedExtra).getJSONObject("xhttpSettings").toString(),
            stream(build(repeatedExtra)).getJSONObject("xhttpSettings").toString())
    }
}
