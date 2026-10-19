package com.github.tfox.flutter_vless.xray.core

import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import java.io.File
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Actual config preparation/producer with inert environment and port callbacks. */
class XrayOpaqueFieldsDataTest {
    private fun cases(): JSONArray = JSONArray(requireNotNull(javaClass.getResource("/opaque-fields.json")).readText())
    private fun base(): JSONObject = JSONObject(cases().getJSONObject(0).getJSONObject("config").toString()).apply { remove("custom") }
    private fun stream(source: JSONObject): JSONObject = source.getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")
    private fun build(source: JSONObject): JSONObject {
        val before = source.toString()
        val prepared = AndroidTunnelDnsPolicy.prepare(before,
            environment = { error("Opaque data must not bind environment") },
            resolveEndpoint = { error("Config mode must not bootstrap opaque data") })
        assertTrue(prepared.bootstrapHostnames.isEmpty()); assertTrue(prepared.bootstrapAddresses.isEmpty())
        val profile = XrayConfig(V2RAY_FULL_JSON_CONFIG = prepared.configJson)
        try {
            return XrayCoreManager.buildRuntimeConfigJson(profile, File("."),
                LocalProxyCredentials("opaque-user", "opaque-secret"), prepared,
                tcpAvailable = { true }, environment = { error("Opaque data must not bind listener environment") })
        } finally {
            assertEquals(before, source.toString())
            assertEquals(prepared.configJson, profile.V2RAY_FULL_JSON_CONFIG)
        }
    }
    private fun at(value: Any, path: JSONArray): Any {
        var current = value
        for (index in 0 until path.length()) current = when (val owner = current) {
            is JSONObject -> owner.get(path.getString(index))
            is JSONArray -> owner.get(path.getString(index).toInt())
            else -> error("Invalid synthetic opaque path")
        }
        return current
    }

    @Test fun sharedOpaqueFieldsSurviveActualPreparationAtEveryDeclaredPath() {
        val values = cases(); assertEquals(6, values.length())
        val failures = mutableListOf<String>(); var paths = 0
        for (index in 0 until values.length()) {
            val item = values.getJSONObject(index); val source = item.getJSONObject("config")
            val selected = item.getJSONArray("opaquePaths"); paths += selected.length()
            val result = runCatching {
                val runtime = build(source)
                for (path in 0 until selected.length()) {
                    val parts = selected.getJSONArray(path)
                    val runtimeParts = JSONArray(parts.toString())
                    if (parts.length() >= 3 && parts.optString(0) == "routing" && parts.optString(1) == "rules") {
                        val originalRules = source.getJSONObject("routing").getJSONArray("rules")
                        assertEquals(originalRules.length() + 2, runtime.getJSONObject("routing").getJSONArray("rules").length())
                        // Config-mode DNS and the owned API each prepend one rule.
                        runtimeParts.put(2, (parts.getString(2).toInt() + 2).toString())
                    }
                    assertEquals(at(source, parts).toString(), at(runtime, runtimeParts).toString())
                }
            }
            if (result.isFailure) failures += item.getString("name") + ":" + result.exceptionOrNull()!!.javaClass.simpleName
        }
        assertEquals(18, paths)
        assertEquals("Opaque configuration data changed or was rejected", emptyList<String>(), failures)
    }

    @Test fun unknownNamesAreNotStreamOrTlsSettingsEvenWithoutFeatureLookingStrings() {
        val source = base()
        val metadata = JSONObject("""{"network":"Case/Sensitive","xHTTPSettings":"opaque","allowInsecure":"metadata","tlsSettings":{"allowInsecure":false},"file":"/Case/Sensitive/key.pem","address":"env:Metadata.Address","port":"env:Metadata.Port"}""")
        source.put("custom", metadata)
        assertEquals(metadata.toString(), build(source).getJSONObject("custom").toString())
    }

    @Test fun genuineStreamAndTlsConfigurationsRetainTheirCompatibilityAndPrivacyRules() {
        val source = base(); val parent = stream(source)
        parent.put("network", "XHTTP").put("tlsSettings", JSONObject().put("allowInsecure", true))
        val child = JSONObject().put("network", "XHTTP").put("tlsSettings", JSONObject().put("AllowInſecure", true))
            .put("xHTTPSettings", JSONObject().put("path", "/child"))
        parent.put("xHTTPSettings", JSONObject().put("path", "/parent").put("extra", JSONObject().put("downloadSettings", child)))
        parent.put("finalmask", JSONObject().put("udp", JSONArray()
            .put(JSONObject().put("type", "realm").put("settings", JSONObject().put("tlsConfig", JSONObject().put("allowInsecure", true))))
            .put(JSONObject().put("type", "xdns").put("settings", JSONObject().put("resolvers", JSONArray().put(
                JSONObject().put("tlsConfig", JSONObject().put("allowInsecure", false))))))))
        val actual = stream(build(source))
        assertEquals("xhttp", actual.getString("network")); assertFalse(actual.has("xHTTPSettings"))
        assertFalse(actual.getJSONObject("tlsSettings").has("allowInsecure"))
        val download = actual.getJSONObject("xhttpSettings").getJSONObject("extra").getJSONObject("downloadSettings")
        assertEquals("xhttp", download.getString("network")); assertTrue(download.has("xhttpSettings"))
        assertFalse(download.getJSONObject("tlsSettings").has("AllowInſecure"))
        val masks = actual.getJSONObject("finalmask").getJSONArray("udp")
        assertFalse(masks.getJSONObject(0).getJSONObject("settings").getJSONObject("tlsConfig").has("allowInsecure"))
        assertFalse(masks.getJSONObject(1).getJSONObject("settings").getJSONArray("resolvers").getJSONObject(0)
            .getJSONObject("tlsConfig").has("allowInsecure"))
    }

    @Test fun effectiveXhttpAliasAndNullExtraLeaveUnusedDownloadObjectsUnchanged() {
        val source = base(); val parent = stream(source)
        val dormant = JSONObject("""{"network":"MiXeD","xHTTPSettings":"opaque","tlsSettings":{"allowInsecure":true},"type":"xicmp"}""")
        parent.put("network", "tcp").put("xhttpSettings", JSONObject().put("extra", JSONObject.NULL)
            .put("downloadSettings", JSONObject(dormant.toString())))
        parent.put("splithttpSettings", JSONObject().put("downloadSettings", JSONObject(dormant.toString())))
        val actual = stream(build(source))
        assertEquals(dormant.toString(), actual.getJSONObject("xhttpSettings").getJSONObject("downloadSettings").toString())
        assertEquals(dormant.toString(), actual.getJSONObject("splithttpSettings").getJSONObject("downloadSettings").toString())
    }

    @Test fun actualUdpXicmpAndParsedLocalQuicDnsRemainRefused() {
        val mask = base()
        stream(mask).put("FinalMaſk", JSONObject().put("Udp", JSONArray().put(JSONObject().put("TyPe", "XICMP"))))
        assertThrows(IllegalArgumentException::class.java) { build(mask) }
        for (address in listOf("quic+local://dns.invalid", "[ QUIC+LOCAL://dns.invalid ]")) {
            for (server in listOf<Any>(address, JSONObject().put("ADDRESS", address))) {
                val dns = base(); dns.getJSONObject("dns").put("servers", JSONArray().put(server))
                assertThrows("Active local QUIC DNS escaped the typed guard", IllegalArgumentException::class.java) { build(dns) }
            }
        }
    }
}
