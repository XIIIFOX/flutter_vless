package com.github.tfox.flutter_vless.xray.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class XdriveServicePolicyTest {
    @Test fun actualCallerAndProxyPreparersUseOnlyQualifiedServiceOrigins() {
        val cases = JSONArray(requireNotNull(javaClass.getResource("/xdrive-services.json")).readText())
        assertEquals(13, cases.length())
        for (index in 0 until cases.length()) {
            val item = cases.getJSONObject(index); val label = item.getString("name")
            val source = item.getJSONObject("config"); val before = source.toString()
            for (policy in listOf("config", "proxy")) {
                val lookedUp = mutableSetOf<String>()
                if (!item.getBoolean("accepted")) {
                    assertThrows(label, IllegalArgumentException::class.java) {
                        AndroidTunnelDnsPolicy.prepare(before, policy) { host -> lookedUp += host; listOf("192.0.2.17") }
                    }
                    assertTrue(label, lookedUp.isEmpty())
                } else {
                    val prepared = AndroidTunnelDnsPolicy.prepare(before, policy) { host -> lookedUp += host; listOf("192.0.2.17") }
                    val expected = item.getJSONArray("bootstrapHosts").let { entries -> (0 until entries.length()).map(entries::getString).toSet() }
                    assertEquals(label, if (policy == "proxy") expected else emptySet<String>(), lookedUp)
                    val proxy = JSONObject(prepared.configJson).getJSONArray("outbounds").getJSONObject(0)
                    val original = source.getJSONArray("outbounds").getJSONObject(0)
                    assertEquals(label, original.getJSONObject("settings").toString(), proxy.getJSONObject("settings").toString())
                    assertEquals(label, original.getJSONObject("streamSettings").getJSONObject("xdriveSettings").toString(),
                        proxy.getJSONObject("streamSettings").getJSONObject("xdriveSettings").toString())
                    assertTrue(XdriveServicePolicy.requiresLifetime(prepared.configJson))
                }
                assertEquals(label, before, source.toString())
            }
        }
    }

    @Test fun cloudInboundsBootstrapBesideLiteralOnlyProxy() {
        val cases = JSONArray(requireNotNull(javaClass.getResource("/xdrive-services.json")).readText())
        for (index in listOf(0, 2)) {
            val item = cases.getJSONObject(index); val source = item.getJSONObject("config")
            val stream = source.getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")
            val settings = JSONObject().put("decryption", "none").put("clients", JSONArray().put(JSONObject().put("id", "11111111-1111-4111-8111-111111111111")))
            source.put("inbounds", JSONArray().put(JSONObject().put("tag", "cloud-in").put("listen", "127.0.0.1")
                .put("port", 8443).put("protocol", "vless").put("settings", settings).put("streamSettings", stream)))
            val proxy = JSONObject().put("protocol", "socks").put("tag", "proxy").put("settings", JSONObject().put("servers",
                JSONArray().put(JSONObject().put("address", "192.0.2.99").put("port", 443))))
            source.put("outbounds", JSONArray().put(proxy).put(JSONObject().put("protocol", "freedom").put("tag", "direct")))
            val before = source.toString(); val lookedUp = mutableSetOf<String>()
            val prepared = AndroidTunnelDnsPolicy.prepare(before, "proxy") { host -> lookedUp += host; listOf("192.0.2.17") }
            val expected = item.getJSONArray("bootstrapHosts").let { entries -> (0 until entries.length()).map(entries::getString).toSet() }
            assertEquals(expected, lookedUp)
            val inbounds = JSONObject(prepared.configJson).getJSONArray("inbounds")
            val cloud = (0 until inbounds.length()).map(inbounds::getJSONObject).single { it.optString("tag") == "cloud-in" }
            assertEquals(stream.getJSONObject("xdriveSettings").toString(), cloud.getJSONObject("streamSettings").getJSONObject("xdriveSettings").toString())
            assertEquals(ManagedServiceCapabilities.XDRIVE, ManagedServiceCapabilities.required(prepared.configJson))
            assertFalse(ManagedServiceCapabilities.allows(prepared.configJson, 0))
            assertEquals(before, source.toString())
        }
    }

    @Test fun dormantSettingsDoNotEnableCloudOrInterpretExternalFiles() {
        val source = JSONObject().put("outbounds", JSONArray().put(JSONObject().put("protocol", "vless")
            .put("streamSettings", JSONObject().put("network", "tcp").put("xdriveSettings", "/private/not-read"))))
        assertFalse(XdriveServicePolicy.requiresLifetime(source.toString()))
        XdriveServicePolicy.validate(source)
    }

    @Test fun capabilityReplyRejectsLegacyMalformedAndUnknownProtocols() {
        fun parse(raw: String) = ManagedServiceCapabilities.parse(raw.toByteArray())
        assertEquals(3, parse("""{"stage":"capabilities","code":0,"managed_service_lifetimes":3}"""))
        for (raw in listOf("", "1", "[]", "{}", "version26.10.29",
            """{"stage":"capabilities","code":0,"capability":1}""",
            """{"stage":"capabilities","code":0,"managed_service_lifetimes":4}""",
            """{"stage":"capabilities","code":0,"managed_service_lifetimes":"3"}""",
            """{"stage":"capabilities","code":0,"managed_service_lifetimes":3} {}""",
            """{"stage":"capabilities","code":0,"managed_service_lifetimes":0,"managed_service_lifetimes":3}""",
            """{"stage":"capabilities","code":0,"managed_service_lifetimes":3,"unknown":1}"""))
            assertEquals(0, parse(raw))
        assertEquals(0, ManagedServiceCapabilities.parse(ByteArray(4097)))
        assertEquals(0, ManagedServiceCapabilities.parse(null))
    }

    @Test fun eachActiveServiceRequiresItsActualRuntimeBit() {
        val source = JSONArray(requireNotNull(javaClass.getResource("/xdrive-services.json")).readText())
            .getJSONObject(0).getJSONObject("config")
        assertFalse(ManagedServiceCapabilities.allows(source.toString(), 0))
        assertFalse(ManagedServiceCapabilities.allows(source.toString(), ManagedServiceCapabilities.GEODATA))
        assertTrue(ManagedServiceCapabilities.allows(source.toString(), ManagedServiceCapabilities.XDRIVE))
        source.put("geodata", JSONObject().put("cron", "@every 1m"))
        assertEquals(3, ManagedServiceCapabilities.required(source.toString()))
        assertFalse(ManagedServiceCapabilities.allows(source.toString(), ManagedServiceCapabilities.XDRIVE))
        assertTrue(ManagedServiceCapabilities.allows(source.toString(), 3))
    }
}
