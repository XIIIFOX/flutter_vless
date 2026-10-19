package com.github.tfox.flutter_vless.xray.core

import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import java.io.File
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Pure injected environment/availability callbacks; no listener, Core or child process. */
class XrayPortEnvironmentTest {
    @Test fun sharedPortEnvironmentNamesFollowPinnedCoreWithoutLocaleExpansion() {
        val cases = JSONArray(requireNotNull(javaClass.getResource("/port-env.json")).readText())
        assertEquals(8, cases.length())
        val mismatches = mutableListOf<String>()
        for (index in 0 until cases.length()) {
            val item = cases.getJSONObject(index)
            val environment = item.getJSONObject("environment")
            val actual = runCatching { XrayPortSpec.reservedPorts(item.get("value")) { environment.opt(it) as? String } }
            val matches = if (item.optBoolean("invalid")) actual.exceptionOrNull() is IllegalArgumentException else {
                val ports = item.getJSONArray("ports")
                actual.getOrNull() == (0 until ports.length()).map(ports::getInt).toSet()
            }
            if (!matches) mismatches += item.getString("name")
        }
        assertEquals("Core environment port cases changed", emptyList<String>(), mismatches)
    }

    @Test fun sharpSPortAliasAloneRemainsValid() {
        val environment = mapOf("ß_PORT" to "10807")
        assertEquals(setOf(10807), XrayPortSpec.reservedPorts("env:ß.port", environment::get))
    }

    @Test fun exactPortEnvironmentWinsIncludingAnInvalidEmptyValue() {
        val values = mapOf("ß.port" to "10811", "ß_PORT" to "10807", "SS_PORT" to "10809")
        assertEquals(setOf(10811), XrayPortSpec.reservedPorts("env:ß.port", values::get))
        val empty = values + ("ß.port" to "")
        assertThrows(IllegalArgumentException::class.java) { XrayPortSpec.reservedPorts("env:ß.port", empty::get) }
    }

    @Test fun actualRuntimeChooserReservesInjectedEnvironmentPortBeforeItsPrivateInput() {
        val cases = JSONArray(requireNotNull(javaClass.getResource("/port-env.json")).readText())
        for (index in 0 until cases.length()) {
            val item = cases.getJSONObject(index)
            val label = item.getString("name"); val environment = item.getJSONObject("environment")
            val source = JSONObject().put("inbounds", JSONArray().put(JSONObject()
                .put("tag", "caller-http").put("protocol", "http").put("listen", "127.0.0.1").put("port", item.get("value"))))
                .put("outbounds", JSONArray().put(JSONObject().put("protocol", "freedom").put("tag", "direct")))
            val before = source.toString()
            val profile = XrayConfig(V2RAY_FULL_JSON_CONFIG = before, LOCAL_SOCKS5_PORT = 10807, LOCAL_API_PORT = 10809)
            val names = mutableListOf<String>(); val candidates = mutableListOf<Int>()
            val actual = runCatching {
                XrayCoreManager.buildRuntimeConfigJson(profile, File("."), LocalProxyCredentials("port-user", "port-secret"),
                    tcpAvailable = { candidates += it; true }, environment = {
                        names += it
                        environment.opt(it) as? String
                    })
            }
            try {
                assertTrue("$label did not consult its injected port environment", names.isNotEmpty())
                if (item.optBoolean("invalid")) {
                    assertTrue("$label invalid port was accepted", actual.exceptionOrNull() is IllegalArgumentException)
                    assertTrue("$label reached private port allocation before refusal", candidates.isEmpty())
                } else {
                    assertTrue("$label imported port was rejected", actual.isSuccess)
                    val ports = item.getJSONArray("ports")
                    val reserved = (0 until ports.length()).map(ports::getInt).toSet()
                    val expected = (10807..65535).first { it !in reserved }
                    assertEquals(label, expected, profile.LOCAL_SOCKS5_PORT)
                    assertEquals(label, expected, actual.getOrThrow().getJSONArray("inbounds").getJSONObject(1).getInt("port"))
                    assertTrue("$label imported port reached the private availability checker", candidates.none { it in reserved })
                }
            } finally {
                assertEquals(label, before, source.toString())
                assertEquals(label, before, profile.V2RAY_FULL_JSON_CONFIG)
            }
        }
    }
}
