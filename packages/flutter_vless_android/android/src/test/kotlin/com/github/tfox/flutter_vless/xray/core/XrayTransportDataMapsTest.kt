package com.github.tfox.flutter_vless.xray.core

import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import java.io.File
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

/** Shared Core-typed dictionaries through the actual Android prepare/build path. */
@RunWith(Parameterized::class)
class XrayTransportDataMapsTest(private val label: String, private val fixture: String) {
    companion object {
        @JvmStatic @Parameterized.Parameters(name = "{0}")
        fun cases(): Collection<Array<Any>> {
            val cases = JSONArray(requireNotNull(XrayTransportDataMapsTest::class.java.getResource("/transport-data-maps.json")).readText())
            assertEquals(10, cases.length())
            assertEquals(18, (0 until cases.length()).sumOf { cases.getJSONObject(it).getJSONArray("maps").length() })
            return (0 until cases.length()).map {
                val item = cases.getJSONObject(it)
                arrayOf<Any>(item.getString("name"), item.toString())
            }
        }
    }

    private fun atPath(root: JSONObject, path: JSONArray): JSONObject {
        var current: Any = root
        for (index in 0 until path.length()) {
            val component = path.getString(index)
            current = when (val owner = current) {
                is JSONArray -> owner.get(component.toInt())
                is JSONObject -> {
                    val field = component.replace('ſ', 's').replace('K', 'k').lowercase(java.util.Locale.ROOT)
                    val key = owner.keys().asSequence().single {
                        it.replace('ſ', 's').replace('K', 'k').lowercase(java.util.Locale.ROOT) == field
                    }
                    owner.get(key)
                }
                else -> error("Invalid shared dictionary fixture path")
            }
        }
        return current as JSONObject
    }

    @Test fun typedHeaderMapsSurviveActualPreparationAndRuntimeNormalization() {
        val item = JSONObject(fixture)
        val source = item.getJSONObject("config")
        val before = source.toString()
        val prepared = AndroidTunnelDnsPolicy.prepare(before,
            environment = { error("Header data must not bind endpoint environment") },
            resolveEndpoint = { error("Header data must not resolve an endpoint") })
        assertTrue(prepared.bootstrapHostnames.isEmpty())
        assertTrue(prepared.bootstrapAddresses.isEmpty())
        val profile = XrayConfig(V2RAY_FULL_JSON_CONFIG = prepared.configJson)
        try {
            val runtime = XrayCoreManager.buildRuntimeConfigJson(profile, File("."),
                LocalProxyCredentials("transportuser", "transportsecret"), prepared,
                tcpAvailable = { true }, environment = { error("Header data must not bind listener environment") })
            assertEquals(label, source.getJSONObject("dns").toString(), runtime.getJSONObject("dns").toString())
            val maps = item.getJSONArray("maps")
            for (index in 0 until maps.length()) {
                val map = maps.getJSONObject(index)
                val path = map.getJSONArray("path")
                val expected = atPath(source, path)
                val actual = atPath(runtime, path)
                val kind = map.getString("kind")
                assertTrue(kind in setOf("string", "string-list"))
                for (key in expected.keys()) {
                    val value = expected.get(key)
                    assertTrue("$label malformed fixture value", value is String || kind == "string-list" && value is JSONArray)
                }
                assertEquals("$label dictionary $index changed", expected.toString(), actual.toString())
            }
        } finally {
            assertEquals(label, before, source.toString())
            assertEquals(label, prepared.configJson, profile.V2RAY_FULL_JSON_CONFIG)
        }
    }
}
