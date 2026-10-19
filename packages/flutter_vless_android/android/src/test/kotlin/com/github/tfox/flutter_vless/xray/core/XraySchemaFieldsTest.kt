package com.github.tfox.flutter_vless.xray.core

import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import java.io.File
import java.util.Locale
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Native preparation only: no Core validator, socket, process or readiness probe. */
class XraySchemaFieldsTest {
    private fun cases(): List<JSONObject> {
        val values = JSONArray(requireNotNull(javaClass.getResource("/schema-fields.json")).readText())
        assertEquals(5, values.length())
        return (0 until values.length()).map(values::getJSONObject)
    }

    private fun field(value: JSONObject, name: String): Any = value.get(value.keys().asSequence().single {
        it.replace('ſ', 's').replace('K', 'k').lowercase(Locale.ROOT) == name
    })

    private fun build(source: JSONObject): JSONObject {
        val before = source.toString()
        val originalInputs = field(source, "inbounds") as JSONArray
        val originalOutputs = field(source, "outbounds") as JSONArray
        val prepared = AndroidTunnelDnsPolicy.prepare(before,
            environment = { error("Schema fields must not bind endpoint environment") },
            resolveEndpoint = { error("Config mode must not bootstrap endpoints") })
        assertTrue(prepared.bootstrapHostnames.isEmpty())
        assertTrue(prepared.bootstrapAddresses.isEmpty())
        val profile = XrayConfig(V2RAY_FULL_JSON_CONFIG = prepared.configJson)
        val candidates = mutableListOf<Int>()
        try {
            val actual = XrayCoreManager.buildRuntimeConfigJson(profile, File("."),
                LocalProxyCredentials("schema-user", "schema-secret"), prepared,
                tcpAvailable = { candidates += it; true },
                environment = { error("Schema fields must not bind listener environment") })
            val inputs = field(actual, "inbounds") as JSONArray
            val outputs = field(actual, "outbounds") as JSONArray
            assertEquals(1, originalInputs.length())
            val imported = inputs.getJSONObject(0)
            assertEquals("http", field(imported, "protocol"))
            assertEquals("127.0.0.1", field(imported, "listen"))
            assertEquals(10807, field(imported, "port"))
            assertEquals(field(originalInputs.getJSONObject(0), "tag"), field(imported, "tag"))
            assertEquals(listOf(10808, 10809), candidates)
            assertEquals(10808, profile.LOCAL_SOCKS5_PORT)
            assertEquals(10808, field(inputs.getJSONObject(originalInputs.length()), "port"))
            assertEquals(10809, profile.LOCAL_API_PORT)
            assertEquals(originalOutputs.length() + 1, outputs.length())
            for (index in 0 until originalOutputs.length()) {
                assertEquals("Caller outbound representation changed", originalOutputs.getJSONObject(index).toString(),
                    outputs.getJSONObject(index).toString())
                assertEquals(field(originalOutputs.getJSONObject(index), "protocol"),
                    field(outputs.getJSONObject(index), "protocol"))
            }
            assertEquals((field(source, "dns") as JSONObject).toString(),
                (field(actual, "dns") as JSONObject).toString())
            return actual
        } finally {
            assertEquals("Caller source changed", before, source.toString())
            assertEquals(prepared.configJson, profile.V2RAY_FULL_JSON_CONFIG)
        }
    }

    @Test fun sharedValidSchemaFieldsReachActualRuntimeProducerWithoutLosingCallerFields() {
        val valid = cases().filterNot { it.optBoolean("coreInvalid") }
        assertEquals(3, valid.size)
        for (item in valid) {
            val actual = build(item.getJSONObject("config"))
            val first = (field(actual, "outbounds") as JSONArray).getJSONObject(0)
            val stream = field(first, "streamsettings") as JSONObject
            assertEquals("socks", field(first, "protocol"))
            assertEquals("proxy", field(first, "tag"))
            val network = field(stream, "network")
            if (item.getString("name") == "empty_network_overridden_by_method") {
                assertEquals("", network)
                assertEquals("tcp", field(stream, "method"))
            } else assertEquals("tcp", network)
        }
    }

    @Test fun activeEmptyNetworkRemainsForCoreValidationRatherThanBeingRewritten() {
        val item = cases().single { it.getString("name") == "active_empty_network" }
        assertTrue(item.getBoolean("coreInvalid"))
        assertFalse(item.optBoolean("invalidSyntax"))
        val actual = build(item.getJSONObject("config"))
        val first = (field(actual, "outbounds") as JSONArray).getJSONObject(0)
        val stream = field(first, "streamsettings") as JSONObject
        assertEquals("", field(stream, "network"))
        assertFalse(stream.has("method"))
        // This is a preparation pass, not acceptance by the native Core parser.
    }
}
