package com.github.tfox.flutter_vless.xray.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class XrayPortSpecTest {
    @Test fun sharedNumericApiListenerCorpusWithoutResolvingNamesOrChangingSource() {
        val cases = JSONArray(requireNotNull(javaClass.getResource("/api-listeners.json")).readText())
        for (i in 0 until cases.length()) {
            val item = cases.getJSONObject(i)
            val config = item.getJSONObject("config")
            val original = config.toString()
            val ports = item.getJSONArray("ports")
            assertEquals(item.getString("name"), (0 until ports.length()).map { ports.getInt(it) }.toSet(), XrayPortSpec.apiListenerPorts(config))
            assertEquals(original, config.toString())
        }
    }

    @Test fun privateAdapterReservesImportedApiAlongsidePortRanges() {
        val raw = """{"api":{"listen":"127.0.0.1:10807","tag":"caller-api","services":["StatsService"]},
          "inbounds":[{"protocol":"http","port":"10808-10810"}],"outbounds":[{"protocol":"freedom"}]}"""
        val config = com.github.tfox.flutter_vless.xray.dto.XrayConfig(V2RAY_FULL_JSON_CONFIG = raw)
        XrayCoreManager.buildRuntimeConfigJson(config, java.io.File("."), LocalProxyCredentials("user", "password"))
        assertEquals(10811, config.LOCAL_SOCKS5_PORT)
        assertEquals(raw, config.V2RAY_FULL_JSON_CONFIG)
    }

    @Test fun sharedNumericMetricsAndApiCorpusWithoutResolvingNamesOrChangingSource() {
        val cases = JSONArray(requireNotNull(javaClass.getResource("/metrics-listeners.json")).readText())
        for (i in 0 until cases.length()) {
            val item = cases.getJSONObject(i)
            val config = item.getJSONObject("config")
            val original = config.toString()
            val ports = item.getJSONArray("ports")
            assertEquals(item.getString("name"), (0 until ports.length()).map { ports.getInt(it) }.toSet(),
                XrayPortSpec.serviceListenerPorts(config))
            assertEquals(original, config.toString())
        }
    }

    @Test fun privateAdapterAndStatsApiReserveCallerMetricsWithoutChangingThem() {
        for (metricsKey in listOf("metrics", "METRICS", "Metric\u017f")) {
            val source = JSONObject("""{"api":{"listen":"127.0.0.1:10807","tag":"caller-api","services":["StatsService"]},
                "inbounds":[{"protocol":"http","port":"10808-10810"}],"outbounds":[{"protocol":"freedom"}]}""")
            val metrics = JSONObject().put("Li\u017ften", "127.0.0.1:10811").put("tag", "caller-metrics")
            source.put(metricsKey, metrics)
            val raw = source.toString()
            val config = com.github.tfox.flutter_vless.xray.dto.XrayConfig(V2RAY_FULL_JSON_CONFIG = raw)
            val effective = XrayCoreManager.buildRuntimeConfigJson(config, java.io.File("."), LocalProxyCredentials("user", "password"))
            assertEquals(10812, config.LOCAL_SOCKS5_PORT)
            assertEquals(10813, config.LOCAL_API_PORT)
            assertEquals(metrics.toString(), effective.getJSONObject(metricsKey).toString())
            assertEquals(raw, source.toString())
            assertEquals(raw, config.V2RAY_FULL_JSON_CONFIG)
        }
    }

    @Test fun sharedPinnedCorePortCorpus() {
        val cases = JSONArray(requireNotNull(javaClass.getResource("/ports.json")).readText())
        for (index in 0 until cases.length()) {
            val c = cases.getJSONObject(index)
            val environment = c.optJSONObject("environment") ?: JSONObject()
            val result = runCatching { XrayPortSpec.reservedPorts(c.get("value")) { environment.opt(it) as? String } }
            if (c.optBoolean("invalid")) assertTrue(c.getString("name"), result.isFailure)
            else {
                val ports = c.getJSONArray("ports")
                assertEquals(c.getString("name"), (0 until ports.length()).map { ports.getInt(it) }.toSet(), result.getOrThrow())
            }
        }
    }
}
