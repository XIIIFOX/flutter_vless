package com.github.tfox.flutter_vless.xray.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class XrayPortSpecTest {
    @Test fun environmentUnixListenDoesNotReserveEveryTcpPortAndIsFrozenBeforeLaunch() {
        val source = """{"inbounds":[{"tag":"caller-unix","listen":"env:FLUTTER_VLESS_TEST_UNIX_LISTEN",
          "port":"0-65535","protocol":"socks","settings":{"auth":"noauth","udp":false}}],
          "outbounds":[{"protocol":"freedom"}]}"""
        val config = com.github.tfox.flutter_vless.xray.dto.XrayConfig(V2RAY_FULL_JSON_CONFIG = source)
        val output = XrayCoreManager.buildRuntimeConfigJson(config, java.io.File("."), LocalProxyCredentials("user", "password"),
            environment = { if (it == "FLUTTER_VLESS_TEST_UNIX_LISTEN") "/tmp/flutter-vless-fixture.sock" else null })
        assertEquals(10807, config.LOCAL_SOCKS5_PORT)
        val expected = JSONObject(source).getJSONArray("inbounds").getJSONObject(0)
            .put("listen", "/tmp/flutter-vless-fixture.sock")
        assertEquals(expected.toString(), output.getJSONArray("inbounds").getJSONObject(0).toString())
        assertEquals(source, config.V2RAY_FULL_JSON_CONFIG)
    }

    @Test fun listenEnvironmentUsesExactEmptyThenGoAliasWithoutRecursiveExpansion() {
        val values = mapOf("listen.name" to "", "LISTEN_NAME" to "/tmp/alias.sock",
            "\u00df_PORT" to "127.0.0.1", "SS_PORT" to "/tmp/wrong.sock",
            "CONTROL" to "/tmp/not-trimmed.sock", "SECOND" to "/tmp/not-recursive.sock",
            "FIRST" to "env:SECOND")
        val lookup: (String) -> String? = values::get
        assertEquals("", XrayPortSpec.bindListenEnvironment("env:listen.name", lookup))
        assertEquals("/tmp/alias.sock", XrayPortSpec.bindListenEnvironment("env:\u0085 listen.name\u00a0", lookup))
        assertEquals("127.0.0.1", XrayPortSpec.bindListenEnvironment("env:\u00df.port", lookup))
        assertEquals("", XrayPortSpec.bindListenEnvironment("env:\u001ccontrol\u001c", lookup))
        assertThrows(IllegalArgumentException::class.java) { XrayPortSpec.bindListenEnvironment("env:FIRST", lookup) }
        assertEquals("", XrayPortSpec.bindListenEnvironment("env:MISSING", lookup))
        assertEquals("ENV:FIRST", XrayPortSpec.bindListenEnvironment("ENV:FIRST", lookup))
    }

    @Test fun sharedListenAddressCorpusFreezesRuntimeWithoutChangingSource() {
        val cases = JSONArray(requireNotNull(javaClass.getResource("/listen-addresses.json")).readText())
        assertEquals(6, cases.length())
        for (index in 0 until cases.length()) {
            val item = cases.getJSONObject(index); val label = item.getString("name")
            val environment = item.getJSONObject("environment")
            val source = JSONObject().put("inbounds", JSONArray().put(JSONObject().put("protocol", "socks")
                .put("tag", "caller-input").put("listen", item.getString("listen")).put("port", item.get("port"))))
                .put("outbounds", JSONArray().put(JSONObject().put("protocol", "freedom")))
            val before = source.toString()
            val config = com.github.tfox.flutter_vless.xray.dto.XrayConfig(V2RAY_FULL_JSON_CONFIG = before)
            val output = runCatching { XrayCoreManager.buildRuntimeConfigJson(config, java.io.File("."),
                LocalProxyCredentials("user", "password"), environment = { environment.opt(it) as? String }) }
            if (item.optBoolean("invalid")) assertTrue(label, output.exceptionOrNull() is IllegalArgumentException)
            else {
                val resolved = item.getString("resolved")
                assertEquals(label, resolved, output.getOrThrow().getJSONArray("inbounds").getJSONObject(0).getString("listen"))
                val expected = JSONObject(source.getJSONArray("inbounds").getJSONObject(0).toString()).put("listen", resolved)
                assertEquals(label, expected.toString(), output.getOrThrow().getJSONArray("inbounds").getJSONObject(0).toString())
                assertEquals(label, item.getBoolean("unix"), XrayPortSpec.isUnixListen(resolved))
                val occupied = if (item.getBoolean("unix")) emptySet() else XrayPortSpec.reservedPorts(item.get("port"))
                assertEquals(label, (10807..65535).first { it !in occupied }, config.LOCAL_SOCKS5_PORT)
            }
            assertEquals(label, before, source.toString())
            assertEquals(label, before, config.V2RAY_FULL_JSON_CONFIG)
        }
    }

    @Test fun boundIpEmptyAndMissingListenStillReserveTheirPortsAndPreserveSource() {
        for (value in listOf<String?>("127.0.0.1", "", null)) {
            val source = """{"inbounds":[{"tag":"caller-input","listen":"env:LISTEN_ADDR","port":"10807-10809","protocol":"http"}],"outbounds":[{"protocol":"freedom"}]}"""
            val config = com.github.tfox.flutter_vless.xray.dto.XrayConfig(V2RAY_FULL_JSON_CONFIG = source)
            val output = XrayCoreManager.buildRuntimeConfigJson(config, java.io.File("."), LocalProxyCredentials("user", "password"),
                environment = { if (it == "LISTEN_ADDR") value else null })
            assertEquals(10810, config.LOCAL_SOCKS5_PORT)
            assertEquals(value ?: "", output.getJSONArray("inbounds").getJSONObject(0).getString("listen"))
            assertEquals(source, config.V2RAY_FULL_JSON_CONFIG)
        }
    }

    @Test fun unixListenUsesCoreAddressViewWhilePreservingResolvedWhitespaceAndBrackets() {
        for (listen in listOf(" \t/tmp/flutter-vless-fixture.sock\u0085", "[/tmp/flutter-vless-fixture.sock]", " \t@flutter-vless-fixture ")) {
            val source = """{"inbounds":[{"protocol":"socks","listen":"env:LISTEN_ADDR","port":"0-65535"}],"outbounds":[{"protocol":"freedom"}]}"""
            val config = com.github.tfox.flutter_vless.xray.dto.XrayConfig(V2RAY_FULL_JSON_CONFIG = source)
            val output = XrayCoreManager.buildRuntimeConfigJson(config, java.io.File("."), LocalProxyCredentials("user", "password"),
                environment = { if (it == "LISTEN_ADDR") listen else null })
            assertEquals(10807, config.LOCAL_SOCKS5_PORT)
            assertEquals(listen, output.getJSONArray("inbounds").getJSONObject(0).getString("listen"))
            assertEquals(source, config.V2RAY_FULL_JSON_CONFIG)
        }
        assertFalse(XrayPortSpec.isUnixListen("\u001c/tmp/not-go-whitespace"))
        assertFalse(XrayPortSpec.isUnixListen(" [/tmp/not-unwrapped] "))
    }

    @Test fun proxyOnlyDoesNotSelectCredentialsFromAWhitespaceUnixListen() {
        val source = """{"inbounds":[{"protocol":"socks","listen":"env:LISTEN_ADDR","port":10807,
          "settings":{"auth":"password","accounts":[{"user":"unix-user","pass":"unix-password"}]}}],"outbounds":[{"protocol":"freedom"}]}"""
        val config = com.github.tfox.flutter_vless.xray.dto.XrayConfig(V2RAY_FULL_JSON_CONFIG = source, PROXY_ONLY = true)
        val output = XrayCoreManager.buildRuntimeConfigJson(config, java.io.File("."),
            environment = { if (it == "LISTEN_ADDR") " \t/tmp/flutter-vless-fixture.sock " else null })
        assertEquals(10807, config.LOCAL_SOCKS5_PORT)
        assertEquals(3, output.getJSONArray("inbounds").length()) // Imported Unix, private SOCKS, owned API.
        assertNull(LocalProxyAccessPolicy.credentialsForProxyOnly(output, config.LOCAL_SOCKS5_PORT))
        assertEquals(source, config.V2RAY_FULL_JSON_CONFIG)
    }

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

    @Test fun privateAdapterReservesCallerApiAndMetricsWithoutAddingAnApi() {
        for (metricsKey in listOf("metrics", "METRICS", "Metric\u017f")) {
            val source = JSONObject("""{"api":{"listen":"127.0.0.1:+10807","tag":"caller-api","services":["StatsService"]},
                "inbounds":[{"protocol":"http","port":"10808-10810"}],"outbounds":[{"protocol":"freedom"}]}""")
            val metrics = JSONObject().put("Li\u017ften", "127.0.0.1:+10811").put("tag", "caller-metrics")
            source.put(metricsKey, metrics)
            val raw = source.toString()
            val config = com.github.tfox.flutter_vless.xray.dto.XrayConfig(V2RAY_FULL_JSON_CONFIG = raw)
            val effective = XrayCoreManager.buildRuntimeConfigJson(config, java.io.File("."), LocalProxyCredentials("user", "password"))
            assertEquals(10812, config.LOCAL_SOCKS5_PORT)
            assertEquals(0, config.LOCAL_API_PORT)
            assertEquals(source.getJSONObject("api").toString(), effective.getJSONObject("api").toString())
            assertEquals(metrics.toString(), effective.getJSONObject(metricsKey).toString())
            assertEquals(raw, source.toString())
            assertEquals(raw, config.V2RAY_FULL_JSON_CONFIG)
        }
    }

    @Test fun ownedStatsApiStillReservesCallerMetricsPorts() {
        val config = com.github.tfox.flutter_vless.xray.dto.XrayConfig(V2RAY_FULL_JSON_CONFIG =
            """{"metrics":{"listen":"127.0.0.1:10809"},"outbounds":[{"protocol":"freedom"}]}""")
        XrayCoreManager.buildRuntimeConfigJson(config, java.io.File("."), LocalProxyCredentials("user", "password"))
        assertEquals(10807, config.LOCAL_SOCKS5_PORT)
        assertEquals(10810, config.LOCAL_API_PORT)
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
