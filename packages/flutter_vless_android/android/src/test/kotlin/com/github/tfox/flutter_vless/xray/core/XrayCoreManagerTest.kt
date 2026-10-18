package com.github.tfox.flutter_vless.xray.core

import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import java.io.File
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class XrayCoreManagerTest {
    @Test fun unixPortListDoesNotConsumeTcpPortsOrReceivePrivateAuthentication() {
        val input = JSONObject("""{"protocol":"socks","listen":"/tmp/flutter-vless-port-corpus.sock","port":"0-65535","settings":{"auth":"password","accounts":[{"user":"caller","pass":"caller-password"}]}}""")
        val profile = JSONObject().put("inbounds", JSONArray().put(input)).put("outbounds", JSONArray().put(JSONObject().put("protocol", "freedom")))
        val config = XrayConfig(LOCAL_SOCKS5_PORT = 10807, V2RAY_FULL_JSON_CONFIG = profile.toString())
        val output = XrayCoreManager.buildRuntimeConfigJson(config, File("build/test-files/ports"), credentials)
        assertEquals(10807, config.LOCAL_SOCKS5_PORT)
        assertEquals(input.toString(), output.getJSONArray("inbounds").getJSONObject(0).toString())
    }

    @Test
    fun protectedVpnRejectsUncontrolledIcmpSocketsButKeepsNormalTransports() {
        XrayCoreManager.requireProtectedSocketSupport(JSONObject("""{"streamSettings":{"network":"tcp"}}"""))
        for (address in listOf("quic+local://dns.example", "QUIC+LOCAL://dns.example")) {
            try {
                XrayCoreManager.requireProtectedSocketSupport(JSONObject().put("DNS", JSONObject().put("Servers", JSONArray().put(address))))
                org.junit.Assert.fail("Uncontrolled QUIC DNS sockets must be rejected")
            } catch (_: IllegalArgumentException) { }
        }
        for (key in listOf("type", "Type")) {
            val value = JSONObject().put("finalmask", JSONObject().put("udp", JSONArray().put(JSONObject().put(key, "XICMP"))))
            try {
                XrayCoreManager.requireProtectedSocketSupport(value)
                org.junit.Assert.fail("Uncontrolled ICMP sockets must be rejected")
            } catch (_: IllegalArgumentException) { }
        }
    }
    @Test
    fun buildRuntimeConfigJson_normalizesFlatVlessAndKeepsEncryption() {
        val filesDir = File("build/test-files/android-normalize")
        val config = XrayConfig(
            V2RAY_FULL_JSON_CONFIG = """
                {
                  "log": {
                    "access": "/Users/dev/Desktop/access.log",
                    "error": "/Users/dev/Desktop/error.log"
                  },
                  "inbounds": [],
                  "outbounds": [
                    {
                      "tag": "proxy",
                      "protocol": "vless",
                      "settings": {
                        "address": "xhttp.example.com",
                        "port": 2043,
                        "id": "22222222-2222-4222-8222-222222222222",
                        "encryption": "$vlessEncryption",
                        "flow": "xtls-rprx-vision",
                        "level": 8
                      },
                      "streamSettings": {
                        "network": "xhttp",
                        "security": "none"
                      }
                    }
                  ],
                  "routing": { "rules": [] }
                }
            """.trimIndent()
        )

        val output = XrayCoreManager.buildRuntimeConfigJson(config, filesDir, credentials)
        val user = output
            .getJSONArray("outbounds")
            .getJSONObject(0)
            .getJSONObject("settings")
            .getJSONArray("vnext")
            .getJSONObject(0)
            .getJSONArray("users")
            .getJSONObject(0)
        val log = output.getJSONObject("log")

        assertEquals(vlessEncryption, user.getString("encryption"))
        assertEquals("xtls-rprx-vision", user.getString("flow"))
        assertEquals("none", log.getString("access"))
        assertEquals("none", log.getString("error"))
        assertTrue(output.has("api"))
        assertTrue(output.has("stats"))
        assertTrue(output.getJSONObject("policy").getJSONObject("system").getBoolean("statsOutboundDownlink"))
    }

    @Test
    fun buildRuntimeConfigJson_injectsUniqueInboundsAndApiRouteOnPortConflicts() {
        val config = XrayConfig(
            LOCAL_SOCKS5_PORT = 10807,
            LOCAL_HTTP_PORT = 10808,
            LOCAL_API_PORT = 10809,
            V2RAY_FULL_JSON_CONFIG = """
                {
                  "inbounds": [
                    { "tag": "socks", "protocol": "dokodemo-door", "port": 10807 },
                    { "tag": "http", "protocol": "dokodemo-door", "port": 10808 },
                    { "tag": "api", "protocol": "dokodemo-door", "port": 10809 }
                  ],
                  "outbounds": [
                    {
                      "tag": "proxy",
                      "protocol": "shadowsocks",
                      "settings": {
                        "servers": [
                          {
                            "address": "ss.example.com",
                            "port": 8388,
                            "method": "2022-blake3-aes-128-gcm",
                            "password": "secret"
                          }
                        ]
                      }
                    }
                  ]
                }
            """.trimIndent()
        )

        val output = XrayCoreManager.buildRuntimeConfigJson(config, File("build/test-files/android-conflicts"), credentials)
        val inbounds = output.getJSONArray("inbounds")
        val socks = findInbound(inbounds, "flutter-vless-tun")
        val api = findInbound(inbounds, "flutter-vless-stats-in")
        val routingRules = output.getJSONObject("routing").getJSONArray("rules")
        val apiRule = routingRules.getJSONObject(0)

        assertEquals(10810, config.LOCAL_SOCKS5_PORT)
        assertEquals(10811, config.LOCAL_API_PORT)
        assertEquals("socks", socks.getString("protocol"))
        assertEquals(10810, socks.getInt("port"))
        assertEquals(0, countInboundsByProtocol(inbounds, "http"))
        assertEquals("dokodemo-door", api.getString("protocol"))
        assertEquals(10811, api.getInt("port"))
        assertEquals("flutter-vless-stats", apiRule.getString("outboundTag"))
        assertEquals("flutter-vless-stats-in", apiRule.getJSONArray("inboundTag").getString(0))
    }

    @Test
    fun buildRuntimeConfigJson_preservesUserSocksAndHttpAndAddsPrivateAdapter() {
        val config = XrayConfig(
            LOCAL_SOCKS5_PORT = 10807,
            LOCAL_HTTP_PORT = 10808,
            V2RAY_FULL_JSON_CONFIG = """
                {
                  "inbounds": [
                    { "tag": "socks", "protocol": "socks", "listen": "127.0.0.1", "port": 10807 },
                    { "tag": "http", "protocol": "http", "listen": "127.0.0.1", "port": 10808 }
                  ],
                  "outbounds": [
                    {
                      "tag": "proxy",
                      "protocol": "freedom"
                    }
                  ]
                }
            """.trimIndent()
        )

        val output = XrayCoreManager.buildRuntimeConfigJson(config, File("build/test-files/android-existing"), credentials)
        val inbounds = output.getJSONArray("inbounds")

        assertEquals(4, inbounds.length())
        assertEquals(2, countInboundsByProtocol(inbounds, "socks"))
        assertEquals(1, countInboundsByProtocol(inbounds, "http"))
        assertFalse(output.toString().contains("socks_1"))
        assertFalse(output.toString().contains("http_1"))
        assertEquals(JSONObject(config.V2RAY_FULL_JSON_CONFIG).getJSONArray("inbounds").toString(),
            JSONArray().put(inbounds.getJSONObject(0)).put(inbounds.getJSONObject(1)).toString())
        assertEquals(10809, config.LOCAL_SOCKS5_PORT)
    }

    @Test
    fun buildDelayConfigJson_reusesRuntimeNormalizationForHappJson() {
        val (output, socksPort) = XrayCoreManager.buildDelayConfigJson(
            """
                {
                  "dns": { "queryStrategy": "UseIPv4" },
                  "log": {
                    "access": "/Users/dev/Library/access.log",
                    "error": "/Users/dev/Library/error.log"
                  },
                  "inbounds": [
                    { "tag": "socks-in", "protocol": "socks", "port": 10808 }
                  ],
                  "outbounds": [
                    {
                      "tag": "proxy",
                      "protocol": "vless",
                      "settings": {
                        "vnext": [
                          {
                            "address": "reality.example.com",
                            "port": 443,
                            "users": [
                              {
                                "id": "22222222-2222-4222-8222-222222222222",
                                "encryption": "none",
                                "flow": "xtls-rprx-vision"
                              }
                            ]
                          }
                        ]
                      },
                      "streamSettings": {
                        "network": "tcp",
                        "security": "reality"
                      }
                    }
                  ]
                }
            """.trimIndent(),
            proxyPort = 19080,
            filesDir = File("build/test-files/android-delay"),
            credentials = credentials
        )
        val inbounds = output.getJSONArray("inbounds")
        val delaySocks = findInbound(inbounds, "flutter-vless-tun")
        val user = output
            .getJSONArray("outbounds")
            .getJSONObject(0)
            .getJSONObject("settings")
            .getJSONArray("vnext")
            .getJSONObject(0)
            .getJSONArray("users")
            .getJSONObject(0)

        assertEquals(19080, socksPort)
        assertEquals(19080, delaySocks.getInt("port"))
        assertEquals("none", user.getString("encryption"))
        assertEquals("xtls-rprx-vision", user.getString("flow"))
        assertEquals("none", output.getJSONObject("log").getString("access"))
        assertTrue(output.has("api"))
    }

    @Test
    fun buildDelayConfigJson_discardsCallerServicesWithoutChangingOutboundsOrNormalSession() {
        for ((apiKey, metricsKey) in listOf("api" to "metrics", "API" to "Metrics", "Api" to "METRICS", "api" to "Metric\u017f")) {
            val source = JSONObject().put("Inbounds", JSONArray().put(JSONObject()
                .put("protocol", "http").put("listen", "127.0.0.1").put("port", 18080)))
                .put(apiKey, JSONObject().put("tag", "caller-api").put("listen", "127.0.0.1:18081")
                    .put("services", JSONArray().put("StatsService")))
                .put(metricsKey, JSONObject().put("tag", "caller-metrics").put("listen", "127.0.0.1:18082"))
                .put("outbounds", JSONArray()
                    .put(JSONObject().put("tag", "caller-api").put("protocol", "freedom"))
                    .put(JSONObject().put("tag", "caller-metrics").put("protocol", "blackhole")))
            val original = source.toString()
            val (delay, port) = XrayCoreManager.buildDelayConfigJson(original, 19080,
                File("build/test-files/android-delay-services"), credentials)
            assertEquals(19080, port)
            assertFalse(delay.keys().asSequence().any { it.equals("metrics", ignoreCase = true) })
            assertFalse(delay.getJSONObject("api").has("listen"))
            assertFalse(delay.getJSONObject("api").getString("tag") == "caller-api")
            assertEquals(source.getJSONArray("outbounds").toString(), delay.getJSONArray("outbounds").toString())
            val inputs = delay.getJSONArray("inbounds")
            assertEquals(2, inputs.length()) // Owned SOCKS and native stats only.
            assertFalse((0 until inputs.length()).any { inputs.getJSONObject(it).getInt("port") == 18080 })

            val normal = XrayCoreManager.buildRuntimeConfigJson(XrayConfig(V2RAY_FULL_JSON_CONFIG = original),
                File("build/test-files/android-normal-services"), credentials)
            assertEquals(source.getJSONObject(metricsKey).toString(), normal.getJSONObject(metricsKey).toString())
            assertEquals(source.getJSONArray("outbounds").toString(), normal.getJSONArray("outbounds").toString())
            assertEquals(original, source.toString())
        }
    }

    @Test
    fun buildDelayConfigJson_rejectsAmbiguousServiceAliases() {
        for (fields in listOf(
            "\"api\":{},\"API\":{}",
            "\"metrics\":{},\"Metrics\":{}",
            "\"metrics\":{},\"Metric\u017f\":{}"
        )) {
            val original = """{$fields,"outbounds":[{"protocol":"freedom"}]}"""
            try {
                XrayCoreManager.buildDelayConfigJson(original, 19080,
                    File("build/test-files/android-delay-service-aliases"), credentials)
                org.junit.Assert.fail("Ambiguous native service fields must be rejected")
            } catch (_: IllegalArgumentException) { }
        }
    }

    @Test
    fun buildRuntimeConfigJson_normalizesXray26RuntimeAliases() {
        val filesDir = File("build/test-files/android-aliases")
        val config = XrayConfig(
            V2RAY_FULL_JSON_CONFIG = """
                {
                  "log": {
                    "access": "/Users/example/access.log",
                    "error": "/Users/example/error.log"
                  },
                  "inbounds": [],
                  "outbounds": [
                    {
                      "protocol": "vless",
                      "settings": {
                        "vnext": [
                          {
                            "address": "example.com",
                            "port": 443,
                            "users": [
                              {
                                "id": "11111111-1111-4111-8111-111111111111",
                                "encryption": "none"
                              }
                            ]
                          }
                        ]
                      },
                      "streamSettings": {
                        "network": "XHTTP",
                        "security": "tls",
                        "tlsSettings": {
                          "allowInsecure": false,
                          "serverName": "example.com"
                        },
                        "xHTTPSettings": {
                          "path": "/",
                          "mode": "auto"
                        },
                        "httpUpgradeSettings": {
                          "path": "/upgrade"
                        },
                        "splitHTTPSettings": {
                          "path": "/split"
                        }
                      }
                    }
                  ]
                }
            """.trimIndent()
        )

        val runtime = XrayCoreManager.buildRuntimeConfigJson(config, filesDir, credentials)
        val stream = runtime
            .getJSONArray("outbounds")
            .getJSONObject(0)
            .getJSONObject("streamSettings")

        assertEquals("xhttp", stream.getString("network"))
        assertNotNull(stream.optJSONObject("xhttpSettings"))
        assertNotNull(stream.optJSONObject("httpupgradeSettings"))
        assertNotNull(stream.optJSONObject("splithttpSettings"))
        assertFalse(stream.has("xHTTPSettings"))
        assertFalse(stream.has("httpUpgradeSettings"))
        assertFalse(stream.has("splitHTTPSettings"))
        assertFalse(stream.getJSONObject("tlsSettings").has("allowInsecure"))
        assertEquals("none", runtime.getJSONObject("log").getString("access"))
        assertEquals("none", runtime.getJSONObject("log").getString("error"))
    }

    private fun findInbound(inbounds: JSONArray, tag: String): JSONObject {
        for (i in 0 until inbounds.length()) {
            val inbound = inbounds.getJSONObject(i)
            if (inbound.optString("tag") == tag) {
                return inbound
            }
        }
        error("Inbound $tag not found in $inbounds")
    }

    private fun countInboundsByProtocol(inbounds: JSONArray, protocol: String): Int {
        var count = 0
        for (i in 0 until inbounds.length()) {
            if (inbounds.getJSONObject(i).optString("protocol") == protocol) {
                count++
            }
        }
        return count
    }

    private companion object {
        val credentials = LocalProxyCredentials("sessionuser", "sessionsecret")
        const val vlessEncryption =
            "mlkem768x25519plus.native.1rtt.100-500-2000.75-0-100.80-0-5000.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    }
}
