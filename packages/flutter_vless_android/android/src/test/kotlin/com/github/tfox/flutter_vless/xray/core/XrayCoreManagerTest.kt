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

        val output = XrayCoreManager.buildRuntimeConfigJson(config, filesDir)
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
        assertEquals(File(filesDir, "access.log").absolutePath, log.getString("access"))
        assertEquals(File(filesDir, "error.log").absolutePath, log.getString("error"))
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

        val output = XrayCoreManager.buildRuntimeConfigJson(config, File("build/test-files/android-conflicts"))
        val inbounds = output.getJSONArray("inbounds")
        val socks = findInbound(inbounds, "socks_1")
        val http = findInbound(inbounds, "http_1")
        val api = findInbound(inbounds, "api_1")
        val routingRules = output.getJSONObject("routing").getJSONArray("rules")
        val apiRule = routingRules.getJSONObject(routingRules.length() - 1)

        assertEquals(10810, config.LOCAL_SOCKS5_PORT)
        assertEquals(10811, config.LOCAL_HTTP_PORT)
        assertEquals(10812, config.LOCAL_API_PORT)
        assertEquals("socks", socks.getString("protocol"))
        assertEquals(10810, socks.getInt("port"))
        assertEquals("http", http.getString("protocol"))
        assertEquals(10811, http.getInt("port"))
        assertEquals("dokodemo-door", api.getString("protocol"))
        assertEquals(10812, api.getInt("port"))
        assertEquals("api", apiRule.getString("outboundTag"))
        assertEquals("api_1", apiRule.getJSONArray("inboundTag").getString(0))
    }

    @Test
    fun buildRuntimeConfigJson_doesNotDuplicateExistingLocalSocksAndHttpInbounds() {
        val config = XrayConfig(
            LOCAL_SOCKS5_PORT = 10807,
            LOCAL_HTTP_PORT = 10808,
            V2RAY_FULL_JSON_CONFIG = """
                {
                  "inbounds": [
                    { "tag": "socks", "protocol": "socks", "port": 10807 },
                    { "tag": "http", "protocol": "http", "port": 10808 }
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

        val output = XrayCoreManager.buildRuntimeConfigJson(config, File("build/test-files/android-existing"))
        val inbounds = output.getJSONArray("inbounds")

        assertEquals(3, inbounds.length())
        assertEquals(1, countInboundsByProtocol(inbounds, "socks"))
        assertEquals(1, countInboundsByProtocol(inbounds, "http"))
        assertFalse(output.toString().contains("socks_1"))
        assertFalse(output.toString().contains("http_1"))
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
            filesDir = File("build/test-files/android-delay")
        )
        val inbounds = output.getJSONArray("inbounds")
        val delaySocks = findInbound(inbounds, "socks")
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
        assertTrue(output.getJSONObject("log").getString("access").endsWith("access.log"))
        assertTrue(output.has("api"))
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

        val runtime = XrayCoreManager.buildRuntimeConfigJson(config, filesDir)
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
        assertEquals(File(filesDir, "access.log").absolutePath, runtime.getJSONObject("log").getString("access"))
        assertEquals(File(filesDir, "error.log").absolutePath, runtime.getJSONObject("log").getString("error"))
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
        const val vlessEncryption =
            "mlkem768x25519plus.native.1rtt.100-500-2000.75-0-100.80-0-5000.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    }
}
