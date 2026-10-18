package com.github.tfox.flutter_vless.xray.core

import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import java.io.File
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class FullProfileCompatibilityTest {
    @Test fun fullProfilePreservesImportedListenersAndRoutingWhileIsolatingTunnelAdapter() {
        val raw = """{
          "inbounds":[
            {"tag":"socks-in","listen":"127.0.0.1","port":10808,"protocol":"socks","settings":{"auth":"noauth","udp":true},"sniffing":{"enabled":true,"routeOnly":true,"destOverride":["http","tls","quic"],"domainsExcluded":[],"metadataOnly":false}},
            {"tag":"socks-direct","listen":"127.0.0.1","port":10820,"protocol":"socks","settings":{"auth":"noauth","udp":true},"sniffing":{"enabled":true,"routeOnly":false,"domainsExcluded":["excluded.invalid"]}},
            {"tag":"flutter-vless-tun","listen":"127.0.0.1","port":"10807-10809","protocol":"http","settings":{"accounts":[{"user":"app","pass":"app-password"}]}}
          ],
          "outbounds":[{"tag":"proxy","protocol":"vless","settings":{"address":"endpoint.invalid","port":443,"id":"22222222-2222-4222-8222-222222222222","encryption":"none","flow":"xtls-rprx-vision"}},{"tag":"direct","protocol":"freedom"},{"tag":"flutter-vless-stats","protocol":"blackhole"}],
          "routing":{"domainStrategy":"AsIs","rules":[{"inboundTag":["socks-direct"],"outboundTag":"direct"}]}
        }""".trimIndent()
        val original = JSONObject(raw)
        val config = XrayConfig(V2RAY_FULL_JSON_CONFIG = raw)
        val credentials = LocalProxyCredentials("native-user", "native-password")
        XrayCoreManager.validateConfiguration(config)
        val result = XrayCoreManager.buildRuntimeConfigJson(config, File("."), credentials)
        val inputs = result.getJSONArray("inbounds")
        for (index in 0 until 3) {
            assertEquals(original.getJSONArray("inbounds").getJSONObject(index).toString(), inputs.getJSONObject(index).toString())
        }
        val managed = inputs.getJSONObject(3)
        assertEquals("flutter-vless-tun-1", managed.getString("tag"))
        assertEquals(10810, config.LOCAL_SOCKS5_PORT)
        assertEquals("password", managed.getJSONObject("settings").getString("auth"))
        assertEquals("native-password", managed.getJSONObject("settings").getJSONArray("accounts").getJSONObject(0).getString("pass"))
        val rules = result.getJSONObject("routing").getJSONArray("rules")
        assertEquals(original.getJSONObject("routing").getJSONArray("rules").getJSONObject(0).toString(), rules.getJSONObject(1).toString())
        assertEquals("flutter-vless-stats-1", result.getJSONObject("api").getString("tag"))
        assertEquals("flutter-vless-stats-1", rules.getJSONObject(0).getString("outboundTag"))
        assertEquals(raw, config.V2RAY_FULL_JSON_CONFIG)
    }

    @Test fun privatePortAllocationWrapsWithoutUsingInvalidPorts() {
        val config = XrayConfig(LOCAL_SOCKS5_PORT = 65535,
            V2RAY_FULL_JSON_CONFIG = """{"inbounds":[{"protocol":"socks","port":"65534-65535","listen":"127.0.0.1"}],"outbounds":[{"protocol":"freedom"}]}""")
        XrayCoreManager.buildRuntimeConfigJson(config, File("."), LocalProxyCredentials("user", "secret"))
        assertEquals(1024, config.LOCAL_SOCKS5_PORT)
    }
}
