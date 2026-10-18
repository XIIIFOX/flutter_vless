package com.github.tfox.flutter_vless.xray.core

import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import java.io.File
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class XrayServiceTagsTest {
    @Test fun sharedDefinitionAndReferenceCorpusWithoutMutatingInput() {
        val cases = JSONArray(requireNotNull(javaClass.getResource("/tags.json")).readText())
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val config = c.getJSONObject("config")
            val before = config.toString()
            val tags = XrayServiceTags(config)
            val requests = c.getJSONArray("requests")
            val expected = c.getJSONArray("expected")
            for (j in 0 until requests.length()) assertEquals(c.getString("name"), expected.getString(j), tags.next(requests.getString(j)))
            assertEquals(before, config.toString())
        }
    }

    @Test fun vpnAdapterAndStatsDoNotInheritUserTagsOrDanglingReferences() {
        val raw = """{"api":{"tag":"flutter-vless-tun-1"},"dns":{"tag":"flutter-vless-stats"},
          "reverse":{"portals":[{"tag":"flutter-vless-stats-in"}]},
          "outbounds":[{"protocol":"freedom","tag":"direct"}],
          "routing":{"rules":[{"inboundTag":["flutter-vless-tun"],"outboundTag":"direct"}]}}"""
        val config = XrayConfig(V2RAY_FULL_JSON_CONFIG = raw)
        val output = XrayCoreManager.buildRuntimeConfigJson(config, File("."), LocalProxyCredentials("user", "password"))
        val inbounds = output.getJSONArray("inbounds")
        assertEquals("flutter-vless-tun-2", inbounds.getJSONObject(0).getString("tag"))
        assertEquals("flutter-vless-stats-in-1", inbounds.getJSONObject(1).getString("tag"))
        assertEquals("flutter-vless-stats-1", output.getJSONObject("api").getString("tag"))
        assertEquals(raw, config.V2RAY_FULL_JSON_CONFIG)
    }

    @Test fun protectedDnsAllocatesPrivateNamesForUserOwnedServiceTags() {
        for (tag in listOf(AndroidTunnelDnsPolicy.RELAY_TAG, AndroidTunnelDnsPolicy.UPSTREAM_TAG, AndroidTunnelDnsPolicy.PROXY_TAG)) {
            val source = JSONObject("""{"inbounds":[{"tag":"$tag","protocol":"socks","port":10808}],
              "outbounds":[{"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":19000}]}}],
              "routing":{"rules":[{"inboundTag":["flutter-vless-dns-upstream"],"outboundTag":"proxy"}]}}""")
            val before = source.toString()
            val output = JSONObject(AndroidTunnelDnsPolicy.prepare(before, "proxy").configJson)
            assertEquals("flutter-vless-dns-upstream-1", output.getJSONObject("dns").getString("tag"))
            val relay = output.getJSONArray("outbounds").getJSONObject(1)
            assertEquals(if (tag == AndroidTunnelDnsPolicy.RELAY_TAG) "$tag-1" else AndroidTunnelDnsPolicy.RELAY_TAG, relay.getString("tag"))
            assertEquals(before, source.toString())
        }
    }

    @Test fun protectedDnsAndAdapterShareNativeIdentityIncludingRecoveryAndRejectMissingPreparation() {
        val source = """{"inbounds":[{"tag":"flutter-vless-tun","protocol":"socks","port":10808}],
          "outbounds":[{"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":19000}]}}],
          "routing":{"rules":[{"inboundTag":["flutter-vless-tun-1"],"outboundTag":"proxy"}]}}"""
        val dns = AndroidTunnelDnsPolicy.prepare(source, "proxy")
        assertEquals("flutter-vless-tun-2", dns.managedInboundTag)
        val config = XrayConfig(V2RAY_FULL_JSON_CONFIG = dns.configJson, ANDROID_DNS_POLICY = "proxy")
        val secret = LocalProxyCredentials("user", "password")
        repeat(2) {
            val runtime = XrayCoreManager.buildRuntimeConfigJson(config.copy(), File("."), secret, dns)
            val adapter = runtime.getJSONArray("inbounds").getJSONObject(1)
            assertEquals(dns.managedInboundTag, adapter.getString("tag"))
            val dnsRule = runtime.getJSONObject("routing").getJSONArray("rules").getJSONObject(2)
            assertEquals(dns.managedInboundTag, dnsRule.getJSONArray("inboundTag").getString(0))
            assertEquals("198.18.0.2/32", dnsRule.getJSONArray("ip").getString(0))
        }
        assertThrows(IllegalArgumentException::class.java) {
            XrayCoreManager.buildRuntimeConfigJson(config.copy(), File("."), secret)
        }
        assertThrows(IllegalArgumentException::class.java) {
            XrayCoreManager.buildRuntimeConfigJson(config.copy(V2RAY_FULL_JSON_CONFIG = source), File("."), secret, dns)
        }
        assertThrows(IllegalArgumentException::class.java) {
            XrayCoreManager.buildRuntimeConfigJson(config.copy(PROXY_ONLY = true), File("."), secret, dns)
        }
        XrayCoreManager.validateConfiguration(XrayConfig(V2RAY_FULL_JSON_CONFIG = source, ANDROID_DNS_POLICY = "proxy"))
    }
}
