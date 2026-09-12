package com.github.tfox.flutter_vless.xray.core

import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.io.File

class LocalProxyAccessPolicyTest {
    private val secret = LocalProxyCredentials("native-user", "native-password")
    @Test fun securesAllManagedInputsWithoutChangingRemoteCredentialsOrCreatingHttp() {
        val raw = """{"inbounds":[{"tag":"socks","protocol":"socks","listen":"127.0.0.1","port":10807,"settings":{"auth":"noauth","udp":true}}],"outbounds":[{"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"proxy.example","port":1080,"users":[{"user":"remote-user","pass":"remote-password"}]}]}}]}"""
        val output = XrayCoreManager.buildRuntimeConfigJson(XrayConfig(V2RAY_FULL_JSON_CONFIG = raw), File("."), secret)
        val inbound = output.getJSONArray("inbounds").getJSONObject(0)
        assertEquals("password", inbound.getJSONObject("settings").getString("auth"))
        assertEquals("native-password", inbound.getJSONObject("settings").getJSONArray("accounts").getJSONObject(0).getString("pass"))
        assertEquals(JSONObject(raw).getJSONArray("outbounds").toString(), output.getJSONArray("outbounds").toString())
        assertFalse(output.getJSONArray("inbounds").toString().contains("\"protocol\":\"http\""))
        assertTrue(output.has("api"))
    }
    @Test fun rejectsWildcardAndCustomSecondaryInputsBeforeMutatingSource() {
        for (listen in listOf("0.0.0.0", "", "::", "127.0.0.2")) {
            val inputs = JSONArray().put(JSONObject().put("protocol", "socks").put("listen", listen).put("port", 10807))
            assertThrows(IllegalArgumentException::class.java) { LocalProxyAccessPolicy.apply(inputs, secret, 10807) }
        }
        val custom = JSONArray("""[{"tag":"custom","protocol":"http","listen":"127.0.0.1","port":8181}]""")
        assertThrows(IllegalArgumentException::class.java) { LocalProxyAccessPolicy.apply(custom, secret, 10807) }
    }
    @Test fun proxyOnlyPreservesExplicitAccountsAndExplicitNoauth() {
        for (settings in listOf("{\"auth\":\"noauth\"}", "{\"auth\":\"password\",\"accounts\":[{\"user\":\"app\",\"pass\":\"secret\"}]}")) {
            val raw = """{"inbounds":[{"tag":"public","protocol":"socks","listen":"0.0.0.0","port":10807,"settings":$settings}],"outbounds":[{"protocol":"freedom"}]}"""
            val output = XrayCoreManager.buildRuntimeConfigJson(XrayConfig(V2RAY_FULL_JSON_CONFIG = raw, PROXY_ONLY = true), File("."))
            assertEquals(JSONObject(settings).toString(), output.getJSONArray("inbounds").getJSONObject(0).getJSONObject("settings").toString())
        }
    }
    @Test fun proxyOnlyUsersAliasAccountsPrecedenceAndUnknownAuthAreValidatedBeforeActivation() {
        for (settings in listOf(
            """{"Auth":"password","Users":[{"User":"alias-user","Pass":"alias-pass"}]}""",
            """{"auth":"password","users":[{"user":"old","pass":"old"}],"accounts":[{"user":"alias-user","pass":"alias-pass"}]}"""
        )) {
            val raw = """{"inbounds":[{"protocol":"socks","listen":"127.0.0.1","port":10807,"settings":$settings}],"outbounds":[{"protocol":"freedom"}]}"""
            val json = XrayCoreManager.buildRuntimeConfigJson(XrayConfig(V2RAY_FULL_JSON_CONFIG = raw, PROXY_ONLY = true), File("."))
            assertEquals("alias-pass", LocalProxyAccessPolicy.credentialsForProxyOnly(json, 10807)?.password)
        }
        val raw = """{"inbounds":[{"protocol":"socks","listen":"127.0.0.1","port":10807,"settings":{"auth":"misspelled-password"}}],"outbounds":[{"protocol":"freedom"}]}"""
        assertThrows(IllegalArgumentException::class.java) { XrayCoreManager.validateConfiguration(XrayConfig(V2RAY_FULL_JSON_CONFIG = raw, PROXY_ONLY = true)) }
    }

    @Test fun nativeCaseAliasesCannotOpenSecondaryUnauthenticatedListeners() {
        val raw = """{"Inbounds":[{"tag":"http","Protocol":"http","Listen":"127.0.0.1","Port":18081,"Settings":{}}],"Outbounds":[{"protocol":"freedom"}],"Log":{"loglevel":"debug"}}"""
        val json = XrayCoreManager.buildRuntimeConfigJson(XrayConfig(V2RAY_FULL_JSON_CONFIG = raw), File("."), secret)
        val http = json.getJSONArray("inbounds").getJSONObject(0)
        assertEquals("native-password", http.getJSONObject("settings").getJSONArray("accounts").getJSONObject(0).getString("pass"))
        assertEquals("none", json.getJSONObject("log").getString("loglevel"))
        for (rawDuplicate in listOf(
            """{"inboundſ":[],"outbounds":[{"protocol":"freedom"}]}""",
            """{"inbounds":[],"Inbounds":[],"outbounds":[{"protocol":"freedom"}]}""",
            """{"inbounds":[{"protocol":"socks","Protocol":"http","listen":"127.0.0.1","port":10807}],"outbounds":[{"protocol":"freedom"}]}""",
            """{"inbounds":[{"protocol":"socks","listen":"127.0.0.1","port":10807,"settings":{"auth":"password","Auth":"noauth"}}],"outbounds":[{"protocol":"freedom"}]}"""
        )) assertThrows(IllegalArgumentException::class.java) {
            XrayCoreManager.buildRuntimeConfigJson(XrayConfig(V2RAY_FULL_JSON_CONFIG = rawDuplicate), File("."), secret)
        }
    }

    @Test fun secretsAreRotatedAndCannotAppearViaToString() {
        val first = LocalProxyCredentials.generate(); val second = LocalProxyCredentials.generate()
        assertNotEquals(first.password, second.password)
        assertTrue(first.password.length >= 32)
        assertFalse(first.toString().contains(first.password))
    }
}
