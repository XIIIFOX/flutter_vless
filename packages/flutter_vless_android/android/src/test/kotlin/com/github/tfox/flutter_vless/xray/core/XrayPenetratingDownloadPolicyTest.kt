package com.github.tfox.flutter_vless.xray.core

import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import java.io.File
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** File-only preparation and runtime serialization; no Core, process or listener. */
class XrayPenetratingDownloadPolicyTest {
    private fun profile(penetrate: Boolean = true): JSONObject = JSONObject("""{
      "inbounds":[],
      "dns":{"servers":["tcp://192.0.2.53"],"hosts":{"caller.invalid":"192.0.2.9"}},
      "outbounds":[{"tag":"proxy","protocol":"vless",
        "settings":{"address":"upload.test","port":443,
          "id":"11111111-1111-4111-8111-111111111111","encryption":"none"},
        "streamSettings":{"network":"xhttp","sockopt":{"penetrate":$penetrate,"tcpKeepAliveIdle":30},
          "xhttpSettings":{"path":"/upload","extra":{"downloadSettings":{
            "address":"download.test","port":8443,"network":"xhttp","security":"tls",
            "tlsSettings":{"serverName":"download-tls.invalid","allowInsecure":true,"alpn":["h2"]},
            "sockopt":{"domainStrategy":"UseIPv6","dialerProxy":"dormant-child","tcpKeepAliveIdle":7},
            "xhttpSettings":{"path":"/download"}}}}}},
        {"tag":"direct","protocol":"freedom"}]
    }""")

    private fun stream(config: JSONObject): JSONObject =
        config.getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")

    private fun download(config: JSONObject): JSONObject =
        stream(config).getJSONObject("xhttpSettings").getJSONObject("extra").getJSONObject("downloadSettings")

    private fun prepare(source: JSONObject, resolved: MutableList<String> = mutableListOf(),
                        environment: (String) -> String? = { error("No environment lookup expected") }): AndroidTunnelDnsPolicy.Prepared {
        val before = source.toString()
        try {
            return AndroidTunnelDnsPolicy.prepare(before, "proxy", environment = environment) { name ->
                resolved += name
                listOf(when (name) {
                    "upload.test" -> "192.0.2.7"
                    "download.test" -> "192.0.2.8"
                    else -> error("An inactive download destination reached physical bootstrap")
                })
            }
        } finally { assertEquals("Caller JSON changed", before, source.toString()) }
    }

    @Test fun penetratingChildSocketPolicyIsRetainedWhileActiveTlsStillReachesRuntimeCleanup() {
        val source = profile()
        download(source).getJSONObject("sockopt").put("addressPortStrategy", "srvportonly")
        val socketBefore = download(source).getJSONObject("sockopt").toString()
        val tlsBefore = download(source).getJSONObject("tlsSettings").toString()
        val prepared = prepare(source)
        val config = JSONObject(prepared.configJson)
        assertEquals(socketBefore, download(config).getJSONObject("sockopt").toString())
        assertEquals(tlsBefore, download(config).getJSONObject("tlsSettings").toString())
        assertEquals("ForceIP", stream(config).getJSONObject("sockopt").getString("domainStrategy"))
        assertEquals(setOf("upload.test", "download.test"), prepared.bootstrapHostnames)

        val runtime = XrayCoreManager.buildRuntimeConfigJson(
            XrayConfig(V2RAY_FULL_JSON_CONFIG = prepared.configJson), File("."),
            LocalProxyCredentials("penetrating-user", "penetrating-secret"), prepared,
            tcpAvailable = { true }, environment = { error("No listener environment lookup expected") })
        assertEquals(socketBefore, download(runtime).getJSONObject("sockopt").toString())
        val tls = download(runtime).getJSONObject("tlsSettings")
        assertFalse("Active download TLS cleanup was skipped", tls.has("allowInsecure"))
        assertEquals("download-tls.invalid", tls.getString("serverName"))
        assertEquals("[\"h2\"]", tls.getJSONArray("alpn").toString())
    }

    @Test fun activeParentAndNonpenetratingChildSrvPoliciesRemainRefusedBeforeBootstrap() {
        for (parent in listOf(true, false)) {
            val source = profile(penetrate = parent)
            val options = if (parent) stream(source).getJSONObject("sockopt") else download(source).getJSONObject("sockopt")
            options.put("addressPortStrategy", "srvportonly")
            val resolved = mutableListOf<String>()
            val error = assertThrows(IllegalArgumentException::class.java) { prepare(source, resolved) }
            assertTrue(error.message.orEmpty().contains("SRV/TXT"))
            assertTrue("A refused active socket policy reached bootstrap", resolved.isEmpty())
        }
    }

    @Test fun penetratingDownloadStillFreezesAndPinsItsImmediateAddressAndRejectsTheVirtualResolver() {
        val source = profile()
        download(source).put("address", "env:DOWNLOAD_ENDPOINT")
        val resolved = mutableListOf<String>(); val environment = mutableListOf<String>()
        val prepared = prepare(source, resolved) { name ->
            environment += name
            assertEquals("DOWNLOAD_ENDPOINT", name)
            "download.test"
        }
        assertEquals(listOf("DOWNLOAD_ENDPOINT"), environment)
        assertEquals(listOf("upload.test", "download.test"), resolved)
        assertEquals("download.test", download(JSONObject(prepared.configJson)).getString("address"))

        val reserved = profile()
        download(reserved).put("address", AndroidTunnelDnsPolicy.VIRTUAL_SERVER)
        val callbacks = mutableListOf<String>()
        val error = assertThrows(IllegalArgumentException::class.java) { prepare(reserved, callbacks) }
        assertTrue(error.message.orEmpty().contains("conflicts with virtual system DNS"))
        assertTrue("An invalid immediate download destination reached bootstrap", callbacks.isEmpty())
    }

    @Test fun penetratingImmediateClientDoesNotBootstrapItsUnusedNestedDownload() {
        val source = profile()
        val nested = JSONObject().put("address", "inactive-nested.test").put("port", 9443).put("network", "xhttp")
            .put("sockopt", JSONObject().put("addressPortStrategy", "srvportonly"))
            .put("xhttpSettings", JSONObject().put("path", "/inactive"))
        download(source).getJSONObject("xhttpSettings").put("downloadSettings", nested)
        val nestedBefore = nested.toString(); val resolved = mutableListOf<String>()
        val prepared = prepare(source, resolved)
        assertEquals(listOf("upload.test", "download.test"), resolved)
        assertEquals(nestedBefore, download(JSONObject(prepared.configJson)).getJSONObject("xhttpSettings")
            .getJSONObject("downloadSettings").toString())
    }

    @Test fun immediateDownloadRequiresEffectiveXhttpTransportBeforeBootstrap() {
        for (penetrate in listOf(true, false)) {
            for ((network, method) in listOf("tcp" to null, "xhttp" to "tcp")) {
                val source = profile(penetrate)
                download(source).put("network", network)
                if (method != null) download(source).put("method", method)
                val resolved = mutableListOf<String>()
                val error = assertThrows(IllegalArgumentException::class.java) { prepare(source, resolved) }
                assertTrue(error.message.orEmpty().contains("XHTTP download transport"))
                assertTrue("Invalid download transport reached bootstrap", resolved.isEmpty())
            }
        }
    }

    @Test fun immediateDownloadUsesMethodBeforeNetworkAndRetainsNullOrMissingMethodFallback() {
        for (method in listOf<Any?>("xhttp", JSONObject.NULL, null)) {
            val source = profile()
            val child = download(source)
            child.put("network", if (method == "xhttp") "tcp" else "xhttp")
            if (method != null) child.put("method", method)
            val resolved = mutableListOf<String>()
            val actual = download(JSONObject(prepare(source, resolved).configJson))
            assertEquals(listOf("upload.test", "download.test"), resolved)
            assertEquals(child.getString("network"), actual.getString("network"))
            assertEquals(child.has("method"), actual.has("method"))
            if (child.has("method")) assertEquals(child.get("method"), actual.get("method"))
            assertEquals(child.getJSONObject("sockopt").toString(), actual.getJSONObject("sockopt").toString())
        }
    }

    @Test fun nonpenetratingImmediateClientDoesNotAdmitOrPinItsUnusedTcpGrandchild() {
        val source = profile(penetrate = false)
        source.getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").put("address", "192.0.2.7")
        val child = download(source).put("address", "192.0.2.8")
        child.getJSONObject("sockopt").remove("dialerProxy")
        val nested = JSONObject().put("address", "192.0.2.9").put("port", 9443).put("network", "tcp")
            .put("sockopt", JSONObject().put("dialerProxy", "missing-grandchild"))
        child.getJSONObject("xhttpSettings").put("downloadSettings", nested)
        val nestedBefore = nested.toString(); val resolved = mutableListOf<String>()
        val prepared = prepare(source, resolved)
        assertTrue("Numeric upload/download required physical DNS", resolved.isEmpty())
        assertTrue(prepared.bootstrapHostnames.isEmpty())
        assertEquals(setOf("192.0.2.7", "192.0.2.8"), prepared.bootstrapAddresses)
        val actualChild = download(JSONObject(prepared.configJson))
        assertEquals("ForceIP", actualChild.getJSONObject("sockopt").getString("domainStrategy"))
        assertEquals(nestedBefore, actualChild.getJSONObject("xhttpSettings").getJSONObject("downloadSettings").toString())
        val profile = XrayConfig(V2RAY_FULL_JSON_CONFIG = prepared.configJson)
        val before = profile.V2RAY_FULL_JSON_CONFIG
        val runtime = XrayCoreManager.buildRuntimeConfigJson(profile, File("."),
            LocalProxyCredentials("chain-user", "chain-secret"), prepared,
            tcpAvailable = { true }, environment = { error("No listener environment lookup expected") })
        assertEquals(nestedBefore, download(runtime).getJSONObject("xhttpSettings").getJSONObject("downloadSettings").toString())
        assertEquals(before, profile.V2RAY_FULL_JSON_CONFIG)
    }
}
