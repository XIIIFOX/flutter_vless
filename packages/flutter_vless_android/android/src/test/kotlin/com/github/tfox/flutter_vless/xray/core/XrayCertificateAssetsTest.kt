package com.github.tfox.flutter_vless.xray.core

import com.github.tfox.flutter_vless.FlutterVlessPlugin
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.google.gson.Gson
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.nio.file.Files

class XrayCertificateAssetsTest {
    private val rootField = "CERTIFICATE_ASSETS_DIRECTORY"
    private val credentials = LocalProxyCredentials("fixture-user", "fixture-password")

    // Gson ignores this new field on the old implementation. That gives a
    // functional regression against the existing runtime builder before adding
    // the optional DTO property, rather than a compile-only missing API test.
    private fun profile(source: String, directory: String?, proxyOnly: Boolean = false): XrayConfig =
        Gson().fromJson(JSONObject().put("V2RAY_FULL_JSON_CONFIG", source).put("PROXY_ONLY", proxyOnly)
            .apply { if (directory != null) put(rootField, directory) }.toString(), XrayConfig::class.java)

    private fun replaceBoundPaths(config: JSONObject, paths: JSONArray, directory: File): JSONObject {
        val expected = JSONObject(config.toString())
        for (index in 0 until paths.length()) {
            val path = paths.getString(index).removePrefix("/").split('/').map { it.replace("~1", "/").replace("~0", "~") }
            var parent: Any = expected
            for (part in path.dropLast(1))
                parent = if (parent is JSONArray) parent.get(part.toInt()) else (parent as JSONObject).get(part)
            val owner = parent as JSONObject
            owner.put(path.last(), directory.resolve(owner.getString(path.last())).normalize().absolutePath)
        }
        return expected
    }

    @Test fun sharedCertificatePathsBindOnlyCoreBuiltTlsFilesBeforeRuntimePreparation() {
        val directory = Files.createTempDirectory("xray-certificates-corpus").toFile()
        try {
            val cases = JSONArray(requireNotNull(javaClass.getResource("/certificate-paths.json")).readText())
            assertEquals(6, cases.length())
            for (index in 0 until cases.length()) for (proxyOnly in listOf(false, true)) {
                val item = cases.getJSONObject(index); val label = item.getString("name") + "/" + proxyOnly
                val input = item.getJSONObject("config"); val before = input.toString()
                val expected = replaceBoundPaths(input, item.getJSONArray("bind"), directory)
                val config = profile(before, directory.absolutePath, proxyOnly)
                val runtime = XrayCoreManager.buildRuntimeConfigJson(config, directory, credentials)
                for (collection in listOf("inbounds", "outbounds")) {
                    val sourceEntries = expected.optJSONArray(collection) ?: continue
                    for (entry in 0 until sourceEntries.length()) {
                        val sourceStream = sourceEntries.getJSONObject(entry).opt("streamSettings") ?: continue
                        val actualStream = runtime.getJSONArray(collection).getJSONObject(entry).get("streamSettings")
                        assertEquals(label, sourceStream.toString(), actualStream.toString())
                    }
                }
                for (field in listOf("remarks", "other")) if (input.has(field))
                    assertEquals(label, input.get(field).toString(), runtime.get(field).toString())
                assertEquals(label, before, config.V2RAY_FULL_JSON_CONFIG)
                assertEquals(label, before, input.toString())
            }
            assertEquals("Selecting a directory must not copy/read certificate files", 0, directory.listFiles()!!.size)
        } finally { directory.deleteRecursively() }
    }

    @Test fun certificateRootRejectsMissingRelativeAndFileDirectoriesBeforeConfigAcceptance() {
        val directory = Files.createTempDirectory("xray-certificates-validation").toFile()
        try {
            val regular = directory.resolve("regular").apply { writeText("fixture") }
            val source = """{"outbounds":[{"protocol":"freedom"}]}"""
            for (requested in listOf("", "relative/certificates", directory.resolve("missing").absolutePath, regular.absolutePath)) {
                val config = profile(source, requested, proxyOnly = true)
                assertThrows(IllegalArgumentException::class.java) { XrayCoreManager.validateConfiguration(config) }
                assertEquals(source, config.V2RAY_FULL_JSON_CONFIG)
            }
        } finally { directory.deleteRecursively() }
    }

    @Test fun certificateRootSurvivesCopyAndPersistedProfileSnapshotsWithoutChangingSource() {
        val directory = Files.createTempDirectory("xray-certificates-snapshot").toFile()
        try {
            val source = """{"outbounds":[{"protocol":"freedom"}]}"""
            val config = profile(source, directory.absolutePath)
            for (snapshot in listOf(config, config.copy(), Gson().fromJson(Gson().toJson(config), XrayConfig::class.java))) {
                assertEquals(directory.absolutePath, JSONObject(Gson().toJson(snapshot)).getString(rootField))
                assertEquals(source, snapshot.V2RAY_FULL_JSON_CONFIG)
            }
            assertFalse(JSONObject(Gson().toJson(Gson().fromJson("{}", XrayConfig::class.java))).has(rootField))
        } finally { directory.deleteRecursively() }
    }

    @Test fun pureCertificatePreparationChangesExactlyDeclaredFieldsAndKeepsNullLegacy() {
        val directory = Files.createTempDirectory("xray-certificates-pure").toFile()
        try {
            val cases = JSONArray(requireNotNull(javaClass.getResource("/certificate-paths.json")).readText())
            for (index in 0 until cases.length()) {
                val item = cases.getJSONObject(index); val source = item.getJSONObject("config"); val before = source.toString()
                assertEquals(item.getString("name"), replaceBoundPaths(source, item.getJSONArray("bind"), directory).toString(),
                    XrayCertificateAssets.prepare(before, directory.absolutePath).toString())
                assertEquals(before, XrayCertificateAssets.prepare(before, null).toString())
                assertEquals(before, source.toString())
            }
            // Inactive malformed TLS and the dormant alias are never inspected.
            val dormant = """{"outbounds":[{"protocol":"freedom","streamSettings":{"security":"none","tlsSettings":42,"xhttpSettings":{"extra":null},"splithttpSettings":42}}]}"""
            assertEquals(JSONObject(dormant).toString(), XrayCertificateAssets.prepare(dormant, directory.absolutePath).toString())
        } finally { directory.deleteRecursively() }
    }

    @Test fun absoluteInlinePathsAndReloadOwnersRemainIndependentAcrossStartAndDelayPreparation() {
        val directory = Files.createTempDirectory("xray-certificates-owners").toFile()
        try {
            val first = directory.resolve("first").apply { mkdir() }
            val second = directory.resolve("second").apply { mkdir() }
            val absolute = first.resolve("absolute.pem").absolutePath
            val certificate = JSONObject().put("CertificateFile", "reload/fixture.pem").put("keyFile", absolute)
                .put("certificate", JSONArray().put("inline certificate unchanged"))
                .put("key", JSONArray().put("inline key unchanged"))
                .put("oneTimeLoading", false).put("ocspStapling", 120).put("buildChain", true)
            val source = JSONObject().put("outbounds", JSONArray().put(JSONObject().put("protocol", "freedom")
                .put("streamSettings", JSONObject().put("security", "TLS")
                    .put("TLSSettingſ", JSONObject().put("certificateſ", JSONArray().put(certificate)
                        .put(JSONObject().put("certificateFile", "../parent.pem").put("keyFile", "")))))))
                .put("custom", JSONObject().put("certificateFile", "../fixture.pem"))
            val before = source.toString()
            val runtimeFirst = XrayCoreManager.buildRuntimeConfigJson(profile(before, first.absolutePath), directory, credentials)
            val oldOwner = runtimeFirst.toString()
            val runtimeSecond = XrayCoreManager.buildRuntimeConfigJson(profile(before, second.absolutePath), directory, credentials)
            val (delay, _) = XrayCoreManager.buildDelayConfigJson(before, 19080, directory, credentials, second.absolutePath)
            fun cert(config: JSONObject) = config.getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")
                .getJSONObject("TLSSettingſ").getJSONArray("certificateſ").getJSONObject(0)
            assertEquals(first.resolve("reload/fixture.pem").normalize().absolutePath, cert(runtimeFirst).getString("CertificateFile"))
            for (prepared in listOf(runtimeSecond, delay))
                assertEquals(second.resolve("reload/fixture.pem").normalize().absolutePath, cert(prepared).getString("CertificateFile"))
            for (prepared in listOf(runtimeFirst, runtimeSecond, delay)) {
                val actual = cert(prepared)
                assertEquals(absolute, actual.getString("keyFile"))
                for (key in listOf("certificate", "key", "oneTimeLoading", "ocspStapling", "buildChain"))
                    assertEquals(certificate.get(key).toString(), actual.get(key).toString())
                assertEquals(source.getJSONObject("custom").toString(), prepared.getJSONObject("custom").toString())
                val parentPath = prepared.getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")
                    .getJSONObject("TLSSettingſ").getJSONArray("certificateſ").getJSONObject(1)
                assertEquals(directory.resolve("parent.pem").absolutePath, parentPath.getString("certificateFile"))
                assertEquals("", parentPath.getString("keyFile"))
            }
            assertThrows(IllegalArgumentException::class.java) {
                XrayCoreManager.buildRuntimeConfigJson(profile(before, directory.resolve("missing").absolutePath), directory, credentials)
            }
            assertEquals(oldOwner, runtimeFirst.toString())
            assertEquals(before, source.toString())
            assertEquals(0, first.listFiles()!!.size); assertEquals(0, second.listFiles()!!.size)
        } finally { directory.deleteRecursively() }
    }

    @Test fun certificateChannelRejectsNonstringBeforeNativeContextAndAdvertisesSupport() {
        val plugin = FlutterVlessPlugin()
        class Response : MethodChannel.Result {
            var value: Any? = null
            var code: String? = null
            var message: String? = null
            override fun success(result: Any?) { value = result }
            override fun error(errorCode: String, errorMessage: String?, errorDetails: Any?) {
                code = errorCode; message = errorMessage; assertNull(errorDetails)
            }
            override fun notImplemented() = fail("Certificate capability/channel unavailable")
        }
        val capability = Response()
        plugin.onMethodCall(MethodCall("getSecurityCapabilities", null), capability)
        assertEquals(true, (capability.value as Map<*, *>)["certificateAssetsDirectory"])
        // The plugin is deliberately unattached: bad new arguments must be
        // refused before touching stores, activities, executors or workers.
        for (method in listOf("startVless", "getServerDelay")) {
            for (value in listOf<Any>(42, true, emptyList<Any>(), mapOf("path" to "opaque"))) {
                val result = Response()
                plugin.onMethodCall(MethodCall(method, mapOf("certificate_assets_directory" to value)), result)
                assertEquals("INVALID_CONFIG", result.code)
                assertEquals("Certificate asset directory must be a string", result.message)
                assertNull(result.value)
            }
        }
    }
}
