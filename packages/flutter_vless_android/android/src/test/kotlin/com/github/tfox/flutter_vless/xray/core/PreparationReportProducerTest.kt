package com.github.tfox.flutter_vless.xray.core

import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.service.SessionRuntimeCandidate
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.io.Closeable
import java.io.File
import java.nio.file.Files

/** Actual typed producers and candidate preflight with inert callbacks only. */
class PreparationReportProducerTest {
    private val secret = "PRIVATE_CANARY_path-host-tag-password"
    private val credentials = LocalProxyCredentials("synthetic-user", secret)
    private fun unchangedProxy() = JSONObject("""{
        "inbounds":[{"tag":"caller","protocol":"socks","listen":"127.0.0.1","port":10807,"settings":{"auth":"noauth"}}],
        "outbounds":[{"tag":"edge-live","protocol":"socks","settings":{"address":"192.0.2.7","port":443}}],
        "api":{"tag":"caller-api","services":["StatsService"]},
        "log":{"loglevel":"none","access":"none","error":"none"}}
    """)

    private fun report(runtime: JSONObject, changes: PreparationChanges): Map<String, Any> =
        SessionRuntimeCandidate.prepare<Closeable>(runtime, { null }, { _, _ -> error("No real probe") },
            { true }, changes = changes).use { it.preparationReport.asMap() }

    @Test fun actualTypedChangesProduceOnlyClosedCodesAndNeverPrivateOrOpaqueValues() {
        val directory = Files.createTempDirectory("startup-report-certificates").toFile()
        try {
            val source = unchangedProxy().apply {
                remove("api"); remove("log")
                getJSONArray("inbounds").getJSONObject(0).put("protocol", "http").put("listen", "env:LISTEN").put("port", "env:PORT")
                getJSONArray("outbounds").getJSONObject(0).put("streamSettings", JSONObject().put("security", "tls")
                    .put("tlsSettings", JSONObject().put("certificates", JSONArray().put(JSONObject().put("certificateFile", "$secret.pem")))))
                put("dns", JSONObject().put("servers", JSONArray().put("env:DNS")))
                put("custom", JSONObject().put("certificateFile", "$secret.opaque").put("address", "env:$secret"))
            }
            val before = source.toString(); val changes = PreparationChanges()
            val env = mapOf("LISTEN" to "127.0.0.1", "PORT" to "10807", "DNS" to "9.9.9.9")
            val dns = AndroidTunnelDnsPolicy.prepare(before, environment = env::get, changes = changes) {
                error("Caller root must not bootstrap endpoints")
            }
            val profile = XrayConfig(V2RAY_FULL_JSON_CONFIG = dns.configJson, CERTIFICATE_ASSETS_DIRECTORY = directory.absolutePath)
            val runtime = XrayCoreManager.buildRuntimeConfigJson(profile, directory, credentials, dns,
                tcpAvailable = { true }, changes = changes, environment = env::get)
            assertEquals("env:PORT", runtime.getJSONArray("inbounds").getJSONObject(0).getString("port"))
            assertEquals("127.0.0.1", runtime.getJSONArray("inbounds").getJSONObject(0).getString("listen"))
            assertEquals("9.9.9.9", runtime.getJSONObject("dns").getJSONArray("servers").getString(0))
            assertEquals(directory.resolve("$secret.pem").absolutePath, runtime.getJSONArray("outbounds").getJSONObject(0)
                .getJSONObject("streamSettings").getJSONObject("tlsSettings").getJSONArray("certificates").getJSONObject(0).getString("certificateFile"))
            assertEquals(source.getJSONObject("custom").toString(), runtime.getJSONObject("custom").toString())
            val result = report(runtime, changes)
            assertEquals(listOf("certificate_refs_bound", "private_listener_added", "system_dns_guard_added",
                "private_logging_applied", "address_environment_bound"), result["changes"])
            assertEquals(setOf("version", "scope", "coreCheck", "changes"), result.keys)
            assertFalse(JSONObject(result).toString().contains(secret))
            assertEquals(before, source.toString())
        } finally { directory.deleteRecursively() }
    }

    @Test fun noChangeAndOpaqueArgumentsDoNotInventOperations() {
        val directory = Files.createTempDirectory("startup-report-no-change").toFile()
        try {
            val source = unchangedProxy().apply {
                getJSONArray("outbounds").getJSONObject(0).put("streamSettings", JSONObject().put("security", "tls")
                    .put("tlsSettings", JSONObject().put("certificates", JSONArray().put(JSONObject()
                        .put("certificateFile", directory.resolve("already-absolute.pem").absolutePath).put("keyFile", "")))))
                put("custom", JSONObject().put("address", "env:$secret").put("certificateFile", "$secret.pem"))
            }
            val before = source.toString(); val changes = PreparationChanges()
            val profile = XrayConfig(PROXY_ONLY = true, V2RAY_FULL_JSON_CONFIG = before, CERTIFICATE_ASSETS_DIRECTORY = directory.absolutePath)
            val runtime = XrayCoreManager.buildRuntimeConfigJson(profile, directory, credentials, changes = changes,
                tcpAvailable = { error("No new private listener") }, environment = { error("Opaque values are not environment bindings") })
            assertEquals(emptyList<String>(), report(runtime, changes)["changes"])
            assertEquals(before, source.toString())
        } finally { directory.deleteRecursively() }
    }

    @Test fun individualActualProducerOperationsAreNotInferredFromSuppliedOptions() {
        val directory = Files.createTempDirectory("startup-report-one-change").toFile()
        try {
            for (expected in listOf("certificate_refs_bound", "private_listener_added", "private_logging_applied", "address_environment_bound")) {
                val source = unchangedProxy()
                when (expected) {
                    "certificate_refs_bound" -> source.getJSONArray("outbounds").getJSONObject(0).put("streamSettings",
                        JSONObject("""{"security":"tls","tlsSettings":{"certificates":[{"keyFile":"relative.key"}]}}"""))
                    "private_listener_added" -> source.remove("api")
                    "private_logging_applied" -> source.getJSONObject("log").put("loglevel", "info")
                    "address_environment_bound" -> source.getJSONArray("inbounds").getJSONObject(0).put("listen", "env:LISTEN")
                }
                val before = source.toString(); val changes = PreparationChanges()
                val runtime = XrayCoreManager.buildRuntimeConfigJson(XrayConfig(PROXY_ONLY = true, V2RAY_FULL_JSON_CONFIG = before,
                    CERTIFICATE_ASSETS_DIRECTORY = directory.absolutePath), directory, credentials, changes = changes,
                    tcpAvailable = { true }, environment = { if (it == "LISTEN") "127.0.0.1" else error("Unexpected lookup") })
                assertEquals(expected, listOf(expected), report(runtime, changes)["changes"])
                assertEquals(before, source.toString())
            }
        } finally { directory.deleteRecursively() }
    }

    @Test fun opaqueLogMetadataKeepsTheSameSummaryWhileRemovedTypedLogFieldsAreObserved() {
        fun changes(extra: Pair<String, Any>?): List<*> {
            val source = unchangedProxy()
            extra?.let { source.getJSONObject("log").put(it.first, it.second) }
            val before = source.toString(); val observed = PreparationChanges()
            val runtime = XrayCoreManager.buildRuntimeConfigJson(XrayConfig(PROXY_ONLY = true, V2RAY_FULL_JSON_CONFIG = before),
                File("."), credentials, changes = observed, environment = { error("No environment lookup") })
            val log = runtime.getJSONObject("log")
            assertEquals(setOf("access", "error", "loglevel"), log.keys().asSequence().toSet())
            for (key in listOf("access", "error", "loglevel")) assertEquals("none", log.getString(key))
            assertEquals(before, source.toString())
            return report(runtime, observed)["changes"] as List<*>
        }
        val unchanged = changes(null)
        assertEquals(emptyList<String>(), unchanged)
        assertEquals("Opaque-only log metadata must not alter the report", unchanged,
            changes("opaqueCanary" to JSONObject().put("password", secret)))
        // These five owners are the pinned Core LogConfig schema. Extra typed
        // dnsLog/maskAddress fields and alternate spellings are actually removed.
        for (field in listOf("dnsLog" to false, "dnsLog" to true, "DNSLOG" to JSONObject.NULL,
            "maskAddress" to "", "maſkAddress" to "quarter", "LOGLEVEL" to "none")) {
            assertEquals(field.first, listOf("private_logging_applied"), changes(field))
        }
    }

    @Test fun checkedCandidateSnapshotsOnlyItsOwnFinalizationBeforeValidationAndAdmission() {
        val changes = PreparationChanges().apply { record(PreparationChange.PRIVATE_LISTENER_ADDED) }
        val source = unchangedProxy(); val before = source.toString()
        var checked: NativeRuntimeConfig? = null
        val first = SessionRuntimeCandidate.prepare<Closeable>(source, { null }, { _, _ -> error("No probe") }, {
            checked = it
            changes.record(PreparationChange.CERTIFICATE_REFS_BOUND) // Too late to describe the checked bytes.
            true
        }, changes = changes)
        val second = SessionRuntimeCandidate.prepare<Closeable>(source, { null }, { _, _ -> error("No probe") }, { true })
        try {
            assertSame(checked, first.configuration)
            assertArrayEquals(before.toByteArray(), first.configuration.bytes)
            assertEquals(listOf("private_listener_added"), first.preparationReport.asMap()["changes"])
            assertEquals(emptyList<String>(), second.preparationReport.asMap()["changes"])
            changes.record(PreparationChange.ADDRESS_ENVIRONMENT_BOUND)
            assertEquals(listOf("private_listener_added"), first.preparationReport.asMap()["changes"])
            assertTrue(second.admit({ true }, {}) { true })
            assertFalse(first.admit({ false }, { error("Stale request must not persist") }) { error("Stale request must not stop the active owner") })
            assertEquals(emptyList<String>(), second.preparationReport.asMap()["changes"])
        } finally { first.close(); second.close() }
    }
}
