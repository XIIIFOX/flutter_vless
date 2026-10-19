package com.github.tfox.flutter_vless.xray.service

import android.content.pm.ApplicationInfo
import com.github.tfox.flutter_vless.xray.core.*
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.mockito.Answers
import org.mockito.Mockito
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.lang.reflect.InvocationTargetException
import java.net.ServerSocket
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/** Actual admission/producer wiring; queued workers, probes and native parser children are all inert fakes. */
class StartupPreparationServiceTest {
    private fun field(name: String) = XrayVPNService::class.java.getDeclaredField(name).apply { isAccessible = true }
    private fun anyJson(): JSONObject { Mockito.any(JSONObject::class.java); return JSONObject() }
    private fun anyAction(): () -> Unit { Mockito.any<() -> Unit>(); return {} }
    private fun accept(service: XrayVPNService, profile: XrayConfig, outcome: StartupPreparationOutcome): Boolean = try {
        XrayVPNService::class.java.getDeclaredMethod("acceptSession", XrayConfig::class.java, Boolean::class.javaPrimitiveType,
            Long::class.javaPrimitiveType, Boolean::class.javaPrimitiveType, StartupPreparationOutcome::class.java)
            .apply { isAccessible = true }.invoke(service, profile, true, 1L, false, outcome) as Boolean
    } catch (error: InvocationTargetException) { throw error.targetException }

    @Test fun actualAdmissionsKeepReportsWithCheckedPendingCandidatesAndNeverPublishStartFailureAsSuccess() {
        val directory = Files.createTempDirectory("startup-service-report").toFile()
        val service = Mockito.mock(XrayVPNService::class.java, Answers.CALLS_REAL_METHODS)
        Mockito.doReturn(directory).`when`(service).filesDir
        Mockito.doReturn(directory).`when`(service).noBackupFilesDir
        Mockito.doReturn(ApplicationInfo().apply { nativeLibraryDir = directory.absolutePath }).`when`(service).applicationInfo
        val recovery = SessionRecoveryPolicy().apply { activate() }
        val worker = Mockito.mock(SessionWorkQueue::class.java)
        val queued = mutableListOf<() -> Unit>()
        Mockito.doAnswer { queued += it.getArgument<() -> Unit>(0); true }.`when`(worker).execute(anyAction())
        field("requests").set(service, AtomicLong(1)); field("recovery").set(service, recovery)
        field("worker").set(service, worker); field("profiles").set(service, Mockito.mock(AuthorizedProfileStore::class.java))
        val probes = (0..2).map { index ->
            Mockito.mock(SessionReadinessProbe::class.java).also { probe ->
                Mockito.`when`(probe.configure(anyJson(), Mockito.anyInt())).thenAnswer {
                    JSONObject(it.getArgument<JSONObject>(0).toString()).apply {
                        getJSONArray("outbounds").put(JSONObject().put("protocol", "freedom").put("tag", "inert-probe-$index"))
                    }
                }
            }
        }
        Mockito.doReturn(probes[0], probes[1], probes[2]).`when`(service).createReadinessProbe(anyJson())
        val savedConfig = AppConfigs.V2RAY_CONFIG
        val managerFields = listOf("xrayProcess", "runtimeInputs", "lastProxyUplink", "lastProxyDownlink").associateWith { name ->
            XrayCoreManager::class.java.getDeclaredField(name).apply { isAccessible = true }
        }
        val previous = managerFields.mapValues { it.value.get(XrayCoreManager) }
        val generation = XrayDiagnosticsStore::class.java.getDeclaredField("activeGeneration").apply { isAccessible = true }
        val previousGeneration = generation.get(XrayDiagnosticsStore)
        val checked = mutableListOf<ByteArray>()
        try {
            managerFields.values.forEach { it.set(XrayCoreManager, null) }
            Mockito.mockConstruction(ServerSocket::class.java).use {
            Mockito.mockConstruction(AuthorizedProfileStore::class.java).use {
            Mockito.mockConstruction(NativeOptionsStore::class.java) { store, _ ->
                Mockito.`when`(store.read()).thenReturn(NativeVlessOptions())
            }.use {
            Mockito.mockConstruction(ProcessBuilder::class.java) { builder, construction ->
                val args = (construction.arguments()[0] as Array<*>).map { it as String }
                Mockito.`when`(builder.redirectErrorStream(true)).thenReturn(builder)
                Mockito.`when`(builder.environment()).thenReturn(mutableMapOf())
                Mockito.`when`(builder.start()).thenAnswer {
                    checked += java.io.File(args.last()).readBytes()
                    Mockito.mock(Process::class.java).also { process ->
                        Mockito.`when`(process.inputStream).thenReturn(ByteArrayInputStream(byteArrayOf()))
                        Mockito.`when`(process.errorStream).thenReturn(ByteArrayInputStream(byteArrayOf()))
                        Mockito.`when`(process.outputStream).thenReturn(ByteArrayOutputStream())
                        Mockito.`when`(process.isAlive).thenReturn(false)
                        Mockito.`when`(process.exitValue()).thenReturn(0)
                    }
                }
            }.use { commands ->
                val outcomes = (0..1).map { index ->
                    val source = JSONObject("""{"inbounds":[],"outbounds":[{"protocol":"freedom"}],"custom":{"password":"PRIVATE_CANARY_$index"}}""")
                    if (index == 1) source.put("log", JSONObject("""{"loglevel":"none","access":"none","error":"none"}"""))
                    val before = source.toString()
                    val outcome = StartupPreparationOutcome()
                    assertTrue(accept(service, XrayConfig(V2RAY_FULL_JSON_CONFIG = before,
                        GEO_ASSETS_DIRECTORY = directory.absolutePath, PLUGIN_OPTIONS_JSON = "{}"), outcome))
                    @Suppress("UNCHECKED_CAST")
                    val pending = (field("pendingRuntime").get(service) as Pair<Long, SessionRuntimeCandidate<SessionReadinessProbe>>).second
                    assertSame("Report must belong to the exact admitted candidate", pending.preparationReport, outcome.report)
                    assertArrayEquals(checked[index], pending.configuration.bytes)
                    assertTrue(String(checked[index]).contains("inert-probe-$index"))
                    assertEquals(before, source.toString())
                    outcome
                }
                assertEquals(listOf("private_listener_added", "system_dns_guard_added", "private_logging_applied"), outcomes[0].report!!.asMap()["changes"])
                assertEquals(listOf("private_listener_added", "system_dns_guard_added"), outcomes[1].report!!.asMap()["changes"])
                assertFalse(outcomes.map { it.report!!.asMap() }.toString().contains("PRIVATE_CANARY"))
                assertEquals("Admission must not run the asynchronous network-ready worker", 2, queued.size)
                assertEquals(2, commands.constructed().size)
                Mockito.verify(probes[0]).close()
                Mockito.verify(probes[1], Mockito.never()).close()

                val oldChild = Mockito.mock(Process::class.java)
                val stopFailure = IllegalStateException("PRIVATE_CANARY_stop_failure")
                Mockito.doThrow(stopFailure).`when`(oldChild).waitFor(1L, TimeUnit.SECONDS)
                managerFields.getValue("xrayProcess").set(XrayCoreManager, oldChild)
                val failure = StartupPreparationOutcome()
                assertSame(stopFailure, assertThrows(IllegalStateException::class.java) {
                    accept(service, XrayConfig(V2RAY_FULL_JSON_CONFIG = """{"outbounds":[{"protocol":"freedom"}]}""",
                        GEO_ASSETS_DIRECTORY = directory.absolutePath, PLUGIN_OPTIONS_JSON = "{}"), failure)
                })
                assertEquals(PreparationStage.START, failure.stage); assertNull(failure.report)
                Mockito.verify(probes[2]).close()
                assertEquals("Failed admission must not enqueue a new startup", 2, queued.size)
            } } } }
        } finally {
            (field("pendingRuntime").get(service) as? Pair<*, *>)?.second?.let { (it as Closeable).close() }
            managerFields.forEach { (name, member) -> member.set(XrayCoreManager, previous[name]) }
            generation.set(XrayDiagnosticsStore, previousGeneration)
            AppConfigs.V2RAY_CONFIG = savedConfig
            directory.deleteRecursively()
        }
    }
}
