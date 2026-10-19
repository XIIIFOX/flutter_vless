package com.github.tfox.flutter_vless.xray.service

import android.content.pm.ApplicationInfo
import com.github.tfox.flutter_vless.xray.core.XrayCoreManager
import com.github.tfox.flutter_vless.xray.core.LocalProxyCredentials
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.mockito.Answers
import org.mockito.Mockito
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.lang.reflect.InvocationTargetException
import java.net.BindException
import java.net.ServerSocket
import java.net.SocketAddress
import java.nio.file.Files
import java.util.concurrent.atomic.AtomicLong

/** Calls the actual service admission method with mocked probe/ProcessBuilder only. */
class SessionRuntimeAdmissionTest {
    @Test fun readinessProbeReceivesAllFutureListenerPortsBeforeOpeningItsSocket() {
        for (callerApi in listOf(false,true)) {
            val source=JSONObject("""{"inbounds":[{"protocol":"http","listen":"127.0.0.1","port":"10807-10808"},{"protocol":"http","listen":"/tmp/owned-probe-corpus.sock","port":"0-65535"},{"protocol":"http","listen":"127.0.0.1","port":0}],"metrics":{"listen":"127.0.0.1:+10810"},"outbounds":[{"protocol":"freedom"}]}""")
            if (callerApi) source.put("api",JSONObject("""{"tag":"caller-api","listen":"127.0.0.1:10809","services":["StatsService"]}"""))
            val base=XrayCoreManager.buildRuntimeConfigJson(XrayConfig(V2RAY_FULL_JSON_CONFIG=source.toString()),
                File("."),LocalProxyCredentials("synthetic-user","synthetic-password"))
            val before=base.toString();val arguments=mutableListOf<List<Any?>>()
            val service=Mockito.mock(XrayVPNService::class.java,Answers.CALLS_REAL_METHODS)
            // Constructor interception skips the real listener and worker entirely.
            Mockito.mockConstruction(SessionReadinessProbe::class.java) { _, construction ->
                arguments.add(construction.arguments().toList())
            }.use { probes ->
                service.createReadinessProbe(base).use { probe ->
                    assertSame(probes.constructed().single(),probe)
                    assertEquals(before,base.toString())
                    assertEquals("Actual service must pass host and future TCP exclusions",2,arguments.single().size)
                    assertEquals((10807..10811).toSet(),arguments.single()[1])
                }
            }
        }
    }

    // Mockito's Java matcher returns null; keep Kotlin's non-null call boundary inert.
    private fun anyJson(): JSONObject { Mockito.any(JSONObject::class.java); return JSONObject() }
    private fun anyProfile(): XrayConfig { Mockito.any(XrayConfig::class.java); return XrayConfig() }
    private fun set(target: Any, name: String, value: Any?) = target.javaClass.getDeclaredField(name)
        .apply { isAccessible = true }.set(target, value)
    private fun accept(service: XrayVPNService, profile: XrayConfig): Boolean = try {
        XrayVPNService::class.java.getDeclaredMethod("acceptSession", XrayConfig::class.java,
            Boolean::class.javaPrimitiveType, Long::class.javaPrimitiveType, Boolean::class.javaPrimitiveType)
            .apply { isAccessible = true }.invoke(service, profile, true, 1L, false) as Boolean
    } catch (error: InvocationTargetException) { throw error.targetException }

    private fun fixture(rejectFinal: Boolean = false, staleDuringCheck: Boolean = false, failSave: Boolean = false,
                        routingCapability: Int? = null, allTcpOccupied: Boolean = false, failProbePreparation: Boolean = false) {
        val directory = Files.createTempDirectory("native-service-admission").toFile()
        val service = Mockito.mock(XrayVPNService::class.java, Answers.CALLS_REAL_METHODS)
        Mockito.doReturn(directory).`when`(service).filesDir
        Mockito.doReturn(directory).`when`(service).noBackupFilesDir
        Mockito.doReturn(ApplicationInfo().apply { nativeLibraryDir = directory.path }).`when`(service).applicationInfo
        val probe = Mockito.mock(SessionReadinessProbe::class.java) // Never invokes its socket-binding constructor.
        if (failProbePreparation) Mockito.doThrow(IllegalStateException("Synthetic probe listener exhaustion"))
            .`when`(service).createReadinessProbe(anyJson())
        else Mockito.doReturn(probe).`when`(service).createReadinessProbe(anyJson())
        Mockito.`when`(probe.configure(anyJson(), Mockito.anyInt())).thenAnswer {
            JSONObject(it.getArgument<JSONObject>(0).toString()).apply {
                getJSONArray("outbounds").put(JSONObject().put("tag", "synthetic-final-probe").put("protocol", "freedom"))
                val rules=getJSONObject("routing").getJSONArray("rules")
                val managed=getJSONArray("inbounds").getJSONObject(0).getString("tag")
                getJSONObject("routing").put("rules",JSONArray().put(JSONObject().put("type", "field")
                    .put("inboundTag", JSONArray().put(managed)).put("outboundTag", "synthetic-final-probe")).also { next ->
                        for(index in 0 until rules.length()) next.put(rules.get(index))
                    })
            }
        }
        val requests = AtomicLong(1); val recovery = SessionRecoveryPolicy().apply { activate() }
        val profiles = Mockito.mock(AuthorizedProfileStore::class.java)
        val saveFailure = IllegalStateException("Synthetic profile save refusal")
        // An old implementation must stop at this tripwire, never reach old-worker cleanup.
        if (failSave || allTcpOccupied) Mockito.doThrow(saveFailure).`when`(profiles).save(anyProfile())
        val active = XrayConfig(REMARK = "Existing accepted session")
        set(service, "requests", requests); set(service, "recovery", recovery); set(service, "profiles", profiles)
        set(service, "config", active)
        val processField = XrayCoreManager::class.java.getDeclaredField("xrayProcess").apply { isAccessible = true }
        val previous = processField.get(XrayCoreManager); val oldChild = Mockito.mock(Process::class.java)
        processField.set(XrayCoreManager, oldChild)
        val incoming = XrayConfig(V2RAY_FULL_JSON_CONFIG = """{"inbounds":[],"outbounds":[{"protocol":"freedom"}],"routing":{"rules":[]}}""",
            GEO_ASSETS_DIRECTORY = directory.absolutePath, PLUGIN_OPTIONS_JSON = "{}",
            VPN_ROUTING_SELECTION_JSON = if(routingCapability == null) null else "{}")
        var checkedFinal = false
        try {
            // No real ServerSocket constructor or bind is executed in this control.
            Mockito.mockConstruction(ServerSocket::class.java) { listener, _ ->
                if (allTcpOccupied) {
                    Mockito.doThrow(BindException("Synthetic occupied TCP listener")).`when`(listener)
                        .bind(Mockito.any(SocketAddress::class.java), Mockito.anyInt())
                    Mockito.doThrow(BindException("Synthetic occupied TCP listener")).`when`(listener)
                        .bind(Mockito.any(SocketAddress::class.java))
                }
            }.use { listeners ->
            Mockito.mockConstruction(ProcessBuilder::class.java) { builder, construction ->
                val args = (construction.arguments()[0] as Array<*>).map { it as String }
                Mockito.`when`(builder.redirectErrorStream(true)).thenReturn(builder)
                Mockito.`when`(builder.environment()).thenReturn(mutableMapOf())
                Mockito.`when`(builder.start()).thenAnswer {
                    val capability=args.last()=="capabilities"
                    if (!capability) {
                        val path=if(args.contains("--config")) args[args.indexOf("--config")+1] else args.last()
                        checkedFinal = File(path).readText().contains("synthetic-final-probe")
                        if(args.contains("--spec")) {
                            val data=File(path).readBytes()
                            val metadata=JSONObject(File(args[args.indexOf("--spec")+1]).readText())
                            val hash=java.security.MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }
                            assertEquals(hash,metadata.getString("source_sha256"))
                            assertEquals("[0,2]",metadata.getJSONArray("guard_rule_indices").toString())
                        }
                        if (staleDuringCheck) requests.incrementAndGet()
                    }
                    Mockito.mock(Process::class.java).also { child ->
                        val output=if(capability) "{\"stage\":\"capabilities\",\"code\":0,\"capability\":$routingCapability}" else if(routingCapability != null) "{\"stage\":\"check\",\"code\":0}" else ""
                        Mockito.`when`(child.inputStream).thenReturn(ByteArrayInputStream(output.toByteArray()))
                        Mockito.`when`(child.errorStream).thenReturn(ByteArrayInputStream(byteArrayOf()))
                        Mockito.`when`(child.outputStream).thenReturn(ByteArrayOutputStream())
                        Mockito.`when`(child.isAlive).thenReturn(false)
                        Mockito.`when`(child.exitValue()).thenReturn(if (rejectFinal && checkedFinal) 3 else 0)
                    }
                }
            }.use { builds ->
                if (allTcpOccupied) {
                    val outcome=runCatching { accept(service, incoming) }
                    assertSame(oldChild, processField.get(XrayCoreManager))
                    Mockito.verify(oldChild, Mockito.never()).destroy()
                    Mockito.verify(oldChild, Mockito.never()).destroyForcibly()
                    assertEquals("Occupied generated TCP listeners must refuse before saving a candidate",0,
                        Mockito.mockingDetails(profiles).invocations.count { it.method.name=="save" })
                    assertEquals("Only 32 OS candidates may be tested before refusal",32,listeners.constructed().size)
                    listeners.constructed().forEach { Mockito.verify(it).close() }
                    assertEquals("No Core parser process is needed after allocation exhaustion",0,builds.constructed().size)
                    assertFalse(outcome.getOrThrow())
                    Mockito.verify(service,Mockito.never()).createReadinessProbe(anyJson())
                } else if (failSave) assertSame(saveFailure, assertThrows(IllegalStateException::class.java) { accept(service, incoming) })
                else assertFalse(accept(service, incoming))
                if (!allTcpOccupied) assertEquals(if(failProbePreparation) 0 else if(routingCapability == 1) 2 else 1, builds.constructed().size)
            }
            }
            if(allTcpOccupied || failProbePreparation || routingCapability == 0) assertFalse(checkedFinal)
            else assertTrue("Actual service native preflight must include generated readiness rule", checkedFinal)
            assertSame(active, XrayVPNService::class.java.getDeclaredField("config").apply { isAccessible = true }.get(service))
            assertEquals(1L, recovery.generation)
            assertSame(oldChild, processField.get(XrayCoreManager))
            Mockito.verify(oldChild, Mockito.never()).destroy()
            Mockito.verify(oldChild, Mockito.never()).destroyForcibly()
            if(allTcpOccupied || failProbePreparation || routingCapability == 0) Mockito.verify(probe,Mockito.never()).close() else Mockito.verify(probe).close()
            if (!failSave) Mockito.verify(profiles, Mockito.never()).save(anyProfile())
        } finally { processField.set(XrayCoreManager, previous); directory.deleteRecursively() }
    }
    @Test fun finalNativeRejectionNeverSavesOrStopsAnExistingAcceptedSession() = fixture(rejectFinal = true)
    @Test fun stopDuringSlowFinalCheckClosesOnlyCandidateAndDoesNotReplaceActiveSession() = fixture(staleDuringCheck = true)
    @Test fun profileSaveFailureClosesCandidateAndLeavesOldWorkersAndGenerationUntouched() = fixture(failSave = true)
    @Test fun unsupportedInstalledRuntimeRefusesBeforeProbeProfileOrActiveStop() = fixture(routingCapability=0)
    @Test fun requestedRoutingChecksFinalConfigAndSpecBeforeRejectingWithoutChangingActiveSession() = fixture(routingCapability=1,rejectFinal=true)
    @Test fun occupiedGeneratedTcpListenersRefuseBeforeSavingOrStoppingAnAcceptedSession() = fixture(allTcpOccupied=true)
    @Test fun failedProbePreparationNeverSavesOrStopsAnAcceptedSession() = fixture(failProbePreparation=true)
}
