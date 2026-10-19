package com.github.tfox.flutter_vless.xray.service

import android.content.pm.ApplicationInfo
import com.github.tfox.flutter_vless.xray.core.XrayCoreManager
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
import java.nio.file.Files
import java.util.concurrent.atomic.AtomicLong

/** Calls the actual service admission method with mocked probe/ProcessBuilder only. */
class SessionRuntimeAdmissionTest {
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

    private fun fixture(rejectFinal: Boolean = false, staleDuringCheck: Boolean = false, failSave: Boolean = false) {
        val directory = Files.createTempDirectory("native-service-admission").toFile()
        val service = Mockito.mock(XrayVPNService::class.java, Answers.CALLS_REAL_METHODS)
        Mockito.doReturn(directory).`when`(service).filesDir
        Mockito.doReturn(directory).`when`(service).noBackupFilesDir
        Mockito.doReturn(ApplicationInfo().apply { nativeLibraryDir = directory.path }).`when`(service).applicationInfo
        val probe = Mockito.mock(SessionReadinessProbe::class.java) // Never invokes its socket-binding constructor.
        Mockito.doReturn(probe).`when`(service).createReadinessProbe(anyJson())
        Mockito.`when`(probe.configure(anyJson(), Mockito.anyInt())).thenAnswer {
            JSONObject(it.getArgument<JSONObject>(0).toString()).apply {
                getJSONArray("outbounds").put(JSONObject().put("tag", "synthetic-final-probe").put("protocol", "freedom"))
                getJSONObject("routing").getJSONArray("rules").put(JSONObject().put("type", "field")
                    .put("inboundTag", JSONArray().put("synthetic-private")).put("outboundTag", "synthetic-final-probe"))
            }
        }
        val requests = AtomicLong(1); val recovery = SessionRecoveryPolicy().apply { activate() }
        val profiles = Mockito.mock(AuthorizedProfileStore::class.java)
        val saveFailure = IllegalStateException("Synthetic profile save refusal")
        if (failSave) Mockito.doThrow(saveFailure).`when`(profiles).save(anyProfile())
        val active = XrayConfig(REMARK = "Existing accepted session")
        set(service, "requests", requests); set(service, "recovery", recovery); set(service, "profiles", profiles)
        set(service, "config", active)
        val processField = XrayCoreManager::class.java.getDeclaredField("xrayProcess").apply { isAccessible = true }
        val previous = processField.get(XrayCoreManager); val oldChild = Mockito.mock(Process::class.java)
        processField.set(XrayCoreManager, oldChild)
        val incoming = XrayConfig(V2RAY_FULL_JSON_CONFIG = """{"inbounds":[],"outbounds":[{"protocol":"freedom"}],"routing":{"rules":[]}}""",
            GEO_ASSETS_DIRECTORY = directory.absolutePath, PLUGIN_OPTIONS_JSON = "{}")
        var checkedFinal = false
        try {
            Mockito.mockConstruction(ProcessBuilder::class.java) { builder, construction ->
                val args = (construction.arguments()[0] as Array<*>).map { it as String }
                Mockito.`when`(builder.redirectErrorStream(true)).thenReturn(builder)
                Mockito.`when`(builder.environment()).thenReturn(mutableMapOf())
                Mockito.`when`(builder.start()).thenAnswer {
                    checkedFinal = File(args.last()).readText().contains("synthetic-final-probe")
                    if (staleDuringCheck) requests.incrementAndGet()
                    Mockito.mock(Process::class.java).also { child ->
                        Mockito.`when`(child.inputStream).thenReturn(ByteArrayInputStream(byteArrayOf()))
                        Mockito.`when`(child.errorStream).thenReturn(ByteArrayInputStream(byteArrayOf()))
                        Mockito.`when`(child.outputStream).thenReturn(ByteArrayOutputStream())
                        Mockito.`when`(child.isAlive).thenReturn(false)
                        Mockito.`when`(child.exitValue()).thenReturn(if (rejectFinal && checkedFinal) 3 else 0)
                    }
                }
            }.use { builds ->
                if (failSave) assertSame(saveFailure, assertThrows(IllegalStateException::class.java) { accept(service, incoming) })
                else assertFalse(accept(service, incoming))
                assertEquals(1, builds.constructed().size)
            }
            assertTrue("Actual service native preflight must include generated readiness rule", checkedFinal)
            assertSame(active, XrayVPNService::class.java.getDeclaredField("config").apply { isAccessible = true }.get(service))
            assertEquals(1L, recovery.generation)
            assertSame(oldChild, processField.get(XrayCoreManager))
            Mockito.verify(oldChild, Mockito.never()).destroy()
            Mockito.verify(oldChild, Mockito.never()).destroyForcibly()
            Mockito.verify(probe).close()
            if (!failSave) Mockito.verify(profiles, Mockito.never()).save(anyProfile())
        } finally { processField.set(XrayCoreManager, previous); directory.deleteRecursively() }
    }
    @Test fun finalNativeRejectionNeverSavesOrStopsAnExistingAcceptedSession() = fixture(rejectFinal = true)
    @Test fun stopDuringSlowFinalCheckClosesOnlyCandidateAndDoesNotReplaceActiveSession() = fixture(staleDuringCheck = true)
    @Test fun profileSaveFailureClosesCandidateAndLeavesOldWorkersAndGenerationUntouched() = fixture(failSave = true)
}
