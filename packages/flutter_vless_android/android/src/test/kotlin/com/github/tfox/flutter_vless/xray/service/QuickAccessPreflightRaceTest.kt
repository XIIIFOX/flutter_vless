package com.github.tfox.flutter_vless.xray.service

import android.content.pm.ApplicationInfo
import com.github.tfox.flutter_vless.xray.core.XrayCoreManager
import com.github.tfox.flutter_vless.xray.core.LocalProxyCredentials
import com.github.tfox.flutter_vless.xray.core.StartupPreparationOutcome
import com.github.tfox.flutter_vless.xray.core.PreparationStage
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
class QuickAccessPreflightRaceTest {
    // Mockito's Java matcher returns null; keep Kotlin's non-null call boundary inert.
    private fun anyJson(): JSONObject { Mockito.any(JSONObject::class.java); return JSONObject() }
    private fun anyProfile(): XrayConfig { Mockito.any(XrayConfig::class.java); return XrayConfig() }
    private fun set(target: Any, name: String, value: Any?) = target.javaClass.getDeclaredField(name)
        .apply { isAccessible = true }.set(target, value)
    private fun accept(service: XrayVPNService, profile: XrayConfig, outcome: StartupPreparationOutcome): Boolean = try {
        XrayVPNService::class.java.getDeclaredMethod("acceptSession", XrayConfig::class.java,
            Boolean::class.javaPrimitiveType, Long::class.javaPrimitiveType, Boolean::class.javaPrimitiveType,
            StartupPreparationOutcome::class.java)
            .apply { isAccessible = true }.invoke(service, profile, true, 1L, false, outcome) as Boolean
    } catch (error: InvocationTargetException) { throw error.targetException }

    private fun fixture(changeDuringCheck:Boolean, pendingTile:Boolean) {
        // Android jar defaults SDK_INT to zero in plain JVM tests. This only changes the fake SDK constant.
        // Reflection keeps the JDK-only fixture implementation off the Android compiler's type path.
        // Availability/access are runtime prerequisites on the CI JDK17; this is not a prior qualified seam.
        val unsafeClass=Class.forName("sun.misc.Unsafe")
        val unsafe=unsafeClass.getDeclaredField("theUnsafe").apply {isAccessible=true}.get(null)
        val sdk=android.os.Build.VERSION::class.java.getDeclaredField("SDK_INT")
        Class.forName(sdk.declaringClass.name,true,sdk.declaringClass.classLoader)
        val sdkBase=unsafeClass.getMethod("staticFieldBase",java.lang.reflect.Field::class.java).invoke(unsafe,sdk)
        val sdkOffset=(unsafeClass.getMethod("staticFieldOffset",java.lang.reflect.Field::class.java).invoke(unsafe,sdk) as Number).toLong()
        val getInt=unsafeClass.getMethod("getInt",Any::class.java,java.lang.Long.TYPE)
        val putInt=unsafeClass.getMethod("putInt",Any::class.java,java.lang.Long.TYPE,java.lang.Integer.TYPE)
        val previousSdk=(getInt.invoke(unsafe,sdkBase,sdkOffset) as Number).toInt()
        putInt.invoke(unsafe,sdkBase,sdkOffset,34)
        var currentOptions=NativeVlessOptions(quickAccess=NativeVlessOptions.QuickAccess(enabled=true))
        var revision="a".repeat(32)
        val directory = Files.createTempDirectory("native-service-admission").toFile()
        val service = Mockito.mock(XrayVPNService::class.java, Answers.CALLS_REAL_METHODS)
        Mockito.doReturn(directory).`when`(service).filesDir
        Mockito.doReturn(directory).`when`(service).noBackupFilesDir
        Mockito.doReturn(ApplicationInfo().apply { nativeLibraryDir = directory.path }).`when`(service).applicationInfo
        val rejectFinal=false;val staleDuringCheck=false;val failSave=false
        val routingCapability:Int?=null;val allTcpOccupied=false;val failProbePreparation=false
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
        // Baseline has no pending-ticket field: its actual admission still runs, so the old result fails semantically.
        if(pendingTile) runCatching {
            val actionClass=Class.forName("com.github.tfox.flutter_vless.xray.service.QuickAccessAction")
            val operation=Class.forName(actionClass.name+"\$Operation").enumConstants.first {it.toString()=="START"}
            val action=actionClass.declaredConstructors.first {it.parameterCount==5}
                .newInstance(revision,"toggle",operation,0L,"b".repeat(64))
            val pendingClass=Class.forName("com.github.tfox.flutter_vless.xray.service.PendingQuickStart")
            val pending=pendingClass.declaredConstructors.first {it.parameterCount==2}.newInstance(1L,action)
            set(service,"pendingQuickStart",pending)
        }.getOrElse {if(it !is ClassNotFoundException && it !is NoSuchFieldException) throw it}

        set(service, "requests", requests); set(service, "recovery", recovery); set(service, "profiles", profiles)
        set(service, "config", active)
        val processField = XrayCoreManager::class.java.getDeclaredField("xrayProcess").apply { isAccessible = true }
        val managerMembers=listOf("xrayProcess","runtimeInputs","lastProxyUplink","lastProxyDownlink").associateWith {name ->
            XrayCoreManager::class.java.getDeclaredField(name).apply {isAccessible=true}
        }
        val previous=managerMembers.mapValues {it.value.get(XrayCoreManager)}
        managerMembers.values.forEach {it.set(XrayCoreManager,null)}
        val previousConfig=com.github.tfox.flutter_vless.xray.utils.AppConfigs.V2RAY_CONFIG
        val diagnostics=com.github.tfox.flutter_vless.xray.core.XrayDiagnosticsStore
        val diagnosticsGeneration=diagnostics.javaClass.getDeclaredField("activeGeneration").apply {isAccessible=true}
        val previousGeneration=diagnosticsGeneration.get(diagnostics)
        val oldChild = Mockito.mock(Process::class.java)
        Mockito.`when`(oldChild.waitFor(1L, java.util.concurrent.TimeUnit.SECONDS)).thenReturn(true)
        processField.set(XrayCoreManager, oldChild)
        val incoming = XrayConfig(V2RAY_FULL_JSON_CONFIG = """{"inbounds":[],"outbounds":[{"protocol":"freedom"}],"routing":{"rules":[]}}""",
            GEO_ASSETS_DIRECTORY = directory.absolutePath, PLUGIN_OPTIONS_JSON = com.google.gson.Gson().toJson(currentOptions),
            VPN_ROUTING_SELECTION_JSON = if(routingCapability == null) null else "{}")
        var checkedFinal = false
        val queue=Mockito.mock(SessionWorkQueue::class.java)
        set(service,"worker",queue)
        val keyguard=Mockito.mock(android.app.KeyguardManager::class.java)
        Mockito.doReturn(keyguard).`when`(service).getSystemService(android.app.KeyguardManager::class.java)
        val preparationOutcome = StartupPreparationOutcome()
        try {
            // No real ServerSocket constructor or bind is executed in this control.
            Mockito.mockConstruction(NativeOptionsStore::class.java, Mockito.withSettings().defaultAnswer { call ->
                when(call.method.name) {
                    "read" -> currentOptions
                    "readSnapshot" -> Class.forName("com.github.tfox.flutter_vless.xray.service.QuickAccessSnapshot")
                        .declaredConstructors.first {it.parameterCount==2}.newInstance(currentOptions,revision)
                    "withSnapshot" -> {
                        val ticket=call.getArgument<Any>(0)
                        val wanted=ticket.javaClass.getDeclaredMethod("getRevision").invoke(ticket)
                        if(wanted != revision || !currentOptions.quickAccess.enabled) null
                        else call.getArgument<(NativeVlessOptions)->Any?>(2)(currentOptions)
                    }
                    else -> Answers.RETURNS_DEFAULTS.answer(call)
                }
            }).use { stores ->
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
                        if (changeDuringCheck) {
                            currentOptions=currentOptions.copy(quickAccess=currentOptions.quickAccess.copy(enabled=false))
                            revision="c".repeat(32)
                        }
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
                val accepted=accept(service,incoming,preparationOutcome)
                if(pendingTile && changeDuringCheck) {
                    assertFalse("Historical implementation admits stale tile after disable",accepted)
                    Mockito.verify(profiles,Mockito.never()).save(anyProfile())
                    Mockito.verify(oldChild,Mockito.never()).destroy()
                    assertSame(active,XrayVPNService::class.java.getDeclaredField("config").apply {isAccessible=true}.get(service))
                    assertEquals(1L,recovery.generation)
                    Mockito.verify(probe).close()
                    assertNull(preparationOutcome.report)
                } else {
                    // Ordinary explicit app Start is deliberately independent of Quick Access disable.
                    assertTrue(accepted)
                    Mockito.verify(profiles).save(anyProfile())
                    assertNotNull(preparationOutcome.report)
                }
                assertEquals(1,builds.constructed().size)
                assertTrue(checkedFinal)
            }
            }
            }
        } finally {
            (XrayVPNService::class.java.getDeclaredField("pendingRuntime").apply {isAccessible=true}.get(service) as? Pair<*,*>)
                ?.second?.let {(it as java.io.Closeable).close()}
            managerMembers.forEach {(name,member)->member.set(XrayCoreManager,previous[name])}
            diagnosticsGeneration.set(diagnostics,previousGeneration)
            com.github.tfox.flutter_vless.xray.utils.AppConfigs.V2RAY_CONFIG=previousConfig
            putInt.invoke(unsafe,sdkBase,sdkOffset,previousSdk)
            directory.deleteRecursively()
        }
    }
    @Test fun disabledTileDuringActualFinalPreflightCannotSaveOrReplaceSession() = fixture(true,true)
    @Test fun unchangedTileStillAcceptsExactCheckedCandidate() = fixture(false,true)
    @Test fun ordinaryExplicitAppStartIsNotRevokedByQuickAccessDisable() = fixture(true,false)
}
