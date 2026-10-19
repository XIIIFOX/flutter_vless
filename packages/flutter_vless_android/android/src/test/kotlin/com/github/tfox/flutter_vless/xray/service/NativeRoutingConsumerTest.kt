package com.github.tfox.flutter_vless.xray.service

import com.github.tfox.flutter_vless.xray.core.*
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.google.gson.Gson
import android.content.Context
import android.content.pm.ApplicationInfo
import org.mockito.Mockito
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

/** Inert channel maps/JSON only; no real probe, process, Core or socket. */
class NativeRoutingConsumerTest {
    @Test fun absentIsOrdinaryButEmptyMapExplicitlyRequestsFactory() {
        assertNull(NativeRoutingSelection.encode(null, false))
        assertNull(NativeRoutingSelection.decode(null, false))
        assertNotNull(NativeRoutingSelection.decode(NativeRoutingSelection.encode(emptyMap<String, Any>(), false), false))
    }
    @Test fun sourceZeroAndByteExactDefaultSurviveSelectionSnapshot() {
        val snapshot=NativeRoutingSelection.encode(mapOf("sourceInboundIndex" to 0, "defaultOutboundTag" to " e\u0301 "), false)
        val intent=NativeRoutingSelection.decode(snapshot, false)!!
        assertEquals(0, intent.sourceInboundIndex); assertEquals(" e\u0301 ", intent.defaultOutboundTag)
        assertFalse(snapshot!!.contains("auth_user"))
    }
    @Test fun nativeMapRejectsUnknownFractionalNullNegativeAndOutOfRangeSource() {
        for (raw in listOf<Any>("{}", mapOf("unknown" to 1), mapOf("sourceInboundIndex" to null),
            mapOf("sourceInboundIndex" to -1), mapOf("sourceInboundIndex" to 0.0),
            mapOf("sourceInboundIndex" to 2147483648L), mapOf("defaultOutboundTag" to 1))) {
            assertThrows(IllegalArgumentException::class.java) { NativeRoutingSelection.encode(raw, false) }
        }
    }
    @Test fun explicitNullOrEmptyDefaultKeepsCoreDefaultWithoutErasingExplicitRequest() {
        for (raw in listOf(mapOf("defaultOutboundTag" to null), mapOf("defaultOutboundTag" to ""))) {
            val encoded=NativeRoutingSelection.encode(raw, false)!!
            assertFalse(JSONObject(encoded).has("defaultOutboundTag"))
            assertNotNull(NativeRoutingSelection.decode(encoded, false))
        }
    }
    @Test fun proxyOnlyAndMalformedRetainedSelectionsFailClosed() {
        assertThrows(IllegalArgumentException::class.java) { NativeRoutingSelection.encode(emptyMap<String, Any>(), true) }
        for (raw in listOf("[]", "{} trailing", "{\"sourceInboundIndex\":null}", "{\"unknown\":1}"))
            assertThrows(IllegalArgumentException::class.java) { NativeRoutingSelection.decode(raw, false) }
        assertThrows(IllegalArgumentException::class.java) { NativeRoutingSelection.decode("{}", true) }
    }

    private class Child(text: String, val code: Int=0) : Process() {
        val input=ByteArrayInputStream(text.toByteArray()); val output=ByteArrayOutputStream()
        override fun getInputStream()=input
        override fun getOutputStream()=output
        override fun getErrorStream()=ByteArrayInputStream(byteArrayOf())
        override fun isAlive()=false
        override fun exitValue()=code
        override fun waitFor():Int=throw AssertionError("No unbounded wait")
        override fun waitFor(timeout:Long, unit:TimeUnit)=true
        override fun destroy()=Unit
    }
    private fun source()=JSONObject("""{"inbounds":[{"tag":"user","protocol":"socks","listen":"127.0.0.1","port":19000}],"outbounds":[{"tag":"blocked","protocol":"blackhole"},{"tag":"chosen","protocol":"freedom"}],"routing":{"rules":[{"type":"field","inboundTag":["flutter-vless-tun"],"outboundTag":"chosen"}]}}""")
    private fun plan(callerApi: Boolean=false, proxyDns: Boolean=false): Pair<JSONObject, NativeRoutingPreparation> {
        val raw=source().apply {
            if (callerApi) put("api", JSONObject.NULL)
            if (proxyDns) getJSONArray("outbounds").getJSONObject(1).put("protocol","socks")
                .put("settings",JSONObject().put("address","127.0.0.1").put("port",18080))
        }.toString()
        val profile=XrayConfig(V2RAY_FULL_JSON_CONFIG=raw, ANDROID_DNS_POLICY=if(proxyDns)"proxy" else "config",
            ANDROID_DNS_PROXY_OUTBOUND_TAG=if(proxyDns)"chosen" else null, VPN_ROUTING_SELECTION_JSON="{\"sourceInboundIndex\":0,\"defaultOutboundTag\":\"chosen\"}")
        XrayCoreManager.validateConfiguration(profile)
        val dns=AndroidTunnelDnsPolicy.prepare(raw,profile.ANDROID_DNS_POLICY,profile.ANDROID_DNS_PROXY_OUTBOUND_TAG)
        profile.V2RAY_FULL_JSON_CONFIG=dns.configJson
        var prepared:NativeRoutingPreparation?=null
        val result=XrayCoreManager.buildRuntimeConfigJson(profile, java.io.File("."), LocalProxyCredentials("synthetic-user", "synthetic-password"), dns,
            routingPrepared={ prepared=it })
        return result to requireNotNull(prepared)
    }
    private fun addProbe(base:JSONObject):JSONObject {
        val copy=JSONObject(base.toString()); val inputs=copy.getJSONArray("inbounds")
        val tag=inputs.getJSONObject(1).getString("tag")
        val rules=copy.getJSONObject("routing").getJSONArray("rules")
        copy.getJSONObject("routing").put("rules", JSONArray().put(JSONObject().put("type","field")
            .put("inboundTag",JSONArray().put(tag)).put("outboundTag","chosen")).also { next ->
                for (i in 0 until rules.length()) next.put(rules.get(i))
            })
        return copy
    }
    @Test fun originalSelectionCannotSelectGeneratedInputsOrDefaultTags() {
        val original=source().toString()
        NativeRoutingSpec.validateOriginal(original,NativeRoutingIntent(0,"chosen"))
        assertThrows(IllegalArgumentException::class.java) { NativeRoutingSpec.validateOriginal(original,NativeRoutingIntent(1)) }
        assertThrows(IllegalArgumentException::class.java) { NativeRoutingSpec.validateOriginal(original,NativeRoutingIntent(defaultOutboundTag="flutter-vless-system-dns")) }
        assertEquals(original,source().toString())
    }
    @Test fun finalProducerProvenanceShiftsDnsAroundApiAndProbeButNeverLendsCallerGuards() {
        for (callerApi in listOf(false,true)) {
            val (base,prep)=plan(callerApi); val final=addProbe(base)
            val snapshot=prep.freeze(final,"synthetic-user")
            val dir=Files.createTempDirectory("routing-provenance").toFile()
            try {
                snapshot.createInputs(dir,"xray").use { files ->
                    val spec=JSONObject(files.spec!!.readText())
                    assertEquals(1,spec.getInt("managed_inbound_index")); assertEquals(0,spec.getInt("source_inbound_index"))
                    assertEquals("chosen",spec.getString("default_outbound_tag"))
                    assertEquals(if(callerApi) "[0,1]" else "[0,2]",spec.getJSONArray("guard_rule_indices").toString())
                    assertEquals(final.toString(),files.config.readText())
                    assertEquals("user",final.getJSONArray("inbounds").getJSONObject(0).getString("tag"))
                }
            } finally { dir.deleteRecursively() }
        }
    }
    @Test fun configAndSpecAreFrozenTogetherPrivateAndSamePairCommandsContainOnlyPaths() {
        val (base,prep)=plan(); val final=addProbe(base); val snapshot=prep.freeze(final,"synthetic-user")
        val expected=snapshot.bytes; final.put("after-freeze",true); snapshot.bytes[0]=0
        val dir=Files.createTempDirectory("routing-input-pair").toFile()
        try {
            snapshot.createInputs(dir,"xray").use { inputs ->
                val spec=JSONObject(inputs.spec!!.readText())
                val digest=MessageDigest.getInstance("SHA-256").digest(expected).joinToString("") { "%02x".format(it) }
                assertArrayEquals(expected,inputs.config.readBytes()); assertEquals(digest,spec.getString("source_sha256"))
                for (file in listOf(inputs.config,inputs.spec!!)) assertEquals(setOf(PosixFilePermission.OWNER_READ,PosixFilePermission.OWNER_WRITE),Files.getPosixFilePermissions(file.toPath()))
                for (check in listOf(false,true)) assertEquals(listOf("/private/libxray.so","native-routing",if(check)"check" else "run","--config",inputs.config.absolutePath,"--spec",inputs.spec!!.absolutePath),inputs.command("/private/libxray.so",check))
                assertFalse(inputs.command("/private/libxray.so",false).joinToString().contains("synthetic-password"))
            }
            assertEquals(0,dir.listFiles()!!.size)
        } finally { dir.deleteRecursively() }
    }
    @Test fun actualCapabilityAndCheckStatusesRequireExactSupportedClosedSchema() {
        assertTrue(NativeRoutingCommand.capabilities("""{"stage":"capabilities","code":0,"capability":1}""".toByteArray()))
        assertTrue(NativeRoutingCommand.checked("""{"stage":"check","code":0}""".toByteArray()))
        for (bad in listOf("", "unknown command", "{}", "{\"stage\":\"capabilities\",\"code\":0,\"capability\":2}",
            "{\"stage\":\"capabilities\",\"code\":0,\"capability\":1,\"extra\":true}",
            "{\"stage\":\"capabilities\",\"code\":0,\"capability\":1} trailing",
            "{\"stage\":\"capabilities\",\"code\":0.0,\"capability\":1}")) assertFalse(NativeRoutingCommand.capabilities(bad.toByteArray()))
        assertFalse(NativeRoutingCommand.capabilities(null)); assertFalse(NativeRoutingCommand.checked(byteArrayOf()))
    }
    @Test fun routingCheckRequiresSameFinalPairAndClosedSuccessBeforeRemovingOwnedFiles() {
        val (base,prep)=plan(); val snapshot=prep.freeze(addProbe(base),"synthetic-user")
        val dir=Files.createTempDirectory("routing-preflight").toFile(); var config=byteArrayOf(); var spec=byteArrayOf()
        try {
            assertTrue(snapshot.preflightInputs(dir,{ files -> config=files.config.readBytes();spec=files.spec!!.readBytes();Child("{\"stage\":\"check\",\"code\":0}") }))
            assertArrayEquals(snapshot.bytes,config); assertTrue(JSONObject(String(spec)).has("source_sha256")); assertEquals(0,dir.listFiles()!!.size)
            assertFalse(snapshot.preflightInputs(dir,{ Child("") })); assertEquals(0,dir.listFiles()!!.size)
            assertFalse(snapshot.preflightInputs(dir,{ Child("{\"stage\":\"check\",\"code\":0}",3) }))
            assertThrows(IllegalArgumentException::class.java) { snapshot.preflight(dir,{ Child("") }) }
        } finally { dir.deleteRecursively() }
    }
    @Test fun ordinaryFrozenConfigKeepsStockArgumentsAndDoesNotNeedRoutingStatus() {
        val snapshot=NativeRuntimeConfig.freeze(source()); val dir=Files.createTempDirectory("ordinary-runtime-input").toFile()
        try {
            snapshot.createInputs(dir,"xray").use { inputs ->
                assertNull(inputs.spec); assertEquals(listOf("/libxray.so","run","-config",inputs.config.absolutePath),inputs.command("/libxray.so",false))
            }
            assertTrue(snapshot.preflight(dir,{ Child("") }))
        } finally { dir.deleteRecursively() }
    }
    @Test fun persistedSelectionCopiesOnlyUserChoicesAndRetainedProxyOnlyStillRefuses() {
        val profile=XrayConfig(VPN_ROUTING_SELECTION_JSON=NativeRoutingSelection.encode(mapOf("sourceInboundIndex" to 0),false))
        val retained=Gson().fromJson(Gson().toJson(profile.copy()),XrayConfig::class.java)
        assertEquals(0,NativeRoutingSelection.decode(retained.VPN_ROUTING_SELECTION_JSON,false)!!.sourceInboundIndex)
        assertThrows(IllegalArgumentException::class.java) { NativeRoutingSelection.decode(retained.VPN_ROUTING_SELECTION_JSON,true) }
        assertFalse(retained.VPN_ROUTING_SELECTION_JSON!!.contains("source_sha256"))
    }

    @Test fun recoveryRefinalizesNewProbeAndDigestWhileRetainingOnlyTheUserSelection() {
        val (base,prep)=plan()
        val checks=mutableListOf<ByteArray>(); val specs=mutableListOf<String>(); var closes=0
        val directory=Files.createTempDirectory("routing-recovery-final").toFile()
        try {
            for (attempt in 1..2) {
                SessionRuntimeCandidate.prepare(base,{ java.io.Closeable { closes++ } },{ _, copy ->
                    addProbe(copy).put("synthetic-probe-generation",attempt)
                }, validate={ frozen ->
                    frozen.preflightInputs(directory,{ files ->
                        checks += files.config.readBytes(); specs += files.spec!!.readText()
                        Child("{\"stage\":\"check\",\"code\":0}")
                    })
                },freeze={ prep.freeze(it,"synthetic-user") }).use { candidate ->
                    assertArrayEquals(checks.last(),candidate.configuration.bytes)
                }
            }
            assertEquals(2,closes); assertFalse(checks[0].contentEquals(checks[1]))
            assertNotEquals(JSONObject(specs[0]).getString("source_sha256"),JSONObject(specs[1]).getString("source_sha256"))
            assertEquals(0,directory.listFiles()!!.size)
        } finally { directory.deleteRecursively() }
    }
    @Test fun explicitProxyDnsGuardsRetainOnlyProducerIndicesAcrossApiAndReadinessInsertions() {
        val (base,prep)=plan(proxyDns=true); val snapshot=prep.freeze(addProbe(base),"synthetic-user")
        val dir=Files.createTempDirectory("proxy-dns-routing-guards").toFile()
        try { snapshot.createInputs(dir,"xray").use { files ->
            val spec=JSONObject(files.spec!!.readText())
            assertEquals("[0,2,3]",spec.getJSONArray("guard_rule_indices").toString())
            assertEquals(0,spec.getInt("source_inbound_index")); assertEquals(1,spec.getInt("managed_inbound_index"))
        } } finally { dir.deleteRecursively() }
    }
    @Test fun optionalApkExecutableIsReservedAndNeverChangesOrdinaryRuntimeSelection() {
        val root=Files.createTempDirectory("routing-apk-library").toFile()
        val context=Mockito.mock(Context::class.java)
        Mockito.`when`(context.applicationInfo).thenReturn(ApplicationInfo().apply { nativeLibraryDir=root.path })
        try {
            assertEquals(root.resolve("libxray.so"),XrayCoreManager.runtimeExecutable(context,true))
            val preview=root.resolve("libxray_routing_preview.so").apply { writeText("inert; never executed") }
            assertEquals(preview,XrayCoreManager.runtimeExecutable(context,true))
            assertEquals(root.resolve("libxray.so"),XrayCoreManager.runtimeExecutable(context,false))
            preview.delete(); preview.mkdir() // Malformed reserved entry must fail its own capability, not fall back.
            assertEquals(preview,XrayCoreManager.runtimeExecutable(context,true))
        } finally { root.deleteRecursively() }
    }
}
