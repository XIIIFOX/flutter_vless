package com.github.tfox.flutter_vless.xray.core

import android.content.Context
import android.content.pm.ApplicationInfo
import android.app.Service
import com.google.gson.Gson
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.mockito.Mockito
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.util.concurrent.TimeUnit

/** Actual public traffic producer, with an inert CLI reply and no real child or socket. */
class XrayTrafficConsumerTest {
    private val credentials = LocalProxyCredentials("synthetic-user", "synthetic-password")
    private var sampleNanos = 0L

    private fun traffic(context: Context, at: Long = sampleNanos + 1_000_000_000): LongArray {
        sampleNanos = at
        return XrayCoreManager.getV2rayTraffic(context) { sampleNanos }
    }

    @Test fun absentWholePolicyEnablesOwnedInputCountersAlongsideLegacyOutboundDefaults() {
        val source = source(true).apply { remove("policy") }
        val before = source.toString()
        val profile = XrayConfig(V2RAY_FULL_JSON_CONFIG = before)
        val runtime = XrayCoreManager.buildRuntimeConfigJson(profile, File("."), credentials)
        val system = runtime.getJSONObject("policy").getJSONObject("system")
        assertTrue("Absent policy must enable owned inbound upload counters", system.optBoolean("statsInboundUplink"))
        assertTrue("Absent policy must enable owned inbound download counters", system.optBoolean("statsInboundDownlink"))
        assertTrue(system.getBoolean("statsOutboundUplink")); assertTrue(system.getBoolean("statsOutboundDownlink"))
        assertEquals(before, source.toString()); assertEquals(before, profile.V2RAY_FULL_JSON_CONFIG)
    }

    @Test fun levelsOnlyAndEmptySystemPoliciesEnableMissingOwnedInputCounters() {
        for (policy in listOf(
            JSONObject("""{"levels":{"8":{"bufferSize":3,"handshake":2}},"futurePolicy":{"value":null}}"""),
            JSONObject("""{"levels":{"8":{"bufferSize":3,"handshake":2}},"system":{},"futurePolicy":{"value":null}}"""),
            JSONObject("""{"levels":{"8":{"bufferSize":3,"handshake":2}},"system":{"statsOutboundUplink":false,"futureSystem":{"value":null}},"futurePolicy":{"value":null}}"""))) {
            val source = source(true).put("policy", policy)
            val before = source.toString()
            val profile = XrayConfig(V2RAY_FULL_JSON_CONFIG = before)
            val runtime = XrayCoreManager.buildRuntimeConfigJson(profile, File("."), credentials)
            val actual = runtime.getJSONObject("policy")
            val system = actual.getJSONObject("system")
            assertTrue("An existing partial policy must not silence owned upload statistics", system.getBoolean("statsInboundUplink"))
            assertTrue("An existing partial policy must not silence owned download statistics", system.getBoolean("statsInboundDownlink"))
            assertEquals(policy.getJSONObject("levels").toString(), actual.getJSONObject("levels").toString())
            assertEquals(policy.getJSONObject("futurePolicy").toString(), actual.getJSONObject("futurePolicy").toString())
            if (policy.has("system")) for (key in policy.getJSONObject("system").keys())
                assertEquals("Existing system settings remain authoritative", policy.getJSONObject("system").get(key).toString(), system.get(key).toString())
            assertEquals(before, source.toString()); assertEquals(before, profile.V2RAY_FULL_JSON_CONFIG)
        }
    }

    @Test fun statisticsDefaultsRespectExplicitValuesAliasesAndDisabledSources() {
        for (policy in listOf<Any>(JSONObject.NULL,
            JSONObject("""{"system":{"statsInboundUplink":false,"statsInboundDownlink":null}}"""),
            JSONObject("""{"System":{"StatsInboundUplink":false,"StatsInboundDownlink":null}}"""),
            JSONObject("""{"\u017fy\u017ftem":{"\u017ftatsInboundUplink":false,"\u017ftatsInboundDownlink":null}}"""),
            JSONObject("""{"system":null}"""),
            JSONObject("""{"system":{"statsInboundUplink":true,"StatsInboundUplink":false}}"""),
            JSONObject("""{"system":{},"System":{"statsInboundUplink":false}}"""))) {
            val source = source(true).put("policy", policy)
            val before = source.toString()
            val runtime = XrayCoreManager.buildRuntimeConfigJson(XrayConfig(V2RAY_FULL_JSON_CONFIG = before), File("."), credentials)
            assertEquals(policy.toString(), runtime.get("policy").toString())
            assertEquals(before, source.toString())
        }
        for (callerApi in listOf<Any?>(null, JSONObject.NULL, JSONObject("""{"tag":"caller-api","services":["StatsService"]}"""))) {
            val source = source(true).put("policy", JSONObject("""{"levels":{"8":{"bufferSize":3}},"system":{}}"""))
            if (callerApi == null) source.put("stats", JSONObject.NULL) else source.put("api", callerApi)
            val before = source.toString()
            val runtime = XrayCoreManager.buildRuntimeConfigJson(XrayConfig(V2RAY_FULL_JSON_CONFIG = before), File("."), credentials)
            assertEquals(source.getJSONObject("policy").toString(), runtime.getJSONObject("policy").toString())
            assertEquals(before, source.toString())
        }
    }

    @Test fun oneExplicitCounterDirectionKeepsItsValueWhileMissingDirectionGetsDefault() {
        for ((key, value) in listOf("statsInboundUplink" to false, "StatsInboundUplink" to JSONObject.NULL)) {
            val policy = JSONObject().put("System", JSONObject().put(key, value).put("unknown", "retained"))
            val source = source(true).put("policy", policy)
            val before = source.toString()
            val runtime = XrayCoreManager.buildRuntimeConfigJson(XrayConfig(V2RAY_FULL_JSON_CONFIG = before), File("."), credentials)
            val actual = runtime.getJSONObject("policy").getJSONObject("System")
            assertEquals(value.toString(), actual.get(key).toString())
            assertFalse(actual.has(if (key == "statsInboundUplink") "StatsInboundUplink" else "statsInboundUplink"))
            assertEquals("retained", actual.getString("unknown"))
            assertTrue(actual.getBoolean("statsInboundDownlink"))
            assertEquals(before, source.toString())
        }
    }

    private fun source(enabled: Boolean, callerApi: Any? = null): JSONObject = JSONObject("""{
        "inbounds":[{"tag":"flutter-vless-tun","protocol":"http","listen":"127.0.0.1","port":18080}],
        "outbounds":[{"tag":"edge-live","protocol":"freedom"}],
        "stats":{},
        "policy":{"system":{"statsInboundUplink":$enabled,"statsInboundDownlink":$enabled,
            "statsOutboundUplink":$enabled,"statsOutboundDownlink":$enabled},"levels":{"8":{"bufferSize":3}}}
    }""").apply { if (callerApi != null) put("api", callerApi) }

    private fun response(managed: String, up: Long?, down: Long?): ByteArray {
        val values = JSONArray()
        fun stat(name: String, value: Long) { values.put(JSONObject().put("name", name).put("value", value)) }
        if (up != null) stat("inbound>>>$managed>>>traffic>>>uplink", up)
        if (down != null) stat("inbound>>>$managed>>>traffic>>>downlink", down)
        stat("inbound>>>flutter-vless-tun>>>traffic>>>uplink", 71)
        stat("inbound>>>flutter-vless-tun>>>traffic>>>downlink", 73)
        stat("inbound>>>$managed-extra>>>traffic>>>uplink", 79)
        stat("outbound>>>edge-live>>>traffic>>>uplink", 401)
        stat("outbound>>>edge-live>>>traffic>>>downlink", 409)
        stat("outbound>>>proxy>>>traffic>>>uplink", 901)
        stat("outbound>>>proxy>>>traffic>>>downlink", 1201)
        stat("user>>>synthetic-user>>>traffic>>>uplink", 811)
        stat("user>>>synthetic-user>>>traffic>>>downlink", 821)
        return JSONObject().put("stat", values).toString().toByteArray(Charsets.UTF_8)
    }

    private fun consumer(source: JSONObject, up: Long?, down: Long?, expectQuery: Boolean = true,
                         allowStop: Boolean = false,
                         proxyOnly: Boolean = false, proxyPort: Int = 10807,
                         replyBytes: ((String) -> ByteArray)? = null,
                         check: (LongArray, List<String>, String, Context, XrayConfig) -> Unit) {
        val raw = source.toString()
        val profile = XrayConfig(V2RAY_FULL_JSON_CONFIG = raw, PROXY_ONLY = proxyOnly, LOCAL_SOCKS5_PORT = proxyPort)
        val runtime = XrayCoreManager.buildRuntimeConfigJson(profile, File("."), credentials)
        // Producer-owned array position, not a tag guessed from caller JSON or an outbound.
        val inputs = runtime.getJSONArray("inbounds")
        val managed = if (proxyOnly) (0 until inputs.length()).map(inputs::getJSONObject).single {
            it.optString("protocol") == "socks" && it.optInt("port") == profile.LOCAL_SOCKS5_PORT
        }.getString("tag") else inputs.getJSONObject(source.getJSONArray("inbounds").length()).getString("tag")
        if (!proxyOnly) assertEquals("flutter-vless-tun-1", managed)
        assertEquals(managed, profile.runtimeTrafficInboundTag)
        assertEquals(source.getJSONObject("policy").toString(), runtime.getJSONObject("policy").toString())
        if (source.has("api")) {
            assertEquals(source.get("api").toString(), runtime.get("api").toString())
            assertEquals(0, profile.LOCAL_API_PORT)
        }
        val processField = XrayCoreManager::class.java.getDeclaredField("xrayProcess").apply { isAccessible = true }
        val lastUp = XrayCoreManager::class.java.getDeclaredField("lastProxyUplink").apply { isAccessible = true }
        val lastDown = XrayCoreManager::class.java.getDeclaredField("lastProxyDownlink").apply { isAccessible = true }
        val lastTime = XrayCoreManager::class.java.getDeclaredField("lastTrafficSampleNanos").apply { isAccessible = true }
        val previousProcess = processField.get(XrayCoreManager)
        val previousConfig = AppConfigs.V2RAY_CONFIG
        val previousUp = lastUp.get(XrayCoreManager); val previousDown = lastDown.get(XrayCoreManager)
        val previousTime = lastTime.get(XrayCoreManager)
        val activeChild = Mockito.mock(Process::class.java)
        Mockito.`when`(activeChild.isAlive).thenReturn(true)
        val context = Mockito.mock(Context::class.java)
        Mockito.`when`(context.applicationInfo).thenReturn(ApplicationInfo().apply { nativeLibraryDir = "/synthetic/apk/lib" })
        var command = emptyList<String>()
        try {
            processField.set(XrayCoreManager, activeChild)
            AppConfigs.V2RAY_CONFIG = profile
            lastUp.set(XrayCoreManager, null); lastDown.set(XrayCoreManager, null); lastTime.set(XrayCoreManager, null)
            sampleNanos = 0
            Mockito.mockConstruction(ProcessBuilder::class.java) { builder, construction ->
                command = (construction.arguments()[0] as Array<*>).map { it as String }
                Mockito.`when`(builder.redirectErrorStream(true)).thenReturn(builder)
                val reply = Mockito.mock(Process::class.java)
                Mockito.`when`(reply.inputStream).thenReturn(ByteArrayInputStream(replyBytes?.invoke(managed) ?: response(managed, up, down)))
                Mockito.`when`(reply.errorStream).thenReturn(ByteArrayInputStream(byteArrayOf()))
                Mockito.`when`(reply.outputStream).thenReturn(ByteArrayOutputStream())
                Mockito.`when`(reply.isAlive).thenReturn(false)
                Mockito.`when`(reply.exitValue()).thenReturn(0)
                Mockito.`when`(builder.start()).thenReturn(reply)
            }.use { builders ->
                val result = traffic(context)
                assertEquals(if (expectQuery) 1 else 0, builders.constructed().size)
                assertEquals(raw, source.toString())
                assertEquals(raw, profile.V2RAY_FULL_JSON_CONFIG)
                check(result, command, managed, context, profile)
                assertEquals(raw, source.toString()); assertEquals(raw, profile.V2RAY_FULL_JSON_CONFIG)
                if (!expectQuery) assertTrue(builders.constructed().isEmpty())
            }
            if (!allowStop) {
                Mockito.verify(activeChild, Mockito.never()).destroy()
                Mockito.verify(activeChild, Mockito.never()).destroyForcibly()
            }
        } finally {
            processField.set(XrayCoreManager, previousProcess)
            AppConfigs.V2RAY_CONFIG = previousConfig
            lastUp.set(XrayCoreManager, previousUp); lastDown.set(XrayCoreManager, previousDown)
            lastTime.set(XrayCoreManager, previousTime)
        }
    }

    @Test fun publicTrafficUsesExactOwnedManagedInputRatherThanProfileOutboundOrOtherScopes() {
        consumer(source(true), 37, 61) { result, command, managed, _, _ ->
            assertArrayEquals("First sample has totals but no prior speed baseline", longArrayOf(0, 0, 37, 61), result)
            assertEquals(listOf("/synthetic/apk/lib/libxray.so", "api", "statsquery", "--server=127.0.0.1:10809",
                "--pattern", "inbound>>>$managed>>>traffic>>>"), command)
        }
    }

    @Test fun exactAvailableZeroDoesNotBecomeImportedOutboundOrUserTraffic() {
        consumer(source(true), 0, 0) { result, command, managed, context, _ ->
            assertEquals("Available zero must be queried in the exact owned input namespace",
                "inbound>>>$managed>>>traffic>>>", command.last())
            assertArrayEquals(longArrayOf(0, 0, 0, 0), result)
            assertEquals(XrayCoreManager.TrafficSample(0, 0), XrayCoreManager.readTraffic(context))
        }
    }

    @Test fun disabledCallerPolicyCannotSubstituteOtherCountersForMissingOwnedCounters() {
        // Existing numeric API has no availability bit: this asserts only no fabricated bytes.
        consumer(source(false), null, null) { result, _, _, context, _ ->
            assertArrayEquals(longArrayOf(0, 0, 0, 0), result)
            assertEquals(XrayCoreManager.TrafficSample(), XrayCoreManager.readTraffic(context))
        }
    }

    @Test fun callerApiAndDisabledPolicyStayUnchangedAndAreNeverQueried() {
        for (api in listOf(JSONObject.NULL,
            JSONObject("""{"tag":"caller-api","listen":"127.0.0.1:18081","services":["HandlerService","StatsService"]}"""))) {
            consumer(source(false, api), null, null, expectQuery = false) { result, command, _, context, _ ->
                assertArrayEquals(longArrayOf(0, 0, 0, 0), result)
                assertTrue(command.isEmpty())
                assertEquals(XrayCoreManager.TrafficSample(), XrayCoreManager.readTraffic(context))
            }
        }
    }

    @Test fun pinnedCliOmittedZeroValueIsAvailableButMissingDirectionIsNot() {
        consumer(source(true), null, null, replyBytes = { tag ->
            JSONObject().put("stat", JSONArray().put(JSONObject().put("name", "inbound>>>$tag>>>traffic>>>uplink")))
                .toString().toByteArray()
        }) { result, _, _, context, _ ->
            assertArrayEquals(longArrayOf(0, 0, 0, 0), result)
            assertEquals(XrayCoreManager.TrafficSample(0, null), XrayCoreManager.readTraffic(context))
        }
    }

    @Test fun partialCallerPolicyRetainsAvailableUploadWithoutInventingDownload() {
        val source = source(true)
        source.getJSONObject("policy").getJSONObject("system").put("statsInboundDownlink", false)
        consumer(source, 37, null) { result, _, _, context, _ ->
            assertArrayEquals(longArrayOf(0, 0, 37, 0), result)
            assertEquals(XrayCoreManager.TrafficSample(37, null), XrayCoreManager.readTraffic(context))
        }
    }

    @Test fun invalidOrDuplicateDirectionDoesNotDiscardOtherValidDirection() {
        val invalid = listOf<Any>(JSONObject.NULL, -1, 0.5, "17", true, java.math.BigInteger("9223372036854775808"))
        for (value in invalid + listOf("duplicate")) {
            consumer(source(true), null, null, replyBytes = { tag ->
                val up = JSONObject().put("name", "inbound>>>$tag>>>traffic>>>uplink").put("value", value)
                val rows = JSONArray().put(up)
                if (value == "duplicate") {
                    up.put("value", 17)
                    rows.put(JSONObject(up.toString()))
                }
                rows.put(JSONObject().put("name", "inbound>>>$tag>>>traffic>>>downlink").put("value", 61))
                JSONObject().put("stat", rows).toString().toByteArray()
            }) { result, _, _, context, _ ->
                assertArrayEquals(longArrayOf(0, 0, 0, 61), result)
                assertEquals(XrayCoreManager.TrafficSample(null, 61), XrayCoreManager.readTraffic(context))
            }
        }
    }

    @Test fun directionalDeltasRestartAfterMissingSamplesAndCounterResets() {
        val values = listOf(10L to 20L, 15L to 25L, null to 30L, 40L to 35L,
            44L to 50L, 5L to 7L, 8L to 11L)
        var index = 0
        consumer(source(true), null, null, replyBytes = { tag ->
            val pair = values[index++]; response(tag, pair.first, pair.second)
        }) { first, _, _, context, _ ->
            assertArrayEquals(longArrayOf(0, 0, 10, 20), first)
            for (expected in listOf(longArrayOf(5, 5, 15, 25), longArrayOf(0, 5, 0, 30),
                longArrayOf(0, 5, 40, 35), longArrayOf(4, 15, 44, 50), longArrayOf(0, 0, 5, 7),
                longArrayOf(3, 4, 8, 11))) assertArrayEquals(expected, traffic(context))
        }
    }

    @Test fun ratesUseElapsedTimeAcrossSlowQueriesAndFractionalSeconds() {
        val values = listOf(10L to 20L, 19L to 38L, 22L to 44L, null to 52L, 100L to 56L, 106L to 64L)
        var index = 0
        consumer(source(true), null, null, replyBytes = { tag ->
            val pair = values[index++]; response(tag, pair.first, pair.second)
        }) { first, _, _, context, _ ->
            assertArrayEquals(longArrayOf(0, 0, 10, 20), first)
            assertArrayEquals("The CLI plus scheduled gap is three seconds, not one",
                longArrayOf(3, 6, 19, 38), traffic(context, 4_000_000_000))
            assertArrayEquals("Half-second samples scale to bytes per second",
                longArrayOf(6, 12, 22, 44), traffic(context, 4_500_000_000))
            assertArrayEquals(longArrayOf(0, 4, 0, 52), traffic(context, 6_500_000_000))
            assertArrayEquals("An unavailable direction needs a fresh baseline",
                longArrayOf(0, 2, 100, 56), traffic(context, 8_500_000_000))
            assertArrayEquals(longArrayOf(12, 16, 106, 64), traffic(context, 9_000_000_000))
        }
    }

    @Test fun ratesKeepInt64PrecisionAndSaturateWithoutIntermediateOverflow() {
        val values = listOf(0L, Long.MAX_VALUE, 0L, Long.MAX_VALUE)
        var index = 0
        consumer(source(true), null, null, replyBytes = { tag ->
            val value = values[index++]; response(tag, value, value)
        }) { _, _, _, context, _ ->
            assertArrayEquals(longArrayOf(Long.MAX_VALUE / 2, Long.MAX_VALUE / 2, Long.MAX_VALUE, Long.MAX_VALUE),
                traffic(context, 3_000_000_000))
            assertArrayEquals("A counter reset is not negative traffic", longArrayOf(0, 0, 0, 0),
                traffic(context, 4_000_000_000))
            assertArrayEquals(longArrayOf(Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE),
                traffic(context, 4_000_000_001))
        }
    }

    @Test fun nonIncreasingClockCannotProduceInvalidRatesOrPoisonFollowingSample() {
        var value = 0L
        consumer(source(true), null, null, replyBytes = { tag ->
            value += 10; response(tag, value, value)
        }) { _, _, _, context, _ ->
            assertArrayEquals(longArrayOf(0, 0, 20, 20), traffic(context, 1_000_000_000))
            assertArrayEquals(longArrayOf(0, 0, 30, 30), traffic(context, 500_000_000))
            assertArrayEquals(longArrayOf(10, 10, 40, 40), traffic(context, 1_500_000_000))
        }
    }

    @Test fun sharedIntegerRateVectorsFeedActualPublicTrafficProducer() {
        val vectors = JSONArray(requireNotNull(javaClass.getResource("/traffic-rate-vectors.json")).readText())
        assertTrue(vectors.length() > 0)
        for (index in 0 until vectors.length()) {
            val vector = vectors.getJSONObject(index)
            val delta = vector.getString("delta").toLong()
            val elapsed = vector.getString("elapsedNanoseconds").toLong()
            val expected = vector.getString("bytesPerSecond").toLong()
            var first = true
            consumer(source(true), null, null, replyBytes = { tag ->
                val current = if (first) 0 else delta
                first = false; response(tag, current, current)
            }) { baseline, _, _, context, _ ->
                assertArrayEquals(longArrayOf(0, 0, 0, 0), baseline)
                // Signed nanoTime rollover still has the same positive elapsed
                // subtraction for an interval bounded by Long.MAX_VALUE.
                assertArrayEquals("Shared rate vector $index: $vector", longArrayOf(expected, expected, delta, delta),
                    traffic(context, sampleNanos + elapsed))
            }
        }
    }

    @Test fun actualStopClearsDirectionalBaselinesBeforeNextOwnedSample() {
        var first = true
        consumer(source(true), null, null, allowStop = true, replyBytes = { tag ->
            response(tag, if (first) 37 else 61, 73).also { first = false }
        }) { _, _, _, context, _ ->
            val field = XrayCoreManager::class.java.getDeclaredField("xrayProcess").apply { isAccessible = true }
            val child = field.get(XrayCoreManager) as Process
            Mockito.`when`(child.waitFor(Mockito.anyLong(), Mockito.any(TimeUnit::class.java))).thenReturn(true)
            assertTrue(XrayCoreManager.stopWorkers())
            Mockito.verify(child).destroy()
            field.set(XrayCoreManager, child) // Inert replacement: no process or probe construction.
            assertArrayEquals(longArrayOf(0, 0, 61, 73), traffic(context))
        }
    }

    @Test fun actualStartRefusalClearsBaselinesWithoutLaunchingReplacement() {
        var first = true
        consumer(source(true), null, null, allowStop = true, replyBytes = { tag ->
            response(tag, if (first) 37 else 61, 73).also { first = false }
        }) { _, _, _, context, profile ->
            // Existing owner refuses bounded reap. startCore must return before
            // file/process/monitor construction, but still invalidate baselines.
            assertFalse(XrayCoreManager.startCore(Mockito.mock(Service::class.java), profile,
                NativeRuntimeConfig.freeze(JSONObject()), null, 1) { _, _ -> fail("No monitor may run") })
            assertArrayEquals(longArrayOf(0, 0, 61, 73), traffic(context))
        }
    }

    @Test fun runtimeIdentityIsRegeneratedAndExcludedFromCopiesAndPersistence() {
        val source = source(true)
        val profile = XrayConfig(V2RAY_FULL_JSON_CONFIG = source.toString())
        XrayCoreManager.buildRuntimeConfigJson(profile, File("."), credentials)
        assertEquals("flutter-vless-tun-1", profile.runtimeTrafficInboundTag)
        assertNull(profile.copy().runtimeTrafficInboundTag)
        val gson = Gson().toJson(profile)
        assertFalse(gson.contains("runtimeTrafficInboundTag"))
        assertNull(Gson().fromJson("""{"runtimeTrafficInboundTag":"caller-controlled"}""", XrayConfig::class.java).runtimeTrafficInboundTag)
        val bytes = ByteArrayOutputStream().also { ObjectOutputStream(it).use { output -> output.writeObject(profile) } }.toByteArray()
        assertNull((ObjectInputStream(ByteArrayInputStream(bytes)).use { it.readObject() } as XrayConfig).runtimeTrafficInboundTag)
        source.getJSONArray("inbounds").put(JSONObject("""{"tag":"flutter-vless-tun-1","protocol":"http","port":18082}"""))
        profile.V2RAY_FULL_JSON_CONFIG = source.toString()
        XrayCoreManager.buildRuntimeConfigJson(profile, File("."), credentials)
        assertEquals("flutter-vless-tun-2", profile.runtimeTrafficInboundTag)
        profile.V2RAY_FULL_JSON_CONFIG = "{}"
        assertThrows(IllegalArgumentException::class.java) { XrayCoreManager.buildRuntimeConfigJson(profile, File("."), credentials) }
        assertNull(profile.runtimeTrafficInboundTag)
    }

    @Test fun callerNullLevelsOnlyAndFalsePolicyAndStatsAreNotEnabledOrRewritten() {
        for (policy in listOf(JSONObject.NULL, JSONObject("""{"levels":{"8":{"bufferSize":3}}}"""),
            source(false).getJSONObject("policy"))) {
            val source = source(true).put("policy", policy).put("stats", JSONObject.NULL)
            val before = source.toString()
            val profile = XrayConfig(V2RAY_FULL_JSON_CONFIG = before)
            val runtime = XrayCoreManager.buildRuntimeConfigJson(profile, File("."), credentials)
            assertEquals(policy.toString(), runtime.get("policy").toString())
            assertTrue(runtime.isNull("stats"))
            assertEquals(before, source.toString()); assertEquals(before, profile.V2RAY_FULL_JSON_CONFIG)
        }
    }

    @Test fun proxyPrimaryIdentityMatchesSelectedInputWithoutTagOrPolicyRewrite() {
        for (variant in listOf("tagged", "untagged", "duplicate", "ambiguous")) {
            val source = source(false)
            val inputs = source.getJSONArray("inbounds")
            val primary = JSONObject("""{"protocol":"socks","port":18081,"listen":"127.0.0.1","settings":{"auth":"noauth"}}""")
            if (variant != "untagged") primary.put("tag", "selected-primary")
            inputs.put(primary)
            if (variant == "duplicate") inputs.getJSONObject(0).put("tag", "selected-primary")
            if (variant == "ambiguous") inputs.put(JSONObject(primary.toString()).put("listen", "127.0.0.2"))
            val before = source.toString()
            val profile = XrayConfig(V2RAY_FULL_JSON_CONFIG = before, PROXY_ONLY = true, LOCAL_SOCKS5_PORT = 18081)
            val runtime = XrayCoreManager.buildRuntimeConfigJson(profile, File("."))
            assertEquals(if (variant == "tagged") "selected-primary" else null, profile.runtimeTrafficInboundTag)
            for (index in 0 until inputs.length())
                assertEquals(inputs.getJSONObject(index).toString(), runtime.getJSONArray("inbounds").getJSONObject(index).toString())
            assertEquals(source.getJSONObject("policy").toString(), runtime.getJSONObject("policy").toString())
            assertEquals(before, source.toString()); assertEquals(before, profile.V2RAY_FULL_JSON_CONFIG)
        }
    }

    @Test fun sharedPinnedCoreWireCorpusFeedsActualSelectedPrimaryConsumer() {
        val cases = JSONArray(requireNotNull(javaClass.getResource("/traffic-counters.json")).readText())
        assertEquals(11, cases.length())
        for (index in 0 until cases.length()) {
            val item = cases.getJSONObject(index); val before = item.toString()
            val name = item.getString("name"); val tag = item.getString("tag")
            val source = source(true)
            source.getJSONArray("inbounds").put(JSONObject().put("tag", tag).put("protocol", "socks")
                .put("port", 18081).put("listen", "127.0.0.1").put("settings", JSONObject().put("auth", "noauth")))
            val expected = item.getJSONObject("expected")
            fun value(direction: String): Long? = if (expected.isNull(direction)) null else expected.getLong(direction)
            val sample = XrayCoreManager.TrafficSample(value("uplink"), value("downlink"))
            val public = longArrayOf(0, 0, sample.uplink ?: 0, sample.downlink ?: 0)
            val wire = item.getJSONObject("wire").toString().toByteArray(Charsets.UTF_8)
            consumer(source, null, null, proxyOnly = true, proxyPort = 18081, replyBytes = { wire }) {
                    first, command, managed, context, profile ->
                assertEquals(name, tag, managed)
                assertEquals(name, tag, profile.runtimeTrafficInboundTag)
                assertEquals(name, "inbound>>>$tag>>>traffic>>>", command.last())
                assertEquals(name, sample, XrayCoreManager.readTraffic(context))
                assertArrayEquals(name, public, first)
                assertArrayEquals(name, public, traffic(context))
            }
            assertEquals(name, before, item.toString())
        }
    }
}
