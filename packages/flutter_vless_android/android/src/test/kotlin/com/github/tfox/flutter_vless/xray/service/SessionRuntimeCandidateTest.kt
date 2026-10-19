package com.github.tfox.flutter_vless.xray.service

import com.github.tfox.flutter_vless.xray.core.NativeRuntimeConfig
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.io.Closeable
import java.nio.file.Files

/** No service, real SessionReadinessProbe, sockets, child processes or Core are constructed. */
class SessionRuntimeCandidateTest {
    private class Probe(val id: Int, var closeFailure: Boolean = false) : Closeable {
        var closes = 0
        override fun close() { closes++; if (closeFailure) throw IllegalStateException("Synthetic cleanup refusal") }
    }
    private fun base() = JSONObject("""{"outbounds":[{"tag":"caller","protocol":"freedom"}],"routing":{"rules":[]},"remarks":"caller"}""")
    private fun configure(probe: Probe, json: JSONObject): JSONObject {
        json.getJSONArray("outbounds").put(JSONObject().put("tag", "probe-${probe.id}").put("protocol", "freedom"))
        json.getJSONObject("routing").getJSONArray("rules").put(JSONObject().put("probe", probe.id))
        return json
    }
    private fun prepare(probe: Probe?, base: JSONObject = base(), validate: (NativeRuntimeConfig) -> Boolean = { true }) =
        SessionRuntimeCandidate.prepare(base, { probe }, ::configure, validate)

    @Test fun finalGeneratedRuleIsCheckedBeforeAnyProfileSaveOrActiveStop() {
        var active = "working"; var saved = 0; var stopped = 0
        val probe = Probe(1)
        try {
            prepare(probe) { snapshot -> !String(snapshot.bytes).contains("probe-1") }.admit(
                isCurrent = { true }, persist = { saved++ }, commit = { active = "candidate"; stopped++; true })
            fail("Unpreflighted final readiness rule replaced the active session")
        } catch (_: IllegalArgumentException) { }
        assertEquals("working", active); assertEquals(0, saved); assertEquals(0, stopped); assertEquals(1, probe.closes)
    }

    @Test fun exactCheckedFinalBytesAreStartedWithTheSameStillLiveProbe() {
        val probe = Probe(2); val original = base(); val before = original.toString()
        val order = mutableListOf<String>(); var checked = byteArrayOf(); var started = byteArrayOf()
        val candidate = prepare(probe, original) { checked = it.bytes; order += "preflight"; true }
        assertEquals(0, probe.closes)
        assertTrue(candidate.admit({ true }, { order += "save" }) { accepted ->
            order += "stop-old"
            assertSame(probe, accepted.takeProbe()); started = accepted.configuration.bytes
            order += "start"; true
        })
        assertArrayEquals(checked, started); assertTrue(String(checked).contains("probe-2"))
        assertEquals(listOf("preflight", "save", "stop-old", "start"), order)
        assertEquals(before, original.toString()); assertEquals(0, probe.closes)
        candidate.close(); assertEquals(0, probe.closes) // transferred probe belongs to active service
        probe.close()
    }

    @Test fun staleRequestBeforeOrAfterSaveClosesOnlyCandidateAndNeverCommits() {
        for (staleAfterSave in listOf(false, true)) {
            val probe = Probe(3); val candidate = prepare(probe); var current = staleAfterSave
            var saves = 0; var commits = 0
            assertFalse(candidate.admit({ current }, { saves++; current = false }) { commits++; true })
            assertEquals(if (staleAfterSave) 1 else 0, saves); assertEquals(0, commits); assertEquals(1, probe.closes)
            candidate.close(); assertEquals(1, probe.closes)
        }
    }

    @Test fun saveFailureRetainsPrimaryFailureAndClosesCandidateWithoutStoppingActive() {
        val probe = Probe(4); val candidate = prepare(probe); val error = IllegalStateException("Synthetic save refusal")
        var stopped = false
        val thrown = assertThrows(IllegalStateException::class.java) {
            candidate.admit({ true }, { throw error }) { stopped = true; true }
        }
        assertSame(error, thrown); assertFalse(stopped); assertEquals(1, probe.closes)
    }

    @Test fun failedCommitClosesCandidateAndPendingReplacementCanBeCancelledBeforeStartup() {
        val refused = Probe(5); assertFalse(prepare(refused).admit({ true }, {}) { false }); assertEquals(1, refused.closes)
        val pending = Probe(6); val candidate = prepare(pending)
        assertTrue(candidate.admit({ true }, {}) { true }); assertEquals(0, pending.closes)
        candidate.close(); candidate.close(); assertEquals(1, pending.closes)
        assertThrows(IllegalStateException::class.java) { candidate.takeProbe() }
    }

    @Test fun configurationAndValidationFailuresCloseProbeAndRetainPrimaryError() {
        val configureProbe = Probe(7); val original = IllegalStateException("Synthetic finalization refusal")
        val thrown = assertThrows(IllegalStateException::class.java) {
            SessionRuntimeCandidate.prepare(base(), { configureProbe }, { _, _ -> throw original }, { true })
        }
        assertSame(original, thrown); assertEquals(1, configureProbe.closes)
        val validationProbe = Probe(8, closeFailure = true)
        val invalid = assertThrows(IllegalArgumentException::class.java) { prepare(validationProbe) { false } }
        assertEquals(1, validationProbe.closes); assertEquals(1, invalid.suppressed.size)
    }

    @Test fun recoveryFinalizesAndChecksAFreshProbeWhileKeepingPreviousSnapshotImmutable() {
        val checks = mutableListOf<ByteArray>()
        val first = prepare(Probe(9)) { checks += it.bytes; true }
        val original = first.configuration.bytes
        first.close()
        val recovered = prepare(Probe(10)) { checks += it.bytes; true }
        assertEquals(2, checks.size); assertArrayEquals(original, checks[0])
        assertTrue(String(checks[0]).contains("probe-9")); assertTrue(String(checks[1]).contains("probe-10"))
        assertFalse(checks[0].contentEquals(checks[1])); assertArrayEquals(original, first.configuration.bytes)
        recovered.close()
    }

    @Test fun failedRecoveryPreflightNeverStartsNewWorkersAndClosesNewProbe() {
        val probe = Probe(11); var starts = 0
        try {
            prepare(probe) { false }.admit({ true }, {}) { starts++; true }
            fail("Invalid recovery candidate accepted")
        } catch (_: IllegalArgumentException) { }
        assertEquals(0, starts); assertEquals(1, probe.closes)
    }

    @Test fun proxyOnlyChecksUnmodifiedBytesWithoutCreatingReadinessResources() {
        val source = base(); val before = source.toString(); var configureCalls = 0
        val candidate = SessionRuntimeCandidate.prepare<Probe>(source, { null }, { _, _ -> configureCalls++; error("No VPN probe") }, { true })
        assertEquals(0, configureCalls); assertEquals(before, String(candidate.configuration.bytes)); assertNull(candidate.takeProbe()); candidate.close()
    }

    @Test fun frozenConfigurationAndDiskBytesCannotChangeAfterValidation() {
        val source = base(); val frozen = NativeRuntimeConfig.freeze(source); val exact = frozen.bytes
        source.put("remarks", "changed"); frozen.bytes[0] = 0
        assertArrayEquals(exact, frozen.bytes); assertEquals("NativeRuntimeConfig(<private>)", frozen.toString())
        val file = Files.createTempFile("native-runtime-candidate", ".json").toFile()
        try { frozen.writeTo(file); assertArrayEquals(exact, file.readBytes()) } finally { file.delete() }
    }
}
