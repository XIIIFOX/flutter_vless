package com.github.tfox.flutter_vless.xray.service

import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test

class NativePreviewSocketPolicyTest {
    @Test fun onlyScopedCommandsWithExactlyOneDescriptorCanReachProtection() {
        val policy = NativePreviewSocketPolicy(NativePreviewNetworkGeneration()) { true }
        val calls = mutableListOf<String>()
        for (command in listOf('H', 'P', 'D', '?', 'S', 'Q')) for (count in 0..2) {
            calls.clear()
            val result = policy.protectBindAndAcknowledge(command.code, count,
                { calls.add("protect"); true }, { calls.add("bind") }, { calls.add("ACK") })
            val expected = command in listOf('S', 'Q') && count == 1
            assertEquals("$command/$count", expected, result)
            assertEquals(if (expected) listOf("protect", "bind", "ACK") else emptyList<String>(), calls)
        }
    }

    @Test fun refusedProtectionCannotBindOrAcknowledge() {
        val policy = NativePreviewSocketPolicy(NativePreviewNetworkGeneration()) { true }
        assertFalse(policy.protectBindAndAcknowledge('Q'.code, 1,
            { false }, { fail("Refused FD reached bind") }, { fail("Refused FD reached ACK") }))
    }

    @Test fun failedBindingCannotAcknowledge() {
        val policy = NativePreviewSocketPolicy(NativePreviewNetworkGeneration()) { true }
        assertFalse(policy.protectBindAndAcknowledge('Q'.code, 1,
            { true }, { throw IOException("synthetic bind failure") }, { fail("Unbound FD reached ACK") }))
    }

    @Test fun revokedGenerationCannotRunEitherOperationOrReactivate() {
        val generation = NativePreviewNetworkGeneration()
        val policy = NativePreviewSocketPolicy(generation) { true }
        generation.revoke(); generation.revoke()
        assertFalse(policy.isCurrent())
        assertFalse(policy.protectBindAndAcknowledge('S'.code, 1,
            { fail("Revoked FD reached protect"); true }, { fail("Revoked FD reached bind") }, { fail("Revoked FD reached ACK") }))
        assertThrows(IllegalArgumentException::class.java) { NativePreviewSocketPolicy(generation) { true } }
    }

    @Test fun aGenerationCannotBindTwoPoliciesOrNetworksWhileTheFirstIsStillAlive() {
        val generation = NativePreviewNetworkGeneration()
        val original = NativePreviewSocketPolicy(generation) { true }
        assertThrows(IllegalArgumentException::class.java) { NativePreviewSocketPolicy(generation) { true } }
        assertTrue("A rejected duplicate claim must not revoke the original policy", original.isCurrent())
        original.revoke()
        assertFalse(original.isCurrent())
    }

    @Test fun revocationWhileProtectingPreventsBindAndAck() {
        val generation = NativePreviewNetworkGeneration()
        val policy = NativePreviewSocketPolicy(generation) { true }
        assertFalse(policy.protectBindAndAcknowledge('S'.code, 1,
            { generation.revoke(); true }, { fail("Stale FD reached bind") }, { fail("Stale FD reached ACK") }))
    }

    @Test fun revocationWhileBindingPreventsAck() {
        val generation = NativePreviewNetworkGeneration()
        val policy = NativePreviewSocketPolicy(generation) { true }
        assertFalse(policy.protectBindAndAcknowledge('Q'.code, 1,
            { true }, { generation.revoke() }, { fail("Stale FD reached ACK") }))
    }

    @Test fun lostCapturedNetworkPermanentlyRevokesInsteadOfUsingAnotherNetwork() {
        val generation = NativePreviewNetworkGeneration()
        var capturedValid = false
        val policy = NativePreviewSocketPolicy(generation) { capturedValid }
        assertFalse(policy.isCurrent())
        capturedValid = true
        assertFalse(policy.isCurrent())
        assertFalse(generation.isCurrent())
    }

    @Test fun networkLossDuringProtectionPreventsBindingAndAck() {
        var capturedValid = true
        val policy = NativePreviewSocketPolicy(NativePreviewNetworkGeneration()) { capturedValid }
        assertFalse(policy.protectBindAndAcknowledge('Q'.code, 1,
            { capturedValid = false; true }, { fail("Lost network reached bind") }, { fail("Lost network reached ACK") }))
    }

    @Test fun networkLossDuringBindingPreventsAck() {
        var capturedValid = true
        val policy = NativePreviewSocketPolicy(NativePreviewNetworkGeneration()) { capturedValid }
        assertFalse(policy.protectBindAndAcknowledge('S'.code, 1,
            { true }, { capturedValid = false }, { fail("Lost network reached ACK") }))
    }

    @Test fun completedAckIsOrderedBeforeRevocationAndNoLaterAckCanCommit() {
        val generation = NativePreviewNetworkGeneration()
        val policy = NativePreviewSocketPolicy(generation) { true }
        val executor = Executors.newFixedThreadPool(2)
        val ackEntered = CountDownLatch(1)
        val releaseAck = CountDownLatch(1)
        val revokeEntered = CountDownLatch(1)
        val revoked = CountDownLatch(1)
        val acknowledgements = AtomicInteger()
        try {
            val request = executor.submit<Boolean> {
                policy.protectBindAndAcknowledge('Q'.code, 1, { true }, {}, {
                    ackEntered.countDown()
                    check(releaseAck.await(5, TimeUnit.SECONDS))
                    acknowledgements.incrementAndGet()
                })
            }
            assertTrue(ackEntered.await(5, TimeUnit.SECONDS))
            val revocation = executor.submit {
                revokeEntered.countDown()
                generation.revoke()
                revoked.countDown()
            }
            assertTrue(revokeEntered.await(5, TimeUnit.SECONDS))
            assertFalse("Revoke must be ordered after an ACK already holding admission", revoked.await(100, TimeUnit.MILLISECONDS))
            releaseAck.countDown()
            assertTrue(request.get(5, TimeUnit.SECONDS))
            revocation.get(5, TimeUnit.SECONDS)
            assertEquals(1, acknowledgements.get())
            assertFalse(policy.protectBindAndAcknowledge('Q'.code, 1, { true }, {}, { acknowledgements.incrementAndGet() }))
            assertEquals(1, acknowledgements.get())
        } finally {
            releaseAck.countDown()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    @Test fun failedAckDoesNotReportSuccess() {
        val policy = NativePreviewSocketPolicy(NativePreviewNetworkGeneration()) { true }
        assertFalse(policy.protectBindAndAcknowledge('S'.code, 1,
            { true }, {}, { throw IOException("synthetic closed client") }))
    }

    @Test fun failedCapturedNetworkInspectionRevokesWithoutCallingProtection() {
        val generation = NativePreviewNetworkGeneration()
        val policy = NativePreviewSocketPolicy(generation) { throw IOException("synthetic network inspection failure") }
        assertFalse(policy.protectBindAndAcknowledge('Q'.code, 1,
            { fail("Unavailable network reached protection"); true }, {}, {}))
        assertFalse(generation.isCurrent())
    }
}
