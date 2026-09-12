package com.github.tfox.flutter_vless.xray.service

import org.junit.Assert.*
import org.junit.Test
import java.io.IOException

class FileDescriptorTransferTest {
    @Test fun exhaustionIsBoundedAndLeavesAuthorizationOwnedForRecovery() {
        val policy = SessionRecoveryPolicy()
        val owner = policy.activate()
        var attempts = 0
        var waits = 0
        assertFalse(FileDescriptorTransfer.send({ policy.owns(owner) }, { true }, {
            attempts++; throw IOException("Controlled unavailable receiver")
        }, { waits++ }))
        assertEquals(10, attempts); assertEquals(9, waits)
        assertTrue(policy.authorized); assertTrue(policy.owns(owner))
        val recoveryOwner = policy.restart()
        assertFalse(policy.owns(owner)); assertTrue(policy.owns(recoveryOwner))
        assertEquals(1000L, policy.nextDelayMillis())
    }

    @Test fun lateSuccessfulWriteCannotConfirmAReplacedOrStoppedGeneration() {
        for (stop in listOf(false, true)) {
            val policy = SessionRecoveryPolicy()
            val owner = policy.activate()
            assertFalse(FileDescriptorTransfer.send({ policy.owns(owner) }, { true }, {
                if (stop) policy.disarm() else policy.restart()
            }, { fail("A successful write must not be retried") }))
            assertFalse(policy.owns(owner)); assertEquals(!stop, policy.authorized)
        }
    }

    @Test fun recoversBeforeTheLimitAndStopsWhenTheWorkerDies() {
        var attempts = 0
        assertTrue(FileDescriptorTransfer.send({ true }, { true }, {
            if (++attempts < 3) throw IOException("Controlled startup delay")
        }, {}))
        assertEquals(3, attempts)
        attempts = 0
        var alive = true
        assertFalse(FileDescriptorTransfer.send({ true }, { alive }, {
            attempts++; alive = false; throw IOException("Controlled worker exit")
        }, { fail("An exited worker must not be retried") }))
        assertEquals(1, attempts)
    }
}
