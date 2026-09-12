package com.github.tfox.flutter_vless.xray.service

import org.junit.Assert.*
import org.junit.Test

class SessionRecoveryPolicyTest {
    @Test fun oldCallbacksCannotChangeNewWorkersAndStopDisarmsAllCallbacks() {
        val policy = SessionRecoveryPolicy()
        val initial = policy.activate()
        val restarted = policy.restart()
        assertFalse(policy.owns(initial)); assertTrue(policy.owns(restarted))
        val replacement = policy.activate()
        assertFalse(policy.owns(restarted)); assertTrue(policy.owns(replacement))
        policy.disarm()
        assertFalse(policy.owns(replacement)); assertFalse(policy.authorized)
    }
    @Test fun persistentFailuresStayAuthorizedWithCappedBackoff() {
        val policy = SessionRecoveryPolicy()
        policy.activate()
        assertEquals(listOf(1000L, 2000L, 4000L, 8000L, 16000L, 32000L, 60000L), List(7) { policy.nextDelayMillis() })
        repeat(1000) { assertEquals(60000L, policy.nextDelayMillis()) }
        assertTrue(policy.authorized)
        policy.recovered()
        assertEquals(1000L, policy.nextDelayMillis())
    }
}
