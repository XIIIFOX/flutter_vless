package com.github.tfox.flutter_vless.xray.service

/** Pure ownership/backoff boundary, shared by every delayed worker callback. */
internal class SessionRecoveryPolicy {
    @Volatile var generation = 0L; private set
    @Volatile var authorized = false; private set
    @Volatile var failures = 0; private set
    @Synchronized fun activate(): Long { authorized = true; failures = 0; return ++generation }
    @Synchronized fun disarm() { authorized = false; ++generation }
    @Synchronized fun owns(candidate: Long) = authorized && generation == candidate
    @Synchronized fun restart(): Long { check(authorized); return ++generation }
    @Synchronized fun recovered() { failures = 0 }
    @Synchronized fun nextDelayMillis(): Long {
        val delay = (1000L shl failures.coerceAtMost(6)).coerceAtMost(60_000)
        failures = (failures + 1).coerceAtMost(30)
        return delay
    }
}
