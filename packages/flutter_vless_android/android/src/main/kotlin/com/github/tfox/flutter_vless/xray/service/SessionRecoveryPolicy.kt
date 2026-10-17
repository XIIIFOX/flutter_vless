package com.github.tfox.flutter_vless.xray.service

/** Pure ownership/backoff boundary, shared by every delayed worker callback. */
internal class SessionRecoveryPolicy {
    var options = NativeVlessOptions.Reconnect()
    @Volatile var generation = 0L; private set
    @Volatile var authorized = false; private set
    @Volatile var failures = 0; private set
    @Synchronized fun activate(): Long { authorized = true; failures = 0; return ++generation }
    @Synchronized fun disarm() { authorized = false; ++generation }
    @Synchronized fun owns(candidate: Long) = authorized && generation == candidate
    @Synchronized fun restart(): Long { check(authorized); return ++generation }
    @Synchronized fun recovered() { failures = 0 }
    @Synchronized fun nextDelayMillis(): Long {
        val delay = options.delay(failures)
        failures = (failures + 1).coerceAtMost(1000)
        return delay
    }
    @Synchronized fun mayRetry() = options.mayRetry(failures)
}
