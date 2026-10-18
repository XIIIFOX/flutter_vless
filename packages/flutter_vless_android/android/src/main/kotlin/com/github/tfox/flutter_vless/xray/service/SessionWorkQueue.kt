package com.github.tfox.flutter_vless.xray.service

import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** One service's work lifetime; callbacks arriving after close are harmless. */
internal class SessionWorkQueue(
    private val executor: ScheduledThreadPoolExecutor = ScheduledThreadPoolExecutor(1)
) {
    private val admission = Any()
    private var closed = false
    private val delayed = mutableSetOf<ScheduledFuture<*>>()

    init {
        executor.removeOnCancelPolicy = true
    }

    fun execute(action: () -> Unit): Boolean = synchronized(admission) {
        if (closed) return@synchronized false
        // The owned executor cannot shut down between admission and submission.
        // Unexpected rejection while open must still propagate to the caller.
        executor.execute(action)
        true
    }

    fun schedule(action: () -> Unit, delay: Long, unit: TimeUnit): Boolean = synchronized(admission) {
        if (closed) return@synchronized false
        lateinit var future: ScheduledFuture<*>
        future = executor.schedule({
            val run = synchronized(admission) {
                delayed.remove(future)
                !closed
            }
            if (run) action()
        }, delay, unit)
        delayed.add(future)
        true
    }

    /** Drain accepted immediate work, then perform exactly one final cleanup. */
    fun close(cleanup: () -> Unit): Boolean = synchronized(admission) {
        if (closed) return@synchronized false
        closed = true
        delayed.forEach { it.cancel(false) }
        delayed.clear()
        try {
            executor.execute(cleanup)
        } finally {
            executor.shutdown()
        }
        true
    }
}
