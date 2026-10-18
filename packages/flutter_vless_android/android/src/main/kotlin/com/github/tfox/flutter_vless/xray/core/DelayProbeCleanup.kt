package com.github.tfox.flutter_vless.xray.core

import java.io.File
import java.util.concurrent.TimeUnit

/** Cancellation must not skip termination of this probe's child or its private file. */
internal object DelayProbeCleanup {
    internal fun cleanup(process: Process?, file: File, graceMillis: Long = 1000, reapMillis: Long = 1000): Boolean {
        require(graceMillis in 0..1000 && reapMillis in 0..1000)
        var interrupted = Thread.interrupted()
        var successful = true
        try {
            if (process != null) {
                var exited = false
                try {
                    process.destroy()
                    if (!interrupted) exited = process.waitFor(graceMillis, TimeUnit.MILLISECONDS)
                } catch (_: InterruptedException) {
                    interrupted = true
                } catch (_: Exception) {
                    successful = false
                }
                if (!exited) {
                    try { process.destroyForcibly() } catch (_: Exception) { successful = false }
                    val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(reapMillis)
                    while (!exited) {
                        val remaining = deadline - System.nanoTime()
                        if (remaining <= 0) break
                        try {
                            exited = process.waitFor(remaining, TimeUnit.NANOSECONDS)
                            break
                        } catch (_: InterruptedException) {
                            // Keep reaping within the original deadline, then restore cancellation.
                            interrupted = true
                        } catch (_: Exception) {
                            successful = false
                            break
                        }
                    }
                }
                try { if (process.isAlive) successful = false } catch (_: Exception) { successful = false }
            }
        } finally {
            try { if (!file.delete() && file.exists()) successful = false } catch (_: Exception) { successful = false }
            if (interrupted) Thread.currentThread().interrupt()
        }
        return successful
    }
}
