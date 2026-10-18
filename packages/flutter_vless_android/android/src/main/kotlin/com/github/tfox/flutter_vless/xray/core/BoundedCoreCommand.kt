package com.github.tfox.flutter_vless.xray.core

import java.io.ByteArrayOutputStream
import java.util.concurrent.TimeUnit

/** Owns one fixed Core CLI command; stdout/stderr must be merged at launch.
 * Poll only currently available pipe bytes: waiting for EOF before waitFor
 * defeats both the time and memory limits when the API stops responding.
 * This collector never starts another reader or retains a background worker.
 */
internal object BoundedCoreCommand {
    fun capture(process: Process, timeoutMillis: Long = 2000, maxBytes: Int = 64 * 1024,
        nanoTime: () -> Long = System::nanoTime): ByteArray? {
        require(timeoutMillis in 1..10000 && maxBytes in 1..1024 * 1024)
        var interrupted = Thread.interrupted()
        var result: ByteArray? = null
        try {
            if (!interrupted) {
                val deadline = nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
                val output = ByteArrayOutputStream(minOf(maxBytes, 4096))
                val bytes = ByteArray(4096)
                var finished = false
                while (nanoTime() < deadline) {
                    val available = process.inputStream.available()
                    if (available > 0) {
                        val count = process.inputStream.read(bytes, 0, minOf(bytes.size, available))
                        if (count <= 0 || count > maxBytes - output.size()) break
                        output.write(bytes, 0, count)
                        continue // Recheck the same deadline even for continuous output.
                    }
                    if (!process.isAlive) {
                        if (process.exitValue() == 0) result = output.toByteArray()
                        finished = true
                        break
                    }
                    process.waitFor(minOf(TimeUnit.MILLISECONDS.toNanos(20),
                        (deadline - nanoTime()).coerceAtLeast(1)), TimeUnit.NANOSECONDS)
                }
                if (!finished) result = null
            }
        } catch (_: InterruptedException) {
            interrupted = true
        } catch (_: Exception) {
            result = null
        } finally {
            // Kill/reap belongs to this invocation even after interruption.
            // Core's fixed stats CLI creates no descendants or other pipes.
            if (process.isAlive) runCatching { process.destroyForcibly() }
            val deadline = nanoTime() + TimeUnit.MILLISECONDS.toNanos(500)
            while (process.isAlive && nanoTime() < deadline) {
                try { process.waitFor((deadline - nanoTime()).coerceAtLeast(1), TimeUnit.NANOSECONDS) }
                catch (_: InterruptedException) { interrupted = true }
                catch (_: Exception) { break }
            }
            if (process.isAlive) result = null
            runCatching { process.outputStream.close() }
            runCatching { process.inputStream.close() }
            runCatching { process.errorStream.close() }
            if (interrupted) Thread.currentThread().interrupt()
        }
        return result
    }
}
