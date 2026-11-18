package com.github.tfox.flutter_vless.xray.core

import java.io.ByteArrayOutputStream
import java.util.concurrent.TimeUnit

/** Only bounded protocol frames from the currently owned process are decoded. */
internal object NativeBalancerDiagnostics {
    private const val CAPABILITIES = "{\"stage\":\"capabilities\",\"code\":0,\"capability\":1}\n"
    const val STARTED = "{\"stage\":\"started\",\"code\":0}"
    private const val SELECTIONS = "{\"stage\":\"selections\",\"code\":0,\"rows\":\""
    private val row = Regex("[1-9][0-9]{0,18},[1-9][0-9]{0,9},[1-9][0-9]{0,9}")

    fun supported(bytes: ByteArray?): Boolean = bytes?.contentEquals(CAPABILITIES.toByteArray(Charsets.US_ASCII)) == true

    fun rows(line: String?, maxLines: Int, maxBytes: Int): String? {
        if (line == null || line.length < SELECTIONS.length + 2 ||
            !line.startsWith(SELECTIONS) || !line.endsWith("\"}")) return null
        val body = line.substring(SELECTIONS.length, line.length - 2)
        if (body.isEmpty()) return ""
        val rows = body.split("\\n")
        if (rows.size > maxLines) return null
        var previous: Long? = null
        for (raw in rows) {
            if (!row.matches(raw)) return null
            val parts = raw.split(',')
            val sequence = parts[0].toLongOrNull() ?: return null
            if (previous != null && sequence - 1 != previous) return null
            if (parts[1].toIntOrNull() == null || parts[2].toIntOrNull() == null) return null
            previous = sequence
        }
        var bytes = 0
        return rows.asReversed().takeWhile { bytes += it.length + 1; bytes <= maxBytes }
            .asReversed().joinToString("\n")
    }
}

/** Scoped to one worker. No snapshots are cached or emitted as native logs. */
internal class NativeBalancerProcess(private val process: Process, private val maxLines: Int) {
    private var pendingReply = false
    private var disabled = false

    fun awaitStarted(): Boolean = readLine(timeoutMillis = 3000) == NativeBalancerDiagnostics.STARTED

    @Synchronized fun snapshot(maxLines: Int, maxBytes: Int): String {
        if (disabled || pendingReply || !send("snapshot\n")) return ""
        val raw = reply()
        val rows = NativeBalancerDiagnostics.rows(raw, this.maxLines, maxBytes) ?: return ""
        return rows.lineSequence().toList().takeLast(maxLines).joinToString("\n")
    }

    @Synchronized fun disable(): Boolean {
        if (disabled) return true
        if (!process.isAlive) { disabled = true; return true }
        // A timed-out snapshot must not be mistaken for a disable reply.
        if (pendingReply && reply() == null) return false
        if (!send("disable\n")) return false
        disabled = NativeBalancerDiagnostics.rows(reply(), maxLines, 4096) == ""
        return disabled || !process.isAlive
    }

    fun closeInput() { runCatching { process.outputStream.close() } }

    private fun send(value: String): Boolean = runCatching {
        check(process.isAlive)
        process.outputStream.write(value.toByteArray(Charsets.US_ASCII))
        process.outputStream.flush()
        pendingReply = true
    }.isSuccess

    private fun reply(): String? = readLine(500).also { if (it != null) pendingReply = false }

    private fun readLine(timeoutMillis: Long): String? {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        val output = ByteArrayOutputStream()
        return try {
            val input = process.inputStream
            while (System.nanoTime() < deadline && output.size() < 16 * 1024) {
                val available = input.available().coerceAtMost(512)
                if (available == 0) {
                    if (!process.isAlive) return null
                    Thread.sleep(5)
                    continue
                }
                repeat(available) {
                    val byte = input.read()
                    if (byte == '\n'.code) return output.toString(Charsets.US_ASCII.name())
                    if (byte < 32 || byte > 126 || output.size() == 16 * 1024) return null
                    output.write(byte)
                }
            }
            null
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            null
        } catch (_: Exception) { null }
    }
}
