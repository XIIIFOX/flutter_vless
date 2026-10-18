package com.github.tfox.flutter_vless.xray.core

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

class BoundedCoreCommandTest {
    /** Controlled pipe never promises EOF; reads without available data fail. */
    private class Command(val bytes: ByteArray = byteArrayOf(), val exitAtMillis: Long = 0,
        val code: Int = 0, val continuous: Boolean = false, val survivesKill: Boolean = false,
        val interruptWait: Boolean = false) : Process() {
        var now = 0L
        var alive = exitAtMillis > 0
        var forced = false
        var waits = 0
        var reads = 0
        var closed = 0
        private var offset = 0
        private val input = object : InputStream() {
            override fun available() = if (continuous) 4096 else bytes.size - offset
            override fun read(): Int = throw AssertionError("Unbounded/EOF read is forbidden")
            override fun read(target: ByteArray, start: Int, length: Int): Int {
                check(available() > 0) { "Read before data availability" }
                reads++
                val count = minOf(length, available())
                if (continuous) java.util.Arrays.fill(target, start, start + count, 1.toByte())
                else { bytes.copyInto(target, start, offset, offset + count); offset += count }
                now += TimeUnit.MILLISECONDS.toNanos(1)
                return count
            }
            override fun close() { closed++ }
        }
        override fun getInputStream() = input
        override fun getErrorStream() = object : InputStream() {
            override fun read() = -1
            override fun close() { closed++ }
        }
        override fun getOutputStream() = object : ByteArrayOutputStream() {
            override fun close() { closed++ }
        }
        override fun waitFor(): Int = throw AssertionError("Unbounded process wait is forbidden")
        override fun waitFor(timeout: Long, unit: TimeUnit): Boolean {
            waits++
            if (interruptWait && !forced) throw InterruptedException()
            now += unit.toNanos(timeout)
            if (!forced && now >= TimeUnit.MILLISECONDS.toNanos(exitAtMillis)) alive = false
            return !alive
        }
        override fun exitValue(): Int {
            check(!alive)
            return code
        }
        override fun isAlive() = alive
        override fun destroy() { forced = true; if (!survivesKill) alive = false }
        override fun destroyForcibly(): Process { destroy(); return this }
    }

    private fun capture(command: Command, maxBytes: Int = 65536) =
        BoundedCoreCommand.capture(command, timeoutMillis = 100, maxBytes = maxBytes, nanoTime = { command.now })

    @Test fun collectsCompleteBoundedOutputAfterSuccessfulExitWithoutWaitingForEof() {
        val command = Command("{\"stat\":[]}".toByteArray(), exitAtMillis = 30)
        assertEquals("{\"stat\":[]}", capture(command)?.toString(Charsets.UTF_8))
        assertFalse(command.forced)
        assertFalse(command.alive)
        assertEquals(3, command.closed)
    }

    @Test fun silentHungApiIsKilledBeforeAnyPipeReadAndAllStreamsClose() {
        val command = Command(exitAtMillis = 10000)
        assertNull(capture(command))
        assertEquals(0, command.reads)
        assertTrue(command.forced)
        assertFalse(command.alive)
        assertTrue(command.now <= TimeUnit.MILLISECONDS.toNanos(101))
        assertEquals(3, command.closed)
    }

    @Test fun continuousOrOversizedOutputCannotGrowTheCapture() {
        for (command in listOf(Command(ByteArray(10), 10000), Command(exitAtMillis = 10000, continuous = true))) {
            assertNull(capture(command, maxBytes = 9))
            assertTrue(command.forced)
            assertEquals(1, command.reads)
            assertEquals(3, command.closed)
        }
    }

    @Test fun outputBoundaryAndNonzeroExitAreDistinct() {
        assertArrayEquals(ByteArray(9), capture(Command(ByteArray(9)), maxBytes = 9))
        assertNull(capture(Command("{\"stat\":[]}".toByteArray(), code = 1)))
    }

    @Test fun cancellationStillOwnsTerminationAndRestoresInterrupt() {
        for (alreadyInterrupted in listOf(false, true)) {
            val command = Command(exitAtMillis = 10000, interruptWait = true)
            try {
                if (alreadyInterrupted) Thread.currentThread().interrupt()
                assertNull(capture(command))
                assertTrue(Thread.currentThread().isInterrupted)
                assertTrue(command.forced)
                assertFalse(command.alive)
                assertEquals(3, command.closed)
            } finally { Thread.interrupted() }
        }
    }

    @Test fun failedForcedReapIsBoundedAndCannotPublishSuccessfulOutput() {
        val command = Command(exitAtMillis = 10000, survivesKill = true)
        assertNull(capture(command))
        assertTrue(command.forced)
        assertTrue(command.alive)
        assertTrue(command.now <= TimeUnit.MILLISECONDS.toNanos(601))
        assertEquals(3, command.closed)
    }
}
