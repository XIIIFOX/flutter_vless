package com.github.tfox.flutter_vless.xray.core

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

class DelayProbeCleanupTest {
    private class Child : Process() {
        var alive = true
        var destroys = 0
        var forces = 0
        var waits = 0
        var gracefulExit = false
        var forcedExit = true
        var onWait: ((Int) -> Boolean)? = null
        override fun getInputStream() = ByteArrayInputStream(byteArrayOf())
        override fun getErrorStream() = ByteArrayInputStream(byteArrayOf())
        override fun getOutputStream() = ByteArrayOutputStream()
        override fun isAlive() = alive
        override fun exitValue(): Int { check(!alive); return 0 }
        override fun waitFor(): Int = error("Cleanup must never use an unbounded wait")
        override fun waitFor(timeout: Long, unit: TimeUnit): Boolean {
            assertFalse("Cleanup must clear cancellation while reaping", Thread.currentThread().isInterrupted)
            assertTrue(unit.toNanos(timeout) <= TimeUnit.SECONDS.toNanos(1))
            waits++
            return onWait?.invoke(waits) ?: !alive
        }
        override fun destroy() { destroys++; if (gracefulExit) alive = false }
        override fun destroyForcibly(): Process { forces++; if (forcedExit) alive = false; return this }
    }

    private fun withFile(block: (File) -> Unit) {
        val file = Files.createTempFile("delay-owned-cleanup", ".json").toFile()
        val wasInterrupted = Thread.interrupted()
        try { block(file) } finally {
            file.delete()
            Thread.interrupted()
            if (wasInterrupted) Thread.currentThread().interrupt()
        }
    }

    @Test fun alreadyInterruptedCancellationStillForcesReapsAndDeletesTheFile() = withFile { file ->
        val child = Child()
        Thread.currentThread().interrupt()
        assertTrue(DelayProbeCleanup.cleanup(child, file))
        assertFalse(child.alive)
        assertEquals(1, child.destroys)
        assertEquals(1, child.forces)
        assertEquals(1, child.waits)
        assertFalse(file.exists())
        assertTrue(Thread.currentThread().isInterrupted)
    }

    @Test fun interruptionDuringGracefulWaitCannotSkipForcedTerminationOrFileDeletion() = withFile { file ->
        val child = Child().apply { onWait = { if (it == 1) throw InterruptedException() else !alive } }
        assertTrue(DelayProbeCleanup.cleanup(child, file))
        assertEquals(2, child.waits)
        assertEquals(1, child.forces)
        assertFalse(child.alive)
        assertFalse(file.exists())
        assertTrue(Thread.currentThread().isInterrupted)
    }

    @Test fun interruptionDuringForcedReapKeepsTheSameBoundedDeadlineAndRestoresInterrupt() = withFile { file ->
        val child = Child().apply { onWait = {
            when (it) { 1 -> false; 2 -> throw InterruptedException(); else -> !alive }
        } }
        assertTrue(DelayProbeCleanup.cleanup(child, file))
        assertEquals(3, child.waits)
        assertEquals(1, child.forces)
        assertFalse(file.exists())
        assertTrue(Thread.currentThread().isInterrupted)
    }

    @Test fun aChildThatSurvivesTheReapBudgetReportsFailureButStillDeletesItsFile() = withFile { file ->
        val child = Child().apply { forcedExit = false }
        assertFalse(DelayProbeCleanup.cleanup(child, file, reapMillis = 0))
        assertTrue(child.alive)
        assertEquals(1, child.waits)
        assertEquals(1, child.forces)
        assertFalse(file.exists())
        assertFalse(Thread.currentThread().isInterrupted)
    }

    @Test fun gracefulExitNeedsNoForceAndPreparationFailureWithNoChildStillDeletesItsFile() = withFile { file ->
        val child = Child().apply { gracefulExit = true }
        assertTrue(DelayProbeCleanup.cleanup(child, file))
        assertEquals(1, child.waits)
        assertEquals(0, child.forces)
        assertFalse(file.exists())
        file.writeText("synthetic private file")
        assertTrue(DelayProbeCleanup.cleanup(null, file))
        assertFalse(file.exists())
    }

    @Test fun unexpectedWaitFailureIsReportedWithoutEscapingOrSkippingOwnedCleanup() = withFile { file ->
        val child = Child().apply { onWait = { if (it == 1) error("synthetic wait failure") else !alive } }
        assertFalse(DelayProbeCleanup.cleanup(child, file))
        assertEquals(1, child.forces)
        assertFalse(child.alive)
        assertFalse(file.exists())
    }

    @Test fun failedFileRemovalIsReportedWithoutMaskingTheMeasurementOutcome() {
        var deletes = 0
        val file = object : File("unused-synthetic-file") {
            override fun delete(): Boolean { deletes++; return false }
            override fun exists() = true
        }
        assertFalse(DelayProbeCleanup.cleanup(null, file))
        assertEquals(1, deletes)
    }
}
