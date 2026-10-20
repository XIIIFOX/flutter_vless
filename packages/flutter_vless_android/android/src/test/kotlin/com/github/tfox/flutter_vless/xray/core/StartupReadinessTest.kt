package com.github.tfox.flutter_vless.xray.core

import org.junit.Assert.*
import org.junit.Test
import org.mockito.Mockito
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.ByteArrayInputStream
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** All sockets are mocks; only the owned deadline executor is real. */
class StartupReadinessTest {
    @Test(timeout = 5000) fun onlyExactConnectRefusedCanRetryWithinTheSameBudget() {
        var clock = 0L; var attempts = 0
        val phase = StartupReadiness(5000, { true }, { clock }, { clock += TimeUnit.MILLISECONDS.toNanos(it) })
        phase.use {
            it.authenticated {
                attempts++
                if (attempts == 1) throw ReadinessFailure(ReadinessStage.LOCAL_CONNECT, 111)
            }
            assertEquals(2, attempts)
            assertEquals(TimeUnit.MILLISECONDS.toNanos(50), clock)
        }
        assertTrue(phase.timerTerminated)
    }

    @Test(timeout = 5000) fun allPostConnectFailuresAndOtherErrnosArePermanent() {
        val failures = listOf(ReadinessFailure(ReadinessStage.LOCAL_CONNECT, 13),
            ReadinessFailure(ReadinessStage.LOCAL_CONNECT), ReadinessFailure(ReadinessStage.SOCKS_METHOD, 111),
            ReadinessFailure(ReadinessStage.SOCKS_AUTH), ReadinessFailure(ReadinessStage.SOCKS_REPLY),
            ReadinessFailure(ReadinessStage.PRIVATE_CHALLENGE), ReadinessFailure(ReadinessStage.PACKET_CHALLENGE))
        for (failure in failures) {
            var attempts = 0
            val phase = StartupReadiness(isCurrent = { true })
            phase.use {
                assertSame(failure, assertThrows(ReadinessFailure::class.java) { it.authenticated { attempts++; throw failure } })
            }
            assertEquals(1, attempts); assertTrue(phase.timerTerminated)
        }
    }

    @Test(timeout = 5000) fun fragmentedReadsConsumeOneAbsoluteDeadline() {
        var clock = 0L; var reads = 0
        val socket = Mockito.mock(Socket::class.java)
        val input = object : InputStream() {
            override fun read(): Int = error("The bounded bulk read must be used")
            override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                reads++; clock += TimeUnit.SECONDS.toNanos(2); bytes[offset] = 1; return 1
            }
        }
        val phase = StartupReadiness(5000, { true }, { clock })
        phase.use {
            it.adopt(socket)
            val failure = assertThrows(ReadinessFailure::class.java) {
                it.readFully(socket, input, ByteArray(4), ReadinessStage.PRIVATE_CHALLENGE)
            }
            assertEquals(ReadinessStage.DEADLINE, failure.stage)
            assertEquals(3, reads)
        }
        Mockito.verify(socket).close(); assertTrue(phase.timerTerminated)
    }

    @Test(timeout = 5000) fun privateAndPacketChallengesShareTheSameRemainingTime() {
        var clock = 0L
        val socket = Mockito.mock(Socket::class.java)
        val input = object : InputStream() {
            override fun read(): Int = error("Use a bounded bulk read")
            override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                clock += TimeUnit.SECONDS.toNanos(3); bytes[offset] = 1; return 1
            }
        }
        val phase = StartupReadiness(5000, { true }, { clock })
        phase.use {
            it.adopt(socket)
            it.readFully(socket, input, ByteArray(1), ReadinessStage.PRIVATE_CHALLENGE)
            assertEquals(ReadinessStage.DEADLINE, assertThrows(ReadinessFailure::class.java) {
                it.readFully(socket, input, ByteArray(1), ReadinessStage.PACKET_CHALLENGE)
            }.stage)
        }
        assertTrue(phase.timerTerminated)
    }

    @Test(timeout = 5000) fun successAtDeadlineCannotBecomeReady() {
        var clock = 0L
        val phase = StartupReadiness(5000, { true }, { clock })
        phase.use {
            assertEquals(ReadinessStage.DEADLINE, assertThrows(ReadinessFailure::class.java) {
                it.authenticated { clock = TimeUnit.SECONDS.toNanos(5) }
            }.stage)
        }
        assertTrue(phase.timerTerminated)
    }

    @Test(timeout = 5000) fun revokedOrReplacedOwnerCannotPublishACompletedProbe() {
        var current = true
        val phase = StartupReadiness(isCurrent = { current })
        phase.use {
            assertEquals(ReadinessStage.OWNER, assertThrows(ReadinessFailure::class.java) {
                it.authenticated { current = false }
            }.stage)
        }
        assertTrue(phase.timerTerminated)
    }

    @Test(timeout = 5000) fun expiryClosesOnlyOwnedSocketsAndCallerDrainsTheTimer() {
        val closed = CountDownLatch(1)
        val owned = Mockito.mock(Socket::class.java)
        val foreign = Mockito.mock(Socket::class.java)
        Mockito.doAnswer { closed.countDown(); null }.`when`(owned).close()
        val phase = StartupReadiness(500, { true })
        phase.use {
            it.adopt(owned)
            assertTrue("A blocked operation must be released by owned socket close", closed.await(2, TimeUnit.SECONDS))
            assertEquals(ReadinessStage.DEADLINE, assertThrows(ReadinessFailure::class.java, it::check).stage)
            Mockito.verify(foreign, Mockito.never()).close()
        }
        assertTrue("Only caller finally may drain the deadline executor", phase.timerTerminated)
    }

    @Test(timeout = 5000) fun actualConnectorBlockedWriteIsReleasedByTheSharedDeadline() {
        val closed = CountDownLatch(1)
        val output = object : OutputStream() {
            override fun write(value: Int) {
                check(closed.await(2, TimeUnit.SECONDS)) { "Owned deadline did not release the blocked write" }
                throw IOException("Synthetic socket closed")
            }
            override fun write(bytes: ByteArray, offset: Int, length: Int) = write(0)
        }
        Mockito.mockConstruction(Socket::class.java) { socket, _ ->
            Mockito.`when`(socket.inputStream).thenReturn(ByteArrayInputStream(ByteArray(0)))
            Mockito.`when`(socket.outputStream).thenReturn(output)
            Mockito.doAnswer { closed.countDown(); null }.`when`(socket).close()
        }.use {
            val phase = StartupReadiness(500, { true })
            val started = System.nanoTime()
            phase.use {
                assertEquals(ReadinessStage.DEADLINE, assertThrows(ReadinessFailure::class.java) {
                    AuthenticatedSocksClient.connect(18111, LocalProxyCredentials("owned-user", "owned-password"),
                        "198.51.100.1", 18112, phase)
                }.stage)
            }
            assertTrue("Readiness write exceeded its bounded budget", System.nanoTime() - started < TimeUnit.SECONDS.toNanos(2))
            assertTrue(phase.timerTerminated)
        }
    }

    @Test(timeout = 5000) fun cleanupRestoresInterruptAndStillDrainsItsExecutor() {
        val phase = StartupReadiness(isCurrent = { true })
        Thread.currentThread().interrupt()
        try {
            phase.close()
            assertTrue(Thread.currentThread().isInterrupted)
            assertTrue(phase.timerTerminated)
        } finally { Thread.interrupted() }
    }

    @Test(timeout = 5000) fun cancellationIsIdempotentAndClosesOnlyItsOwnedSockets() {
        val owned = Mockito.mock(Socket::class.java); val foreign = Mockito.mock(Socket::class.java)
        val phase = StartupReadiness(isCurrent = { true })
        phase.use {
            it.adopt(owned)
            it.cancel(); it.cancel()
            Mockito.verify(owned, Mockito.times(1)).close()
            Mockito.verify(foreign, Mockito.never()).close()
            assertEquals(ReadinessStage.OWNER, assertThrows(ReadinessFailure::class.java, it::check).stage)
            assertFalse("The caller, rather than Stop, drains the timer", it.timerTerminated)
        }
        assertTrue(phase.timerTerminated)
    }

    @Test(timeout = 5000) fun actualConnectorClosesALateSocketWithoutConnectingAfterCancellation() {
        val phase = StartupReadiness(isCurrent = { true })
        Mockito.mockConstruction(Socket::class.java) { _, _ -> phase.cancel() }.use { sockets ->
            phase.use {
                assertEquals(ReadinessStage.OWNER, assertThrows(ReadinessFailure::class.java) {
                    AuthenticatedSocksClient.connect(18111, LocalProxyCredentials("owned-user", "owned-password"),
                        "198.51.100.1", 18112, it)
                }.stage)
                val late = sockets.constructed().single()
                Mockito.verify(late).close()
                Mockito.verify(late, Mockito.never()).connect(Mockito.any(), Mockito.anyInt())
            }
        }
        assertTrue(phase.timerTerminated)
    }

    @Test(timeout = 5000) fun cleanupFailureDoesNotReplaceThePrimaryStageOrSkipOtherSockets() {
        val first = Mockito.mock(Socket::class.java); val second = Mockito.mock(Socket::class.java)
        Mockito.doThrow(IOException("Synthetic close failure")).`when`(first).close()
        val phase = StartupReadiness(isCurrent = { true })
        val failure = assertThrows(ReadinessFailure::class.java) {
            phase.use {
                it.adopt(first); it.adopt(second)
                throw ReadinessFailure(ReadinessStage.SOCKS_AUTH)
            }
        }
        assertEquals(ReadinessStage.SOCKS_AUTH, failure.stage)
        assertEquals(ReadinessStage.CLEANUP, (failure.suppressed.single() as ReadinessFailure).stage)
        Mockito.verify(second).close(); assertTrue(phase.timerTerminated)
    }
}
