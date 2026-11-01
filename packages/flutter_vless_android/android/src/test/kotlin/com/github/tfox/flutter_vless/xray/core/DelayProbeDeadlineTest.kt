package com.github.tfox.flutter_vless.xray.core

import java.io.DataInputStream
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

/** Real loopback peers exercise time consumed across SOCKS and application I/O. */
class DelayProbeDeadlineTest {
    @Test(timeout = 12000) fun slowStatusLineCannotRenewTheTotalProbeBudget() {
        withPeer({ socket ->
            socks(socket)
            val request = socket.getInputStream()
            var tail = ""
            while (!tail.endsWith("\r\n\r\n")) tail = (tail + request.read().toChar()).takeLast(4)
            for (byte in "HTTP/1.1 200 OK\r\n".toByteArray()) {
                socket.getOutputStream().write(byte.toInt())
                socket.getOutputStream().flush()
                Thread.sleep(600)
            }
        }) { port ->
            val client = Executors.newSingleThreadExecutor()
            try {
                val started = System.nanoTime()
                val result = client.submit<Throwable?> {
                    try { AuthenticatedSocksClient.measure(port, null, "http://target.example/"); null }
                    catch (error: Throwable) { error }
                }
                val error = try { result.get(6500, TimeUnit.MILLISECONDS) }
                    catch (_: TimeoutException) { fail("Slow HTTP bytes renewed the delay budget beyond 6.5 seconds"); null }
                assertNotNull("An incomplete HTTP status line cannot qualify a delay", error)
                assertTrue("Expected expiry of the shared probe deadline", error is ReadinessFailure && error.stage == ReadinessStage.DEADLINE)
                assertTrue(System.nanoTime() - started < TimeUnit.MILLISECONDS.toNanos(6500))
            } finally { client.shutdownNow(); assertTrue(client.awaitTermination(2, TimeUnit.SECONDS)) }
        }
    }

    @Test(timeout = 12000) fun socksAndHttpConsumeTheSameBudget() {
        withPeer({ socket ->
            socks(socket, handshakeDelayMillis = 3300)
            val input = socket.getInputStream()
            var tail = ""
            while (!tail.endsWith("\r\n\r\n")) tail = (tail + input.read().toChar()).takeLast(4)
            Thread.sleep(3300)
            socket.getOutputStream().write("HTTP/1.1 204 No Content\r\n\r\n".toByteArray())
        }) { port ->
            val started = System.nanoTime()
            val error = assertThrows(Exception::class.java) {
                AuthenticatedSocksClient.measure(port, null, "http://target.example/")
            }
            assertTrue(error is ReadinessFailure && error.stage == ReadinessStage.DEADLINE)
            assertTrue("SOCKS and HTTP must not receive separate 5-second budgets", System.nanoTime() - started < TimeUnit.MILLISECONDS.toNanos(6500))
        }
    }

    @Test(timeout = 12000) fun blockedTlsHandshakeExpiresAndClosesThePeer() {
        withPeer({ socket ->
            socks(socket)
            // A TLS peer that never sends a ServerHello. Drain until client close.
            while (socket.getInputStream().read() >= 0) { }
        }) { port ->
            val started = System.nanoTime()
            val error = assertThrows(Exception::class.java) {
                AuthenticatedSocksClient.measure(port, null, "https://target.example/")
            }
            assertTrue(error is ReadinessFailure && error.stage == ReadinessStage.DEADLINE)
            assertTrue(System.nanoTime() - started < TimeUnit.MILLISECONDS.toNanos(6500))
        }
    }

    @Test(timeout = 5000) fun interruptedBlockedHttpProbeDrainsWithinItsOriginalBudgetAndRestoresCancellation() {
        val requestArrived = CountDownLatch(1)
        val phase = StartupReadiness(1200, { true })
        val outcome = AtomicReference<Throwable>()
        val cancellationRestored = AtomicBoolean()
        var client: Thread? = null
        try {
            withPeer({ socket ->
                socks(socket)
                val input = socket.getInputStream()
                var tail = ""
                while (!tail.endsWith("\r\n\r\n")) tail = (tail + input.read().toChar()).takeLast(4)
                requestArrived.countDown()
                while (input.read() >= 0) { } // Wait for the probe's socket ownership to release us.
            }) { port ->
                client = Thread({
                    try { phase.use { AuthenticatedSocksClient.measure(port, null, "http://target.example/", it) } }
                    catch (error: Throwable) { outcome.set(error) }
                    finally { cancellationRestored.set(Thread.currentThread().isInterrupted) }
                }, "test-owned-interrupted-probe").apply { start() }
                assertTrue(requestArrived.await(2, TimeUnit.SECONDS))
                client!!.interrupt()
                client!!.join(2000)
                assertFalse("Interruption cannot leave a delay worker beyond its original deadline", client!!.isAlive)
                assertTrue(outcome.get() is ReadinessFailure)
                assertEquals(ReadinessStage.INTERRUPTED, (outcome.get() as ReadinessFailure).stage)
                assertTrue(cancellationRestored.get())
                assertTrue(phase.timerTerminated)
            }
        } finally {
            phase.cancel()
            client?.interrupt()
            client?.join(2000)
            phase.close()
            assertFalse(client?.isAlive == true)
        }
    }

    private fun socks(socket: Socket, handshakeDelayMillis: Long = 0) {
        val input = DataInputStream(socket.getInputStream())
        assertArrayEquals(byteArrayOf(5, 1, 0), ByteArray(3).also(input::readFully))
        if (handshakeDelayMillis > 0) Thread.sleep(handshakeDelayMillis)
        socket.getOutputStream().write(byteArrayOf(5, 0))
        assertArrayEquals(byteArrayOf(5, 1, 0, 3), ByteArray(4).also(input::readFully))
        input.readFully(ByteArray(input.readUnsignedByte())); input.readUnsignedShort()
        socket.getOutputStream().write(byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, 0, 80))
    }

    private fun withPeer(serve: (Socket) -> Unit, probe: (Int) -> Unit) {
        ServerSocket(0).use { listener ->
            val sockets = CopyOnWriteArrayList<Socket>()
            val executor = Executors.newSingleThreadExecutor()
            val peer = executor.submit {
                listener.accept().use { socket ->
                    sockets.add(socket)
                    socket.soTimeout = 9000
                    try { serve(socket) } catch (_: java.io.IOException) { /* Closed by the bounded probe/fixture. */ }
                }
            }
            try { probe(listener.localPort) }
            finally {
                sockets.forEach { it.close() }
                peer.cancel(true)
                executor.shutdownNow()
                assertTrue("Fixture peer must be reaped", executor.awaitTermination(2, TimeUnit.SECONDS))
            }
        }
    }
}
