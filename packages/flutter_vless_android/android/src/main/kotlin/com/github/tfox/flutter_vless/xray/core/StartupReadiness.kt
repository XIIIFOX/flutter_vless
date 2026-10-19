package com.github.tfox.flutter_vless.xray.core

import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.net.Socket
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

internal enum class ReadinessStage(val code: Int) {
    LOCAL_CONNECT(1), SOCKS_METHOD(2), SOCKS_AUTH(3), SOCKS_REPLY(4),
    PRIVATE_CHALLENGE(5), PACKET_CHALLENGE(6), DEADLINE(7), OWNER(8), CLEANUP(9), INTERRUPTED(10)
}

/** Only fixed stage/errno metadata is safe for the diagnostics event store. */
internal class ReadinessFailure(val stage: ReadinessStage, val errno: Int? = null) : IOException("Startup readiness failed") {
    val diagnosticValue: Long get() = (stage.code.toLong() shl 32) or (errno?.takeIf { it in 1..4095 }?.toLong() ?: 0)
}

/** One startup's absolute budget and socket ownership. This never starts or
 * restarts a native worker. The expiry task only closes this phase's sockets;
 * the caller always owns timer cancellation and bounded termination. */
internal class StartupReadiness(
    timeoutMillis: Long = 5000,
    private val isCurrent: () -> Boolean,
    private val nanoTime: () -> Long = System::nanoTime,
    private val pause: (Long) -> Unit = Thread::sleep
) : Closeable {
    companion object {
        // Android's supported ABIs use Linux ECONNREFUSED. Keep this explicit
        // value independent of the zero-filled mockable Android jar in JVM tests.
        const val CONNECTION_REFUSED = 111
    }
    private val expires: Long
    private val lock = Any()
    private val sockets = mutableSetOf<Socket>()
    private var closed = false
    private var failure: ReadinessFailure? = null
    private val timer = ScheduledThreadPoolExecutor(1) { task ->
        Thread(task, "xray-startup-readiness-deadline").apply { isDaemon = true }
    }.apply { removeOnCancelPolicy = true }
    private val expiry: java.util.concurrent.ScheduledFuture<*>

    init {
        require(timeoutMillis in 1..5000)
        expires = nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        try { expiry = timer.schedule({ expire() }, timeoutMillis, TimeUnit.MILLISECONDS) }
        catch (error: Throwable) { timer.shutdownNow(); throw error }
    }

    private fun expire() {
        val owned = synchronized(lock) {
            if (closed) return
            if (failure == null) failure = ReadinessFailure(ReadinessStage.DEADLINE)
            sockets.toList()
        }
        owned.forEach { socket -> runCatching { socket.close() } }
    }

    fun check() {
        if (Thread.currentThread().isInterrupted) throw ReadinessFailure(ReadinessStage.INTERRUPTED)
        synchronized(lock) {
            failure?.let { throw it }
            if (closed) throw ReadinessFailure(ReadinessStage.OWNER)
        }
        if (!isCurrent()) throw ReadinessFailure(ReadinessStage.OWNER)
        if (expires - nanoTime() <= 0) throw ReadinessFailure(ReadinessStage.DEADLINE)
    }

    fun remainingMillis(maximum: Int = Int.MAX_VALUE): Int {
        check()
        val remaining = expires - nanoTime()
        if (remaining <= 0) throw ReadinessFailure(ReadinessStage.DEADLINE)
        return ((remaining + 999_999) / 1_000_000).coerceIn(1, maximum.toLong()).toInt()
    }

    fun adopt(socket: Socket) {
        check()
        synchronized(lock) {
            failure?.let { throw it }
            if (closed) throw ReadinessFailure(ReadinessStage.OWNER)
            sockets.add(socket)
        }
        check()
    }

    fun release(socket: Socket) = synchronized(lock) { sockets.remove(socket); Unit }

    fun readFully(socket: Socket, input: InputStream, bytes: ByteArray, stage: ReadinessStage) {
        var offset = 0
        while (offset < bytes.size) {
            socket.soTimeout = remainingMillis()
            val count = try { input.read(bytes, offset, bytes.size - offset) }
            catch (_: Exception) { check(); throw ReadinessFailure(stage) }
            check()
            if (count <= 0) throw ReadinessFailure(stage)
            offset += count
        }
    }

    fun authenticated(attempt: () -> Unit) {
        while (true) {
            check()
            try { attempt(); check(); return }
            catch (error: ReadinessFailure) {
                if (error.stage != ReadinessStage.LOCAL_CONNECT || error.errno != CONNECTION_REFUSED) throw error
                check()
                try { pause(minOf(50, remainingMillis().toLong())) }
                catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw ReadinessFailure(ReadinessStage.INTERRUPTED)
                }
            }
        }
    }

    internal val timerTerminated: Boolean get() = timer.isTerminated

    override fun close() {
        val owned = synchronized(lock) {
            if (closed) return
            closed = true
            sockets.toList().also { sockets.clear() }
        }
        var failed = false
        owned.forEach { socket -> if (runCatching { socket.close() }.isFailure) failed = true }
        expiry.cancel(false)
        timer.shutdownNow()
        var interrupted = Thread.interrupted()
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(500)
        try {
            while (!timer.isTerminated) {
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) { failed = true; break }
                try { timer.awaitTermination(remaining, TimeUnit.NANOSECONDS) }
                catch (_: InterruptedException) { interrupted = true }
            }
        } finally { if (interrupted) Thread.currentThread().interrupt() }
        if (failed) throw ReadinessFailure(ReadinessStage.CLEANUP)
    }
}
