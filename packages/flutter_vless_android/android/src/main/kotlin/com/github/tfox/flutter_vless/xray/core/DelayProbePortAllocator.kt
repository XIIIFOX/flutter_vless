package com.github.tfox.flutter_vless.xray.core

import java.io.Closeable
import java.net.BindException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket

/** Only standalone probes own this temporary SOCKS/API listener pair. */
internal object DelayProbePortAllocator {
    internal interface Listener : Closeable {
        val port: Int
    }

    internal class Reservation internal constructor(
        private val socks: Listener,
        private val api: Listener
    ) : Closeable {
        val socksPort: Int get() = socks.port
        val apiPort: Int get() = api.port
        private var closed = false

        @Synchronized override fun close() {
            if (closed) return
            closed = true
            try { api.close() } finally { socks.close() }
        }
    }

    private const val MAX_ATTEMPTS = 32

    internal fun reserve(bind: (Int) -> Listener = ::bindLoopback): Reservation {
        repeat(MAX_ATTEMPTS) {
            var socks: Listener? = null
            var api: Listener? = null
            try {
                val candidate = bind(0).also { socks = it }
                check(candidate.port in 1..65535) { "Invalid temporary listener port" }
                // The delay builder uses the adjacent port for its private API.
                if (candidate.port == 65535) return@repeat
                val adjacent = bind(candidate.port + 1).also { api = it }
                check(adjacent.port == candidate.port + 1) { "Unexpected temporary API port" }
                val result = Reservation(candidate, adjacent)
                socks = null
                api = null
                return result
            } catch (_: BindException) {
                // An unrelated listener may already own the adjacent port.
                // Retry allocation only; Core startup/probe failures are not retried here.
            } finally {
                try { api?.close() } finally { socks?.close() }
            }
        }
        throw BindException("No temporary listener pair is available")
    }

    private fun bindLoopback(port: Int): Listener {
        val socket = ServerSocket()
        try {
            socket.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port), 1)
            return object : Listener {
                override val port: Int get() = socket.localPort
                override fun close() = socket.close()
            }
        } catch (error: Exception) {
            runCatching { socket.close() }
            throw error
        }
    }
}
