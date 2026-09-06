package com.github.tfox.flutter_vless.xray.service

import android.net.ConnectivityManager
import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.NetworkCapabilities
import android.net.Network
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.Os
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.util.Collections
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.SynchronousQueue

/** Receives actual SCM_RIGHTS descriptors, never process-local FD numbers. */
class XraySocketProtector(
    private val service: VpnService,
    private val protectFd: (Int) -> Boolean = service::protect
) : Closeable {
    val socketName = "flutter-vless-protect-${UUID.randomUUID()}"
    private val server = LocalServerSocket(socketName)
    private val verified = CountDownLatch(1)
    @Volatile private var closed = false
    private val clients = Collections.synchronizedSet(mutableSetOf<LocalSocket>())
    private val requests = ThreadPoolExecutor(0, 8, 10, TimeUnit.SECONDS, SynchronousQueue(),
        { task -> Thread(task, "xray-protection-request").apply { isDaemon = true } })
    private val worker = Thread({ serve() }, "xray-socket-protector").apply {
        isDaemon = true
        start()
    }

    fun awaitVerified(): Boolean = verified.await(3, TimeUnit.SECONDS) && !closed

    private fun serve() {
        while (!closed) {
            try {
                val accepted = server.accept()
                clients.add(accepted)
                try { requests.execute { serveClient(accepted) } }
                catch (_: Exception) { clients.remove(accepted); accepted.close() }
            } catch (_: Exception) {
                // Closing the server wakes accept().
            }
        }
    }

    private fun serveClient(accepted: LocalSocket) {
        try {
            accepted.use { socket ->
                socket.soTimeout = 2000
                if (socket.peerCredentials.uid != Process.myUid()) return@use
                val command = socket.inputStream.read()
                val descriptors = socket.ancillaryFileDescriptors.orEmpty()
                try {
                    if (closed) return@use
                    when (command) {
                        'H'.code, 'P'.code -> {
                            val accepted = descriptors.size == 1 && ParcelFileDescriptor.dup(descriptors[0]).use {
                                protectFd(it.fd)
                            }
                            socket.outputStream.write(if (accepted) 1 else 0)
                            if (command == 'H'.code && accepted) verified.countDown()
                        }
                        'D'.code -> {
                            if (descriptors.isNotEmpty()) return@use
                            val input = DataInputStream(socket.inputStream)
                            val size = input.readUnsignedShort()
                            require(size in 12..4096)
                            val query = ByteArray(size).also { input.readFully(it) }
                            val network = physicalNetwork() ?: return@use
                            val answer = XrayPhysicalDns.query(network, query)
                            if (closed) return@use
                            DataOutputStream(socket.outputStream).apply {
                                writeShort(answer.size)
                                write(answer)
                            }
                        }
                    }
                } finally {
                    descriptors.forEach { descriptor -> runCatching { Os.close(descriptor) } }
                }
            }
        } catch (_: Exception) {
            // EOF, timeout and shutdown produce no positive acknowledgement.
        } finally {
            clients.remove(accepted)
        }
    }

    /** Query current physical link properties on every resolver connection. */
    private fun physicalNetwork(): Network? {
        val manager = service.getSystemService(ConnectivityManager::class.java)
        val candidates = (listOfNotNull(manager.activeNetwork) + manager.allNetworks).distinct()
        val physical = candidates.filter {
            val caps = manager.getNetworkCapabilities(it)
            caps != null && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }
        return physical.firstOrNull {
            manager.getNetworkCapabilities(it)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
        } ?: physical.firstOrNull()
    }

    override fun close() {
        closed = true
        runCatching { server.close() }
        synchronized(clients) { clients.forEach { runCatching { it.close() } } }
        requests.shutdownNow()
        worker.interrupt()
    }
}
