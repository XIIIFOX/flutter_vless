package com.github.tfox.flutter_vless.xray.service

import android.net.ConnectivityManager
import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.NetworkCapabilities
import android.net.Network
import android.net.VpnService
import android.content.pm.ApplicationInfo
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.Os
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.FileDescriptor
import java.util.Collections
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.SynchronousQueue
import java.util.Locale

/** Receives actual SCM_RIGHTS descriptors, never process-local FD numbers. */
class XraySocketProtector private constructor(
    private val service: VpnService,
    private val protectFd: (Int) -> Boolean,
    private val numericPreview: NumericPreview?
) : Closeable {
    constructor(service: VpnService, protectFd: (Int) -> Boolean = service::protect) : this(service, protectFd, null)

    private class NumericPreview(val policy: NativePreviewSocketPolicy, val bind: (FileDescriptor) -> Unit)
    val socketName = "flutter-vless-protect-${UUID.randomUUID()}"
    private val server = LocalServerSocket(socketName)
    private val verified = CountDownLatch(1)
    @Volatile private var closed = false
    @Volatile private var allowedPhysicalDnsNames: Set<String>? = null
    private val clients = Collections.synchronizedSet(mutableSetOf<LocalSocket>())
    private val requests = ThreadPoolExecutor(0, 8, 10, TimeUnit.SECONDS, SynchronousQueue(),
        { task -> Thread(task, "xray-protection-request").apply { isDaemon = true } })
    private val worker = Thread({ serve() }, "xray-socket-protector").apply {
        isDaemon = true
        start()
    }

    fun awaitVerified(): Boolean = verified.await(3, TimeUnit.SECONDS) && !closed &&
        (numericPreview?.policy?.isCurrent() ?: true)

    /** Set before launching Xray: null for config mode, emptySet() for pinned proxy DNS. */
    fun allowPhysicalDnsForEndpointNames(names: Set<String>?) {
        allowedPhysicalDnsNames = names?.map { it.removeSuffix(".").lowercase(Locale.ROOT) }?.toSet()
    }

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
                    numericPreview?.let { mode ->
                        if (!NativePreviewSocketPolicy.accepts(command, descriptors.size)) {
                            socket.outputStream.write(0)
                            return@use
                        }
                        val acknowledged = ParcelFileDescriptor.dup(descriptors.single()).use { owned ->
                            mode.policy.protectBindAndAcknowledge(command, descriptors.size,
                                protect = { protectFd(owned.fd) },
                                bind = { mode.bind(owned.fileDescriptor) },
                                acknowledge = {
                                    socket.outputStream.write(1)
                                    if (command == 'S'.code) verified.countDown()
                                })
                        }
                        if (!acknowledged) socket.outputStream.write(0)
                        return@use
                    }
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
                            val permittedNames = allowedPhysicalDnsNames
                            if (!XrayPhysicalDns.isQueryAllowed(query, permittedNames)) return@use
                            val network = physicalNetwork() ?: return@use
                            val answer = XrayPhysicalDns.query(network, query, permittedNames)
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
    private fun physicalNetwork(): Network? = physicalNetwork(service)

    companion object {
        /**
         * Explicit development-only numeric DNS preview capability. The caller
         * supplies an already selected physical Network and a fresh generation.
         * This neither selects the default network nor completes handover.
         * Revocation denies new ACKs; the host must also close the native owner/
         * runtime to close Core sockets that were acknowledged before revocation.
         */
        internal fun forNumericPreview(service: VpnService, capturedNetwork: Network,
            generation: NativePreviewNetworkGeneration,
            protectFd: (Int) -> Boolean = service::protect): XraySocketProtector {
            require(service.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) {
                "Scoped native socket protection is development-only"
            }
            val manager = service.getSystemService(ConnectivityManager::class.java)
            val policy = NativePreviewSocketPolicy(generation) {
                val capabilities = manager.getNetworkCapabilities(capturedNetwork)
                capabilities != null && !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            }
            require(policy.isCurrent()) { "Captured physical network is unavailable" }
            return try { XraySocketProtector(service, protectFd, NumericPreview(policy, capturedNetwork::bindSocket)) }
            catch (error: Exception) { policy.revoke(); throw error }
        }

        /** Bootstrap only: never use a process/global resolver that could re-enter the VPN. */
        fun resolveBootstrapHostname(service: VpnService, hostname: String): List<String> {
            val network = physicalNetwork(service) ?: throw IllegalStateException("No physical network for proxy endpoint bootstrap")
            return network.getAllByName(hostname).mapNotNull { it.hostAddress }
        }

        private fun physicalNetwork(service: VpnService): Network? {
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
    }

    override fun close() {
        numericPreview?.policy?.revoke()
        closed = true
        runCatching { server.close() }
        synchronized(clients) { clients.forEach { runCatching { it.close() } } }
        requests.shutdownNow()
        worker.interrupt()
    }

    /** Bounded lifecycle observation for the opt-in launcher/tests, never a new admission. */
    internal fun awaitClosed(timeoutMillis: Long = 3000): Boolean {
        require(timeoutMillis in 0..3000)
        if (!closed) return false
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        val remaining = (deadline - System.nanoTime()).coerceAtLeast(0)
        if (!requests.awaitTermination(remaining, TimeUnit.NANOSECONDS)) return false
        val waitMillis = TimeUnit.NANOSECONDS.toMillis((deadline - System.nanoTime()).coerceAtLeast(0))
        if (waitMillis > 0) worker.join(waitMillis)
        return !worker.isAlive && clients.isEmpty()
    }
}
