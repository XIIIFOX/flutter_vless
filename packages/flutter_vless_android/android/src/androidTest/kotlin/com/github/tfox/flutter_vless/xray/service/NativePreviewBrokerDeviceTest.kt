package com.github.tfox.flutter_vless.xray.service

import android.content.Context
import android.content.ContextWrapper
import android.content.pm.ApplicationInfo
import android.net.ConnectivityManager
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.system.StructTimeval
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.FileDescriptor
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Development broker boundary only; this does not start Core, establish TUN, or change the host. */
@RunWith(AndroidJUnit4::class)
class NativePreviewBrokerDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val manager = context.getSystemService(ConnectivityManager::class.java)

    private class PreparedService(context: Context) : VpnService() {
        init { attachBaseContext(context) }
    }

    private fun capturedNetwork(): Network = NativePreviewFixtureNetwork.capture(context)

    private fun exchange(broker: XraySocketProtector, command: Char, descriptors: Array<FileDescriptor>,
        allowClosed: Boolean = false): Int = try {
        LocalSocket().use { client ->
            client.connect(LocalSocketAddress(broker.socketName, LocalSocketAddress.Namespace.ABSTRACT))
            client.soTimeout = 2000
            client.setFileDescriptorsForSend(descriptors)
            client.outputStream.write(command.code)
            client.setFileDescriptorsForSend(null)
            client.inputStream.read()
        }
    } catch (error: Exception) {
        if (allowClosed) -1 else throw AssertionError("Broker exchange failed before a protocol reply", error)
    }

    private fun <T> withInetFd(type: Int = OsConstants.SOCK_DGRAM, body: (FileDescriptor) -> T): T {
        val fd = Os.socket(OsConstants.AF_INET, type, 0)
        try { return body(fd) } finally { Os.close(fd) }
    }

    private fun <T> withBroker(broker: XraySocketProtector, body: (XraySocketProtector) -> T): T {
        var primary: Throwable? = null
        try { return body(broker) } catch (error: Throwable) { primary = error; throw error }
        finally {
            val cleanup = runCatching {
                broker.close()
                assertTrue("Owned scoped broker workers did not terminate", broker.awaitClosed())
            }.exceptionOrNull()
            if (cleanup != null) {
                if (primary != null) primary.addSuppressed(cleanup) else throw cleanup
            }
        }
    }

    private fun connectNumeric(descriptor: FileDescriptor, address: InetAddress, port: Int) {
        val flags = Os.fcntlInt(descriptor, OsConstants.F_GETFL, 0)
        Os.fcntlInt(descriptor, OsConstants.F_SETFL, flags or OsConstants.O_NONBLOCK)
        try {
            try { Os.connect(descriptor, address, port) } catch (error: ErrnoException) {
                if (error.errno != OsConstants.EINPROGRESS) throw error
                val poll = StructPollfd().apply { fd = descriptor; events = OsConstants.POLLOUT.toShort() }
                assertEquals("Captured numeric TCP connection timed out", 1, Os.poll(arrayOf(poll), 3000))
                val peer = Os.getpeername(descriptor) as InetSocketAddress
                assertEquals("Captured numeric TCP peer address mismatch", address, peer.address)
                assertEquals("Captured numeric TCP peer port mismatch", port, peer.port)
            }
        } finally { Os.fcntlInt(descriptor, OsConstants.F_SETFL, flags) }
    }

    @Test fun realTransferredSocketsAreProtectedBoundAndTransferNumericHttpBytes() {
        assertNull("Disposable test package must already have VPN consent", VpnService.prepare(context))
        val network = capturedNetwork()
        NativePreviewFixtureNetwork.verify(context, network)
        val generation = NativePreviewNetworkGeneration()
        withBroker(XraySocketProtector.forNumericPreview(PreparedService(context), network, generation)) { broker ->
            withInetFd { handshake ->
                assertEquals("S must protect and bind the transferred preflight socket", 1, exchange(broker, 'S', arrayOf(handshake)))
                Os.fstat(handshake) // Closing broker-owned duplicates must not close the sender's FD.
            }
            assertTrue(broker.awaitVerified())
            withInetFd(OsConstants.SOCK_STREAM) { fd ->
                assertEquals("Q must protect and bind the transferred TCP socket", 1, exchange(broker, 'Q', arrayOf(fd)))
                try { connectNumeric(fd, InetAddress.getByAddress(byteArrayOf(10, 0, 2, 2)), 18083) }
                catch (error: Exception) { throw AssertionError("Actual S/Q numeric connection failed: ${NativePreviewFixtureNetwork.describe(context, network)}", error) }
                val source = (Os.getsockname(fd) as InetSocketAddress).address
                val addresses = requireNotNull(manager.getLinkProperties(network)).linkAddresses.map { it.address }
                assertTrue("The real socket source must belong to the captured physical Network", source in addresses)
                Os.setsockoptTimeval(fd, OsConstants.SOL_SOCKET, OsConstants.SO_RCVTIMEO, StructTimeval.fromMillis(3000))
                Os.setsockoptTimeval(fd, OsConstants.SOL_SOCKET, OsConstants.SO_SNDTIMEO, StructTimeval.fromMillis(3000))
                val request = "GET /native-preview-broker HTTP/1.1\r\nHost: 10.0.2.2\r\nConnection: close\r\n\r\n".toByteArray()
                var sent = 0
                while (sent < request.size) {
                    val count = Os.write(fd, request, sent, request.size - sent)
                    check(count > 0); sent += count
                }
                val response = StringBuilder()
                val buffer = ByteArray(1024)
                while (response.length < 8192 && !response.contains("flutter-vless-direct-bypass")) {
                    val count = Os.read(fd, buffer, 0, buffer.size)
                    if (count == 0) break
                    response.append(String(buffer, 0, count, Charsets.US_ASCII))
                }
                assertTrue("Real bound socket must receive the controlled HTTP marker", response.contains("flutter-vless-direct-bypass"))
            }
        }
        assertFalse(generation.isCurrent())
    }

    @Test fun scopedModeRejectsLegacyUnknownAndWrongDescriptorCountsBeforeProtection() {
        val calls = AtomicInteger()
        withBroker(XraySocketProtector.forNumericPreview(PreparedService(context), capturedNetwork(),
            NativePreviewNetworkGeneration(), protectFd = { calls.incrementAndGet(); true })) { broker ->
            withInetFd { first -> withInetFd { second ->
                for (command in listOf('H', 'P', 'D', '?')) {
                    assertEquals(0, exchange(broker, command, emptyArray()))
                    assertEquals(0, exchange(broker, command, arrayOf(first)))
                }
                for (command in listOf('S', 'Q')) {
                    assertEquals(0, exchange(broker, command, emptyArray()))
                    assertEquals(0, exchange(broker, command, arrayOf(first, second)))
                }
                Os.fstat(first); Os.fstat(second)
            } }
            assertEquals("Refused commands/counts must never reach protect or DNS", 0, calls.get())
        }
    }

    @Test fun protectionBindingAndRevokedInflightRequestsCannotAcknowledge() {
        val service = PreparedService(context)
        val network = capturedNetwork()
        withBroker(XraySocketProtector.forNumericPreview(service, network, NativePreviewNetworkGeneration(),
            protectFd = { false })) { broker ->
            withInetFd { fd ->
                assertEquals(0, exchange(broker, 'S', arrayOf(fd)))
                assertEquals(0, exchange(broker, 'Q', arrayOf(fd)))
            }
        }
        // A real pipe cannot be bound by Network.bindSocket(FileDescriptor).
        // The injected successful protect callback isolates that actual bind refusal.
        withBroker(XraySocketProtector.forNumericPreview(service, network, NativePreviewNetworkGeneration(),
            protectFd = { true })) { broker ->
            val pipe = ParcelFileDescriptor.createPipe()
            try { assertEquals(0, exchange(broker, 'Q', arrayOf(pipe[0].fileDescriptor))) }
            finally { pipe.forEach { it.close() } }
        }
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val generation = NativePreviewNetworkGeneration()
        val executor = Executors.newSingleThreadExecutor()
        val broker = XraySocketProtector.forNumericPreview(service, network, generation, protectFd = {
            entered.countDown()
            check(release.await(3, TimeUnit.SECONDS))
            true
        })
        try {
            withBroker(broker) {
                val request = executor.submit<Int> { withInetFd { fd -> exchange(broker, 'S', arrayOf(fd), allowClosed = true) } }
                assertTrue(entered.await(3, TimeUnit.SECONDS))
                generation.revoke()
                broker.close()
                release.countDown()
                assertNotEquals("Revoked in-flight descriptor must not get a positive ACK", 1, request.get(5, TimeUnit.SECONDS))
            }
        } finally {
            release.countDown()
            executor.shutdownNow()
            assertTrue("Owned FD sender did not terminate", executor.awaitTermination(3, TimeUnit.SECONDS))
        }
    }

    @Test fun legacyModeAndClosedScopedBrokerCannotGrantScopedCapability() {
        val network = capturedNetwork()
        val nonDebugContext = object : ContextWrapper(context) {
            override fun getApplicationInfo() = ApplicationInfo(context.applicationInfo).apply {
                flags = flags and ApplicationInfo.FLAG_DEBUGGABLE.inv()
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            XraySocketProtector.forNumericPreview(PreparedService(nonDebugContext), network, NativePreviewNetworkGeneration())
        }
        val revoked = NativePreviewNetworkGeneration().apply { revoke() }
        assertThrows(IllegalArgumentException::class.java) {
            XraySocketProtector.forNumericPreview(PreparedService(context), network, revoked)
        }
        val legacyCalls = AtomicInteger()
        withBroker(XraySocketProtector(VpnService(), protectFd = { legacyCalls.incrementAndGet(); true })) { legacy ->
            withInetFd { fd ->
                assertNotEquals(1, exchange(legacy, 'S', arrayOf(fd)))
                assertNotEquals(1, exchange(legacy, 'Q', arrayOf(fd)))
            }
            assertEquals(0, legacyCalls.get())
        }
        val generation = NativePreviewNetworkGeneration()
        withBroker(XraySocketProtector.forNumericPreview(PreparedService(context), network, generation)) { broker ->
            broker.close()
            assertTrue(broker.awaitClosed())
            withInetFd { fd ->
                assertNotEquals(1, exchange(broker, 'S', arrayOf(fd), allowClosed = true))
                assertNotEquals(1, exchange(broker, 'Q', arrayOf(fd), allowClosed = true))
            }
            assertFalse(generation.isCurrent())
        }
    }
}
