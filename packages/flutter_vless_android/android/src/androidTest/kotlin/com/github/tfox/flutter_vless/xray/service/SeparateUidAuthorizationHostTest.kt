package com.github.tfox.flutter_vless.xray.service

import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.github.tfox.flutter_vless.xray.core.LocalProxyCredentials
import com.github.tfox.flutter_vless.xray.core.XrayCoreManager
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.net.ServerSocket
import java.net.Socket
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** Disposable real native runtime for an independently installed adversary APK.
 * No live VPN profile or runtime credentials are read by this fixture. */
@RunWith(AndroidJUnit4::class)
class SeparateUidAuthorizationHostTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun separateApplicationUidCannotBypassManagedProxyAuthorizationOrFdBroker() {
        org.junit.Assume.assumeTrue("Run through tool/test_android_separate_uid.py", InstrumentationRegistry.getArguments().getString("separateUidHarness") == "true")
        val ready = File(context.filesDir, "separate-uid-ready.json")
        val done = File(context.filesDir, "separate-uid-done.json")
        ready.delete(); done.delete()
        val socks = ServerSocket(0).use { it.localPort }
        val http = ServerSocket(0).use { it.localPort }
        val api = ServerSocket(0).use { it.localPort }
        val credentials = LocalProxyCredentials("boundary-test-user", "boundary-test-password-never-production")
        val config = XrayConfig(LOCAL_SOCKS5_PORT = socks, LOCAL_HTTP_PORT = http, LOCAL_API_PORT = api,
            V2RAY_FULL_JSON_CONFIG = """{"inbounds":[{"tag":"http","protocol":"http","listen":"127.0.0.1","port":$http,"settings":{}}],"outbounds":[{"tag":"proxy","protocol":"freedom"}]}""")
        val nativeConfig = File(context.noBackupFilesDir, "separate-uid-${UUID.randomUUID()}.json")
        nativeConfig.writeText(XrayCoreManager.buildRuntimeConfigJson(config, context.noBackupFilesDir, credentials).toString())
        val native = ProcessBuilder(File(context.applicationInfo.nativeLibraryDir, "libxray.so").absolutePath,
            "run", "-config", nativeConfig.absolutePath).redirectErrorStream(true).start()
        val calls = AtomicInteger()
        val requests = AtomicInteger()
        val leakedHeader = AtomicBoolean(false)
        val executor = Executors.newSingleThreadExecutor()
        val origin = ServerSocket(0)
        try {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while (runCatching { Socket("127.0.0.1", socks).close() }.isFailure && System.nanoTime() < deadline) Thread.sleep(100)
            assertTrue("Native positive-control runtime is not alive", native.isAlive)
            executor.submit {
                while (!origin.isClosed) {
                    try {
                        origin.accept().use { socket ->
                            socket.soTimeout = 3000
                            val request = StringBuilder()
                            while (!request.endsWith("\r\n\r\n") && request.length < 16384) {
                                val value = socket.getInputStream().read(); if (value < 0) break; request.append(value.toChar())
                            }
                            requests.incrementAndGet()
                            if (request.contains("Proxy-Authorization", ignoreCase = true) || request.contains(credentials.password)) leakedHeader.set(true)
                            val marker = "flutter-vless-separate-uid-control"
                            socket.getOutputStream().write("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: ${marker.length}\r\n\r\n$marker".toByteArray())
                        }
                    } catch (_: Exception) { if (origin.isClosed) break }
                }
            }
            XraySocketProtector(VpnService(), protectFd = { calls.incrementAndGet(); true }).use { broker ->
                val pipe = ParcelFileDescriptor.createPipe()
                try {
                    LocalSocket().use { socket ->
                        socket.connect(LocalSocketAddress(broker.socketName, LocalSocketAddress.Namespace.ABSTRACT))
                        socket.soTimeout = 2000
                        socket.setFileDescriptorsForSend(arrayOf(pipe[0].fileDescriptor))
                        socket.outputStream.write('H'.code)
                        assertEquals("Same-UID FD control must be positively acknowledged", 1, socket.inputStream.read())
                    }
                } finally { pipe.forEach { it.close() } }
                assertTrue(broker.awaitVerified())
                assertEquals(1, calls.get())
                ready.writeText(JSONObject().put("hostUid", android.os.Process.myUid()).put("socksPort", socks)
                    .put("httpPort", http).put("originPort", origin.localPort).put("broker", broker.socketName).toString())
                val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(90)
                while (!done.exists() && System.nanoTime() < until) { assertTrue(native.isAlive); Thread.sleep(100) }
                assertTrue("Separate-UID runner did not provide its result", done.exists())
                val result = JSONObject(done.readText())
                assertTrue("Adversary probes did not all pass", result.getBoolean("passed"))
                assertNotEquals(android.os.Process.myUid(), result.getInt("adversary_uid"))
                assertEquals("Foreign UID reached the FD protection callback", 1, calls.get())
                assertEquals("An unauthorized request reached the origin", 2, requests.get())
                assertFalse("Local HTTP authorization escaped to the origin", leakedHeader.get())
            }
        } finally {
            origin.close(); executor.shutdownNow(); native.destroy(); native.waitFor(3, TimeUnit.SECONDS)
            if (native.isAlive) native.destroyForcibly()
            nativeConfig.delete(); ready.delete(); done.delete()
        }
    }
}
