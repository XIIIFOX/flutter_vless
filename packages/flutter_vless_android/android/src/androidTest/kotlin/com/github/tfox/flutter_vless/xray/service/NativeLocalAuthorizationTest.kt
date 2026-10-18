package com.github.tfox.flutter_vless.xray.service

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.github.tfox.flutter_vless.xray.core.AuthenticatedSocksClient
import com.github.tfox.flutter_vless.xray.core.LocalProxyCredentials
import com.github.tfox.flutter_vless.xray.core.XrayCoreManager
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.json.JSONObject
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class NativeLocalAuthorizationTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun isolatedDelayTransfersBytesWhileCallerApiAndMetricsPortsRemainOccupied() {
        val loopback = InetAddress.getByName("127.0.0.1")
        val ownedSockets = mutableListOf<ServerSocket>()
        val worker = Executors.newSingleThreadExecutor()
        val token = UUID.randomUUID().toString()
        val file = File(context.noBackupFilesDir, "test-delay-services-$token.json")
        val log = File(context.noBackupFilesDir, "test-delay-services-$token.log")
        var process: Process? = null
        try {
            fun listener() = ServerSocket(0, 1, loopback).also(ownedSockets::add)
            val callerApi = listener()
            val callerMetrics = listener()
            val http = listener().apply { soTimeout = 5000 }
            val source = JSONObject("""{
                "API":{"tag":"proxy","listen":"127.0.0.1:${callerApi.localPort}","services":["StatsService"]},
                "Metric\u017f":{"tag":"proxy","listen":"127.0.0.1:${callerMetrics.localPort}"},
                "outbounds":[{"tag":"proxy","protocol":"freedom"}]
            }""")
            val original = source.toString()
            // Reserve both adjacent temporary ports before releasing them to
            // this Core. Caller listeners remain bound throughout measurement.
            var requestedPort = 0
            repeat(20) {
                if (requestedPort == 0) ServerSocket(0, 1, loopback).use { socks ->
                    if (socks.localPort < 65535) runCatching {
                        ServerSocket(socks.localPort + 1, 1, loopback).use { requestedPort = socks.localPort }
                    }
                }
            }
            assertTrue("Temporary probe port pair is unavailable", requestedPort > 0)
            val secret = LocalProxyCredentials.generate()
            val (runtime, socksPort) = XrayCoreManager.buildDelayConfigJson(original, requestedPort,
                context.noBackupFilesDir, secret)
            assertEquals(original, source.toString())
            assertEquals(source.getJSONArray("outbounds").toString(), runtime.getJSONArray("outbounds").toString())
            assertFalse(runtime.has("Metric\u017f"))
            assertFalse(runtime.has("metrics"))
            assertFalse(runtime.getJSONObject("api").has("listen"))
            assertNotEquals("proxy", runtime.getJSONObject("api").getString("tag"))
            file.writeText(runtime.toString())
            val core = ProcessBuilder(File(context.applicationInfo.nativeLibraryDir, "libxray.so").absolutePath,
                "run", "-config", file.absolutePath).redirectErrorStream(true).redirectOutput(log).start()
            process = core
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            var ready = false
            while (!ready && core.isAlive && System.nanoTime() < deadline) {
                ready = runCatching {
                    Socket().use { it.connect(InetSocketAddress(loopback, socksPort), 100) }
                }.isSuccess
                if (!ready) Thread.sleep(50)
            }
            assertTrue("Temporary measurement Core must survive occupied caller service ports", core.isAlive)
            assertTrue("Temporary authenticated SOCKS input did not become ready", ready)
            val request = worker.submit<String> {
                http.accept().use { socket ->
                    socket.soTimeout = 3000
                    val input = socket.getInputStream()
                    val text = StringBuilder()
                    while (!text.endsWith("\r\n\r\n") && text.length < 16384) {
                        val next = input.read()
                        check(next >= 0) { "HTTP fixture request ended before headers" }
                        text.append(next.toChar())
                    }
                    check(text.endsWith("\r\n\r\n")) { "HTTP fixture request headers exceeded limit" }
                    socket.getOutputStream().write("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray())
                    socket.getOutputStream().flush()
                    text.toString()
                }
            }
            assertTrue(AuthenticatedSocksClient.measure(socksPort, secret,
                "http://127.0.0.1:${http.localPort}/delay-$token") >= 0)
            val received = request.get(5, TimeUnit.SECONDS)
            assertTrue(received.startsWith("HEAD /delay-$token HTTP/1.1\r\n"))
            assertFalse(received.contains(secret.password))
            assertFalse(received.contains("Proxy-Authorization", ignoreCase = true))
            assertTrue(callerApi.isBound && !callerApi.isClosed)
            assertTrue(callerMetrics.isBound && !callerMetrics.isClosed)
        } finally {
            val coreExited = process?.let { core -> runCatching {
                core.destroy()
                if (!core.waitFor(3, TimeUnit.SECONDS)) core.destroyForcibly()
                core.waitFor(3, TimeUnit.SECONDS) && !core.isAlive
            }.getOrDefault(false) } ?: true
            ownedSockets.forEach { runCatching { it.close() } }
            worker.shutdownNow()
            val workerExited = runCatching { worker.awaitTermination(3, TimeUnit.SECONDS) }.getOrDefault(false)
            file.delete(); log.delete()
            assertTrue("Temporary measurement Core did not exit", coreExited)
            assertTrue("HTTP fixture worker did not exit", workerExited)
            assertTrue(ownedSockets.all { it.isClosed })
            assertFalse(file.exists()); assertFalse(log.exists())
        }
    }

    @Test fun realXrayRequiresSessionAuthenticationAndTransfersApplicationBytes() {
        val port = ServerSocket(0).use { it.localPort }
        val secret = LocalProxyCredentials.generate()
        val config = XrayConfig(LOCAL_SOCKS5_PORT = port, LOCAL_API_PORT = port + 1,
            V2RAY_FULL_JSON_CONFIG = """{"Inbounds":[{"tag":"http","Protocol":"http","Listen":"127.0.0.1","Port":${port + 2},"Settings":{"accounts":[{"user":"imported-user","pass":"imported-password"}]}}],
              "outbounds":[{"tag":"proxy","protocol":"freedom"},{"tag":"fixture-blocked","protocol":"blackhole"}],
              "routing":{"rules":[{"type":"field","inboundTag":["flutter-vless-tun"],"outboundTag":"fixture-blocked"}]}}""")
        val json = XrayCoreManager.buildRuntimeConfigJson(config, context.noBackupFilesDir, secret)
        assertEquals("flutter-vless-tun-1", json.getJSONArray("inbounds").getJSONObject(1).getString("tag"))
        val file = File(context.noBackupFilesDir, "test-auth-${UUID.randomUUID()}.json")
        file.writeText(json.toString())
        val process = ProcessBuilder(File(context.applicationInfo.nativeLibraryDir, "libxray.so").absolutePath,
            "run", "-config", file.absolutePath).redirectErrorStream(true).start()
        try {
            repeat(30) {
                if (runCatching { Socket("127.0.0.1", port).close() }.isFailure) Thread.sleep(100)
            }
            assertTrue(process.isAlive)
            Socket("127.0.0.1", port + 2).use { socket ->
                socket.soTimeout = 2000
                socket.getOutputStream().write("GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: target.test\r\nConnection: close\r\n\r\n".toByteArray())
                val response = socket.getInputStream().bufferedReader().readText()
                assertTrue("Imported HTTP input must keep its explicit authentication", response.contains(" 407 "))
            }
            Socket("127.0.0.1", port).use { socket ->
                socket.soTimeout = 2000
                socket.getOutputStream().write(byteArrayOf(5, 1, 0))
                assertEquals(5, socket.getInputStream().read())
                assertEquals(255, socket.getInputStream().read())
            }
            assertThrows(Exception::class.java) {
                AuthenticatedSocksClient.connect(port, LocalProxyCredentials(secret.username, "wrong-password"), "127.0.0.1", 80)
            }
            ServerSocket(0).use { server ->
                val worker = Executors.newSingleThreadExecutor()
                try {
                    val request = worker.submit<String> { server.accept().use { socket ->
                        socket.soTimeout = 3000
                        val input = socket.getInputStream()
                        val text = StringBuilder()
                        while (!text.endsWith("\r\n\r\n")) text.append(input.read().toChar())
                        socket.getOutputStream().write("HTTP/1.1 204 No Content\r\n\r\n".toByteArray())
                        text.toString()
                    } }
                    assertTrue(AuthenticatedSocksClient.measure(port, secret, "http://127.0.0.1:${server.localPort}/") >= 0)
                    val text = request.get(5, TimeUnit.SECONDS)
                    assertFalse(text.contains(secret.password)); assertFalse(text.contains("Proxy-Authorization"))
                } finally { worker.shutdownNow() }
            }
        } finally {
            process.destroy(); process.waitFor(3, TimeUnit.SECONDS); file.delete()
        }
    }

    @Test fun authorizedProfileIsEncryptedAuthenticatedAndExplicitlyDisarmed() {
        val store = AuthorizedProfileStore(context)
        val secret = "remote-canary-${UUID.randomUUID()}"
        val profile = XrayConfig(V2RAY_FULL_JSON_CONFIG = "{\"secret\":\"$secret\"}", REMARK = "authorized")
        try {
            store.save(profile)
            val file = File(context.noBackupFilesDir, "flutter_vless_authorized_v1.bin")
            assertFalse(file.readBytes().toString(Charsets.ISO_8859_1).contains(secret))
            assertEquals(profile, store.load())
            val previous = file.readBytes()
            assertThrows(IllegalArgumentException::class.java) {
                store.save(profile.copy(V2RAY_FULL_JSON_CONFIG = "x".repeat(4 * 1024 * 1024)))
            }
            assertArrayEquals(previous, file.readBytes())
            assertEquals(profile, store.load())
            val bytes = file.readBytes(); bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte(); file.writeBytes(bytes)
            assertThrows(Exception::class.java) { store.load() }
            store.disarm()
            assertFalse(file.exists()); assertThrows(Exception::class.java) { store.load() }
        } finally { store.disarm() }
    }
}
