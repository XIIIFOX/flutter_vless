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
import java.io.File
import java.net.ServerSocket
import java.net.Socket
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class NativeLocalAuthorizationTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun realXrayRequiresSessionAuthenticationAndTransfersApplicationBytes() {
        val port = ServerSocket(0).use { it.localPort }
        val secret = LocalProxyCredentials.generate()
        val config = XrayConfig(LOCAL_SOCKS5_PORT = port, LOCAL_API_PORT = port + 1,
            V2RAY_FULL_JSON_CONFIG = """{"Inbounds":[{"tag":"http","Protocol":"http","Listen":"127.0.0.1","Port":${port + 2},"Settings":{}}],"outbounds":[{"tag":"proxy","protocol":"freedom"}]}""")
        val json = XrayCoreManager.buildRuntimeConfigJson(config, context.noBackupFilesDir, secret)
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
                assertTrue("Mixed-case HTTP input must demand local credentials", response.contains(" 407 "))
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
