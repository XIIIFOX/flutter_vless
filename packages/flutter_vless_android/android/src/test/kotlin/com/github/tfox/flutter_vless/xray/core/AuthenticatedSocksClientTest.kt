package com.github.tfox.flutter_vless.xray.core

import java.io.DataInputStream
import java.net.Authenticator
import java.net.ServerSocket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

class AuthenticatedSocksClientTest {
    private val credentials = LocalProxyCredentials("user", "correct-secret")

    @Test fun authenticatedApplicationBytesFlowWithoutGlobalAuthenticatorOrProxyHeader() {
        val global = Authenticator::class.java.getMethod("getDefault").invoke(null)
        withServer { port, serve ->
            val observed = serve { input, output ->
                val greeting = ByteArray(3).also(input::readFully)
                assertArrayEquals(byteArrayOf(5, 1, 2), greeting)
                output.write(byteArrayOf(5, 2))
                assertEquals(1, input.readUnsignedByte())
                val user = ByteArray(input.readUnsignedByte()).also(input::readFully).toString(Charsets.UTF_8)
                val pass = ByteArray(input.readUnsignedByte()).also(input::readFully).toString(Charsets.UTF_8)
                assertEquals("user", user); assertEquals("correct-secret", pass)
                output.write(byteArrayOf(1, 0))
                assertEquals(5, input.readUnsignedByte()); assertEquals(1, input.readUnsignedByte())
                assertEquals(0, input.readUnsignedByte()); assertEquals(3, input.readUnsignedByte())
                assertEquals("target.example", ByteArray(input.readUnsignedByte()).also(input::readFully).toString(Charsets.US_ASCII))
                assertEquals(80, input.readUnsignedShort())
                output.write(byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, 1, 1))
                val request = StringBuilder()
                while (!request.endsWith("\r\n\r\n")) request.append(input.readUnsignedByte().toChar())
                assertTrue(request.startsWith("HEAD /path?value=1 HTTP/1.1"))
                assertFalse(request.contains("correct-secret")); assertFalse(request.contains("Proxy-Authorization"))
                output.write("HTTP/1.1 204 No Content\r\n\r\n".toByteArray())
            }
            assertTrue(AuthenticatedSocksClient.measure(port, credentials, "http://target.example/path?value=1") >= 0)
            observed.get(5, TimeUnit.SECONDS)
        }
        assertSame(global, Authenticator::class.java.getMethod("getDefault").invoke(null))
    }

    @Test fun noauthSelectionAndWrongPasswordNeverFallbackOrSendConnect() {
        for (rejectMethod in listOf(true, false)) withServer { port, serve ->
            val observed = serve { input, output ->
                assertArrayEquals(byteArrayOf(5, 1, 2), ByteArray(3).also(input::readFully))
                if (rejectMethod) output.write(byteArrayOf(5, 0)) else {
                    output.write(byteArrayOf(5, 2))
                    input.readUnsignedByte()
                    input.readFully(ByteArray(input.readUnsignedByte()))
                    input.readFully(ByteArray(input.readUnsignedByte()))
                    output.write(byteArrayOf(1, 1))
                }
                assertEquals(-1, input.read()) // Connection closes; neither noauth nor CONNECT follows.
            }
            assertThrows(Exception::class.java) { AuthenticatedSocksClient.measure(port, credentials, "http://target.example/") }
            observed.get(5, TimeUnit.SECONDS)
        }
    }

    private fun withServer(block: (Int, (((DataInputStream, java.io.OutputStream) -> Unit) -> java.util.concurrent.Future<*>)) -> Unit) {
        ServerSocket(0).use { server ->
            val worker = Executors.newSingleThreadExecutor()
            try {
                block(server.localPort) { body -> worker.submit { server.accept().use { socket ->
                    socket.soTimeout = 3000
                    body(DataInputStream(socket.getInputStream()), socket.getOutputStream())
                } } }
            } finally { worker.shutdownNow() }
        }
    }
}
