package com.github.tfox.flutter_vless.xray.core

import java.io.DataInputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.ConnectException
import java.net.Socket
import java.net.URI
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** RFC 1929 authentication belongs to each socket, never to a process-wide Authenticator. */
internal object AuthenticatedSocksClient {
    fun connect(port: Int, credentials: LocalProxyCredentials?, host: String, targetPort: Int,
        readiness: StartupReadiness? = null): Socket {
        val socket = Socket()
        try {
            readiness?.adopt(socket)
            try { socket.connect(InetSocketAddress("127.0.0.1", port), readiness?.remainingMillis() ?: 5000) }
            catch (error: Exception) {
                if (readiness == null) throw error
                readiness.check()
                var cause: Throwable? = if (error is ConnectException) error else null
                var errno: Int? = null
                repeat(8) {
                    if (cause is android.system.ErrnoException) errno = (cause as android.system.ErrnoException).errno
                    cause = cause?.cause
                }
                throw ReadinessFailure(ReadinessStage.LOCAL_CONNECT, errno)
            }
            readiness?.check()
            socket.soTimeout = readiness?.remainingMillis() ?: 5000
            val input = DataInputStream(socket.getInputStream())
            val output = socket.getOutputStream()
            fun bytes(size: Int, stage: ReadinessStage): ByteArray = ByteArray(size).also {
                if (readiness == null) input.readFully(it) else readiness.readFully(socket, input, it, stage)
            }
            fun byte(stage: ReadinessStage): Int = bytes(1, stage)[0].toInt() and 255
            fun write(bytes: ByteArray, stage: ReadinessStage) {
                readiness?.check()
                try { output.write(bytes) } catch (error: Exception) {
                    if (readiness == null) throw error
                    readiness.check(); throw ReadinessFailure(stage)
                }
                readiness?.check()
            }
            fun reject(stage: ReadinessStage, message: String): Nothing {
                if (readiness != null) throw ReadinessFailure(stage)
                throw IOException(message)
            }
            val method = if (credentials == null) 0 else 2
            write(byteArrayOf(5, 1, method.toByte()), ReadinessStage.SOCKS_METHOD)
            if (byte(ReadinessStage.SOCKS_METHOD) != 5 || byte(ReadinessStage.SOCKS_METHOD) != method)
                reject(ReadinessStage.SOCKS_METHOD, "SOCKS authentication required")
            if (credentials != null) {
                val user = credentials.username.toByteArray(Charsets.UTF_8)
                val pass = credentials.password.toByteArray(Charsets.UTF_8)
                write(byteArrayOf(1, user.size.toByte()) + user + byteArrayOf(pass.size.toByte()) + pass, ReadinessStage.SOCKS_AUTH)
                if (byte(ReadinessStage.SOCKS_AUTH) != 1 || byte(ReadinessStage.SOCKS_AUTH) != 0)
                    reject(ReadinessStage.SOCKS_AUTH, "SOCKS authentication rejected")
            }
            val name = host.toByteArray(Charsets.US_ASCII)
            require(name.size in 1..255 && targetPort in 1..65535) { "Invalid probe target" }
            write(byteArrayOf(5, 1, 0, 3, name.size.toByte()) + name + byteArrayOf((targetPort shr 8).toByte(), targetPort.toByte()), ReadinessStage.SOCKS_REPLY)
            if (byte(ReadinessStage.SOCKS_REPLY) != 5 || byte(ReadinessStage.SOCKS_REPLY) != 0)
                reject(ReadinessStage.SOCKS_REPLY, "SOCKS connect rejected")
            if (byte(ReadinessStage.SOCKS_REPLY) != 0) reject(ReadinessStage.SOCKS_REPLY, "Invalid SOCKS reply")
            val addressLength = when (byte(ReadinessStage.SOCKS_REPLY)) {
                1 -> 4; 3 -> byte(ReadinessStage.SOCKS_REPLY); 4 -> 16
                else -> reject(ReadinessStage.SOCKS_REPLY, "Invalid SOCKS address")
            }
            bytes(addressLength + 2, ReadinessStage.SOCKS_REPLY)
            readiness?.check()
            return socket
        } catch (error: Exception) {
            try { socket.close(); readiness?.release(socket) } catch (cleanup: Exception) { error.addSuppressed(cleanup) }
            throw error
        }
    }

    /** An HTTP response proves authenticated, bidirectional application bytes, not only CONNECT. */
    fun measure(port: Int, credentials: LocalProxyCredentials?, url: String): Long {
        val uri = URI(url)
        require(uri.scheme in setOf("http", "https") && uri.host != null && uri.rawUserInfo == null) { "Invalid probe URL" }
        require(!url.contains('\r') && !url.contains('\n')) { "Invalid probe URL" }
        val secure = uri.scheme == "https"
        val targetPort = if (uri.port >= 0) uri.port else if (secure) 443 else 80
        val started = System.nanoTime()
        connect(port, credentials, uri.host, targetPort).use { raw ->
            val transport = if (secure) {
                (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(raw, uri.host, targetPort, true).let {
                    it as SSLSocket
                    it.sslParameters = it.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                    it.startHandshake()
                    it
                }
            } else raw
            transport.use { socket ->
                val path = (uri.rawPath.takeUnless { it.isNullOrEmpty() } ?: "/") + (uri.rawQuery?.let { "?$it" } ?: "")
                val host = if (targetPort == if (secure) 443 else 80) uri.host else "${uri.host}:$targetPort"
                socket.getOutputStream().write("HEAD $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
                val input = socket.getInputStream()
                val line = StringBuilder()
                while (line.length < 1024) { val value = input.read(); if (value < 0) throw IOException("Empty probe response"); if (value == 10) break; line.append(value.toChar()) }
                require(line.toString().trimEnd('\r').matches(Regex("HTTP/1\\.[01] [1-5][0-9]{2}.*"))) { "Invalid probe response" }
            }
        }
        return (System.nanoTime() - started) / 1_000_000
    }
}
