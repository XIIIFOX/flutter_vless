package com.github.tfox.flutter_vless.xray.core

import java.io.DataInputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** RFC 1929 authentication belongs to each socket, never to a process-wide Authenticator. */
internal object AuthenticatedSocksClient {
    fun connect(port: Int, credentials: LocalProxyCredentials?, host: String, targetPort: Int): Socket {
        val socket = Socket()
        try {
            socket.connect(InetSocketAddress("127.0.0.1", port), 5000)
            socket.soTimeout = 5000
            val input = DataInputStream(socket.getInputStream())
            val output = socket.getOutputStream()
            val method = if (credentials == null) 0 else 2
            output.write(byteArrayOf(5, 1, method.toByte()))
            if (input.readUnsignedByte() != 5 || input.readUnsignedByte() != method) throw IOException("SOCKS authentication required")
            if (credentials != null) {
                val user = credentials.username.toByteArray(Charsets.UTF_8)
                val pass = credentials.password.toByteArray(Charsets.UTF_8)
                output.write(byteArrayOf(1, user.size.toByte()) + user + byteArrayOf(pass.size.toByte()) + pass)
                if (input.readUnsignedByte() != 1 || input.readUnsignedByte() != 0) throw IOException("SOCKS authentication rejected")
            }
            val name = host.toByteArray(Charsets.US_ASCII)
            require(name.size in 1..255 && targetPort in 1..65535) { "Invalid probe target" }
            output.write(byteArrayOf(5, 1, 0, 3, name.size.toByte()) + name + byteArrayOf((targetPort shr 8).toByte(), targetPort.toByte()))
            if (input.readUnsignedByte() != 5 || input.readUnsignedByte() != 0) throw IOException("SOCKS connect rejected")
            if (input.readUnsignedByte() != 0) throw IOException("Invalid SOCKS reply")
            val addressLength = when (input.readUnsignedByte()) { 1 -> 4; 3 -> input.readUnsignedByte(); 4 -> 16; else -> throw IOException("Invalid SOCKS address") }
            input.readFully(ByteArray(addressLength + 2))
            return socket
        } catch (error: Exception) { socket.close(); throw error }
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
