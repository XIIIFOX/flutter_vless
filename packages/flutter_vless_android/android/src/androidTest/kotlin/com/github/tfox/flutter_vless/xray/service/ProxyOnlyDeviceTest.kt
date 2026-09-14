package com.github.tfox.flutter_vless.xray.service

import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import android.os.ResultReceiver
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.github.tfox.flutter_vless.xray.core.XrayCoreManager
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.Closeable
import java.io.File
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Real service + packaged Xray. Every origin is local; no VPN consent or host changes. */
@RunWith(AndroidJUnit4::class)
class ProxyOnlyDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private fun captured(): Boolean {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        return manager.getNetworkCapabilities(manager.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }
    private fun stop() {
        context.startService(Intent(context, XrayVPNService::class.java)
            .putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE))
        Thread.sleep(500)
    }
    private class Origin(private val marker: String) : Closeable {
        private val server = ServerSocket(0, 10, java.net.InetAddress.getByName("127.0.0.1"))
        private val worker = Executors.newSingleThreadExecutor()
        val port = server.localPort
        init {
            worker.submit {
                while (!server.isClosed) {
                    try {
                        server.accept().use { socket ->
                            socket.soTimeout = 3000
                            val input = socket.getInputStream().bufferedReader()
                            while (true) { val line = input.readLine(); if (line == null || line.isEmpty()) break }
                            socket.getOutputStream().write(("HTTP/1.1 200 OK\r\nContent-Length: ${marker.length}\r\nConnection: close\r\n\r\n" + marker).toByteArray())
                        }
                    } catch (_: java.io.IOException) { /* Closed listener or a timed-out control. */ }
                }
            }
        }
        override fun close() { server.close(); worker.shutdownNow() }
    }
    private fun request(port: Int, host: String, http: Boolean = false): String {
        val socket = if (http) Socket() else Socket(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port)))
        return socket.use {
            it.soTimeout = 4000
            it.connect(if (http) InetSocketAddress("127.0.0.1", port) else InetSocketAddress.createUnresolved(host, 80), 4000)
            val target = if (http) "http://$host/" else "/"
            it.getOutputStream().write("GET $target HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n".toByteArray())
            val response = it.getInputStream().bufferedReader().readText()
            assertTrue(response.startsWith("HTTP/1.1 200"))
            response.substringAfter("\r\n\r\n")
        }
    }
    @Test fun socksHttpAndSecondaryDirectListenerRouteIndependentlyAcrossRestarts() {
        val executable = File(context.applicationInfo.nativeLibraryDir, "libxray.so").absolutePath
        val version = ProcessBuilder(executable, "version").redirectErrorStream(true).start()
        assertTrue(version.inputStream.bufferedReader().readText().contains("26.9.9"))
        assertTrue(version.waitFor(5, TimeUnit.SECONDS)); assertEquals(0, version.exitValue())
        val reserved = List(4) { ServerSocket(0) }
        val ports = reserved.map { it.localPort }; reserved.forEach { it.close() }
        val (socks, directSocks, http, api) = ports
        Origin("DIRECT").use { direct -> Origin("PROXY").use { proxy ->
            try {
                stop(); assertFalse("Use a disposable emulator without an active VPN", captured())
                repeat(2) { generation ->
                    val rule = if (generation == 0) "domain:ru" else "domain:myip.com"
                    val json = """{"inbounds":[
                        {"tag":"socks-in","listen":"127.0.0.1","protocol":"socks","port":$socks,"settings":{"auth":"noauth","udp":true}},
                        {"tag":"socks-direct","listen":"127.0.0.1","protocol":"socks","port":$directSocks,"settings":{"auth":"noauth"}},
                        {"tag":"http-in","listen":"127.0.0.1","protocol":"http","port":$http}],
                        "outbounds":[{"tag":"proxy","protocol":"freedom","settings":{"redirect":"127.0.0.1:${proxy.port}"}},
                            {"tag":"direct","protocol":"freedom","settings":{"redirect":"127.0.0.1:${direct.port}"}}],
                        "routing":{"domainStrategy":"AsIs","rules":[
                            {"type":"field","inboundTag":["socks-direct"],"outboundTag":"direct"},
                            {"type":"field","domain":["$rule"],"outboundTag":"direct"}]}}"""
                    val accepted = CountDownLatch(1)
                    val result = AtomicInteger(-1)
                    val receiver = object : ResultReceiver(null) {
                        override fun onReceiveResult(code: Int, data: Bundle?) { result.set(code); accepted.countDown() }
                    }
                    context.startForegroundService(Intent(context, XrayVPNService::class.java)
                        .putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE)
                        .putExtra("PROXY_ONLY", true).putExtra("start_receiver", receiver)
                        .putExtra("V2RAY_CONFIG", XrayConfig(REMARK = "Proxy-only regression", V2RAY_FULL_JSON_CONFIG = json,
                            LOCAL_SOCKS5_PORT = socks, LOCAL_HTTP_PORT = http, LOCAL_API_PORT = api)))
                    assertTrue(accepted.await(20, TimeUnit.SECONDS)); assertEquals(0, result.get())
                    // START acknowledges validation; CONNECTED reports forwarding readiness.
                    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
                    while (!XrayCoreManager.getProviderDebugSnapshot(context).lineSequence().any { it == "CONNECTED" } && System.nanoTime() < deadline) Thread.sleep(100)
                    assertTrue(XrayCoreManager.getProviderDebugSnapshot(context).lineSequence().any { it == "CONNECTED" })
                    assertFalse("Proxy-only must not capture the system network", captured())
                    for (host in listOf("2ip.ru", "myip.com")) {
                        val expected = if ((host == "2ip.ru") == (generation == 0)) "DIRECT" else "PROXY"
                        assertEquals(expected, request(socks, host))
                        assertEquals(expected, request(http, host, http = true))
                        assertEquals("DIRECT", request(directSocks, host))
                    }
                    stop()
                    for (port in ports) assertTrue("Stop closes owned listeners", runCatching { Socket("127.0.0.1", port).close() }.isFailure)
                    assertFalse(captured())
                }
            } finally { stop() }
        } }
    }
}
