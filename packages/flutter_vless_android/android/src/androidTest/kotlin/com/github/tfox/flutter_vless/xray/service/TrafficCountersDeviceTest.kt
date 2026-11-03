package com.github.tfox.flutter_vless.xray.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Bundle
import android.os.ResultReceiver
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import com.github.tfox.flutter_vless.xray.core.AuthenticatedSocksClient
import com.github.tfox.flutter_vless.xray.core.LocalProxyCredentials
import com.github.tfox.flutter_vless.xray.core.StartupReadiness
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.DataInputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** Actual public service broadcasts, packaged Core and verified local payload.
 * These counter controls use the selected Core input in both modes; they do
 * not claim that the proxy-only socket client traverses an Android TUN.
 */
@RunWith(AndroidJUnit4::class)
@SdkSuppress(minSdkVersion = 26)
class TrafficCountersDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private data class Sample(val receivedAt: Long, val seconds: Long, val upSpeed: Long,
        val downSpeed: Long, val upload: Long, val download: Long)

    private data class Input(val port: Int, val credentials: LocalProxyCredentials?)

    private fun captured(): Boolean = context.getSystemService(ConnectivityManager::class.java)
        .let { it.getNetworkCapabilities(it.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true }

    private fun command(start: Boolean, profile: XrayConfig? = null) {
        val completed = CountDownLatch(1)
        val result = AtomicInteger(-1)
        val receiver = object : ResultReceiver(null) {
            override fun onReceiveResult(code: Int, data: Bundle?) {
                result.set(code); completed.countDown()
            }
        }
        val intent = Intent(context, XrayVPNService::class.java)
            .putExtra("COMMAND", if (start) AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE else AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE)
            .putExtra(if (start) "start_receiver" else "stop_receiver", receiver)
        if (start) {
            intent.putExtra("V2RAY_CONFIG", requireNotNull(profile)).putExtra("PROXY_ONLY", profile.PROXY_ONLY)
            context.startForegroundService(intent)
        } else context.startService(intent)
        assertTrue("Native ${if (start) "Start" else "Stop"} acknowledgement", completed.await(10, TimeUnit.SECONDS))
        assertEquals("Native ${if (start) "Start" else "Stop"} accepted", 0, result.get())
    }

    private fun stopped(ports: Set<Int>) {
        command(false)
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        fun ownedInputsRemain() = context.noBackupFilesDir.listFiles().orEmpty().any {
            it.name.startsWith("xray-") || it.name.startsWith("validate-") || it.name.startsWith("tun-") || it.name.startsWith("fd-")
        }
        while ((captured() || ownedInputsRemain()) && System.nanoTime() < end) Thread.sleep(25)
        assertFalse("Stop releases VPN capture", captured())
        assertFalse("Stop removes its runtime inputs and descriptor socket", ownedInputsRemain())
        for (port in ports) assertTrue("Stop closes the owned input/API listener", runCatching {
            Socket().use { it.connect(java.net.InetSocketAddress("127.0.0.1", port), 250) }
        }.isFailure)
        InstrumentationRegistry.getInstrumentation().waitForIdleSync()
    }

    private fun runtime(): JSONObject = JSONObject(context.noBackupFilesDir.listFiles().orEmpty().single {
        it.name.startsWith("xray-") && it.name.endsWith(".json") && !it.name.endsWith(".spec.json")
    }.readText())

    private fun selectedInput(document: JSONObject): Input {
        val inputs = document.getJSONArray("inbounds")
        val socks = (0 until inputs.length()).map(inputs::getJSONObject).single { it.optString("protocol") == "socks" }
        val settings = socks.getJSONObject("settings")
        val secret = if (settings.optString("auth") == "password") {
            val account = settings.getJSONArray("accounts").getJSONObject(0)
            LocalProxyCredentials(account.getString("user"), account.getString("pass"))
        } else null
        return Input(socks.getInt("port"), secret)
    }

    private fun header(input: InputStream): List<String> {
        val bytes = ByteArrayOutputStream()
        var tail = 0
        while (bytes.size() < 4096 && tail != 0x0d0a0d0a) {
            val value = input.read()
            check(value >= 0) { "Incomplete controlled HTTP header" }
            bytes.write(value); tail = (tail shl 8) or value
        }
        check(tail == 0x0d0a0d0a) { "Oversized controlled HTTP header" }
        return bytes.toString("US-ASCII").split("\r\n")
    }

    private fun contentLength(lines: List<String>): Int = lines
        .filter { it.startsWith("Content-Length:", ignoreCase = true) }
        .single().substringAfter(':').trim().toInt()

    private inner class Origin : Closeable {
        private val server = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1")).apply { soTimeout = 1000 }
        private val worker = Executors.newSingleThreadExecutor()
        private val closing = AtomicBoolean()
        private val active = AtomicReference<Socket?>()
        private val failure = AtomicReference<Throwable?>()
        val received = AtomicLong()
        val sent = AtomicLong()
        val port = server.localPort
        val upload = ByteArray(8 * 1024) { (it % 251).toByte() }
        val download = ByteArray(128 * 1024) { ((it * 3) % 251).toByte() }

        init {
            worker.submit {
                try {
                    while (!closing.get()) {
                        val socket = try { server.accept() } catch (_: SocketTimeoutException) { continue }
                        active.set(socket)
                        try {
                            socket.use {
                                if (closing.get()) return@submit
                                it.soTimeout = 3000
                                val input = DataInputStream(it.getInputStream())
                                val lines = header(input)
                                check(lines.first() == "POST /counters HTTP/1.1")
                                check(contentLength(lines) == upload.size)
                                val body = ByteArray(upload.size); input.readFully(body)
                                check(body.contentEquals(upload)) { "Controlled upload payload changed" }
                                received.addAndGet(body.size.toLong())
                                val output = it.getOutputStream()
                                output.write("HTTP/1.1 200 OK\r\nContent-Length: ${download.size}\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
                                for (offset in download.indices step 4096) {
                                    output.write(download, offset, minOf(4096, download.size - offset))
                                    Thread.sleep(4)
                                }
                                output.flush(); sent.addAndGet(download.size.toLong())
                            }
                        } finally { active.compareAndSet(socket, null) }
                    }
                } catch (error: Throwable) {
                    if (!closing.get()) failure.compareAndSet(null, error)
                }
            }
        }

        fun transfer(input: Input, deadline: Long) {
            check(System.nanoTime() < deadline) { "Controlled transfer deadline" }
            val remaining = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime()).coerceIn(1, 3000)
            StartupReadiness(timeoutMillis = remaining, isCurrent = { System.nanoTime() < deadline }).use { phase ->
                AuthenticatedSocksClient.connect(input.port, input.credentials, "127.0.0.1", port, phase).use { socket ->
                    socket.soTimeout = phase.remainingMillis()
                    val output = socket.getOutputStream()
                    output.write("POST /counters HTTP/1.1\r\nHost: traffic-counter.invalid\r\nContent-Length: ${upload.size}\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
                    for (offset in upload.indices step 4096) {
                        phase.check()
                        output.write(upload, offset, minOf(4096, upload.size - offset)); Thread.sleep(4)
                    }
                    output.flush()
                    val response = DataInputStream(socket.getInputStream())
                    val lines = header(response)
                    assertTrue("Controlled HTTP response", lines.first().startsWith("HTTP/1.1 200 "))
                    assertEquals(download.size, contentLength(lines))
                    val body = ByteArray(download.size); response.readFully(body)
                    phase.check()
                    assertArrayEquals("Controlled download payload", download, body)
                }
            }
            failure.get()?.let { throw AssertionError("Controlled origin failed", it) }
        }

        override fun close() {
            closing.set(true); server.close(); active.getAndSet(null)?.close(); worker.shutdownNow()
            check(worker.awaitTermination(3, TimeUnit.SECONDS)) { "Controlled origin worker did not terminate" }
            failure.get()?.let { throw AssertionError("Controlled origin failed", it) }
        }
    }

    private fun exercise(proxyOnly: Boolean, nativeRouting: Boolean = false) {
        // Includes the initial Stop and leaves a separate bounded cleanup budget.
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(38)
        stopped(emptySet())
        if (!proxyOnly) assertNull("Disposable test-app VPN consent is required", android.net.VpnService.prepare(context))
        val updates = LinkedBlockingQueue<Sample>(64)
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                if (intent?.action != AppConfigs.V2RAY_CONNECTION_INFO) return
                @Suppress("DEPRECATION")
                val state = intent.getSerializableExtra("STATE") as? AppConfigs.V2RAY_STATES
                if (state == AppConfigs.V2RAY_STATES.V2RAY_CONNECTED) updates.offer(Sample(System.nanoTime(),
                    intent.getStringExtra("DURATION")?.toLongOrNull() ?: -1,
                    intent.getLongExtra("UPLOAD_SPEED", -1), intent.getLongExtra("DOWNLOAD_SPEED", -1),
                    intent.getLongExtra("UPLOAD_TRAFFIC", -1), intent.getLongExtra("DOWNLOAD_TRAFFIC", -1)))
            }
        }
        val filter = IntentFilter(AppConfigs.V2RAY_CONNECTION_INFO)
        if (Build.VERSION.SDK_INT >= 33) context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        else @Suppress("DEPRECATION") context.registerReceiver(receiver, filter)
        var origin: Origin? = null
        var primary: Throwable? = null
        val ownedPorts = mutableSetOf<Int>()
        fun next(deadline: Long): Sample = updates.poll((deadline - System.nanoTime()).coerceAtLeast(1), TimeUnit.NANOSECONDS)
            ?.also { assertTrue("Complete public statistics fields", listOf(it.seconds, it.upSpeed, it.downSpeed, it.upload, it.download).all { value -> value >= 0 }) }
            ?: throw AssertionError("A fresh public statistics broadcast did not arrive")
        try {
            val server = Origin().also { origin = it }
            val source = JSONObject("""{"inbounds":[],"stats":{},
                "policy":{"levels":{"8":{"bufferSize":3,"handshake":3}},"system":{}},
                "outbounds":[{"tag":"blocked","protocol":"blackhole"},{"tag":"traffic-route","protocol":"freedom"}],
                "routing":{"rules":[
                    {"type":"field","domain":["full:traffic-counter.invalid"],"port":"${server.port}","outboundTag":"traffic-route"},
                    {"type":"field","ip":["127.0.0.1"],"port":"${server.port}","outboundTag":"traffic-route"}]}}""")
            val original = source.toString()
            command(true, XrayConfig(REMARK = "Missing-statistics defaults regression", V2RAY_FULL_JSON_CONFIG = original,
                PROXY_ONLY = proxyOnly, ENABLE_TRAFFIC_STATICS = true,
                VPN_ROUTING_SELECTION_JSON = if (nativeRouting) """{"defaultOutboundTag":"blocked"}""" else null,
                PLUGIN_OPTIONS_JSON = """{"reconnect":{"enabled":false}}"""))
            val before = next(minOf(deadline, System.nanoTime() + TimeUnit.SECONDS.toNanos(12)))
            assertEquals("Capture agrees with the selected mode", !proxyOnly, captured())
            val document = runtime()
            val actualPolicy = document.getJSONObject("policy")
            assertEquals(source.getJSONObject("policy").getJSONObject("levels").toString(), actualPolicy.getJSONObject("levels").toString())
            assertTrue(actualPolicy.getJSONObject("system").getBoolean("statsInboundUplink"))
            assertTrue(actualPolicy.getJSONObject("system").getBoolean("statsInboundDownlink"))
            val input = selectedInput(document)
            ownedPorts += input.port
            ownedPorts += NativeOwnedStatsReader.ownedPort(document)
            val trafficStarted = System.nanoTime()
            val rounds = 8
            repeat(rounds) { server.transfer(input, deadline); Thread.sleep(150) }
            var after = before
            var uploadSpeed = false
            var downloadSpeed = false
            val sampleDeadline = minOf(deadline, System.nanoTime() + TimeUnit.SECONDS.toNanos(8))
            while (System.nanoTime() < sampleDeadline) {
                val sample = next(sampleDeadline)
                if (sample.receivedAt < trafficStarted || sample.seconds <= before.seconds) continue
                after = sample
                uploadSpeed = uploadSpeed || (sample.upSpeed > 0 && sample.upload > before.upload)
                downloadSpeed = downloadSpeed || (sample.downSpeed > 0 && sample.download > before.download)
                if (after.upload - before.upload >= rounds * server.upload.size &&
                    after.download - before.download >= rounds * server.download.size && uploadSpeed && downloadSpeed) break
            }
            assertEquals(rounds * server.upload.size.toLong(), server.received.get())
            assertEquals(rounds * server.download.size.toLong(), server.sent.get())
            assertTrue("Public uploaded bytes include the verified payload", after.upload - before.upload >= rounds * server.upload.size)
            assertTrue("Public downloaded bytes include the verified payload", after.download - before.download >= rounds * server.download.size)
            assertTrue("Asymmetric payload directions must not be swapped", after.download - before.download > after.upload - before.upload)
            assertTrue("Public upload speed is positive during actual traffic", uploadSpeed)
            assertTrue("Public download speed is positive during actual traffic", downloadSpeed)
            assertEquals(original, source.toString())
            InstrumentationRegistry.getInstrumentation().addResults(Bundle().apply {
                putString(if (proxyOnly) "PROXY_PUBLIC_TRAFFIC_DEFAULTS" else if (nativeRouting) "NATIVE_ROUTING_PUBLIC_TRAFFIC_DEFAULTS" else "VPN_PUBLIC_TRAFFIC_DEFAULTS",
                    "TRAFFIC_DEFAULTS mode=${if (proxyOnly) "proxy" else if (nativeRouting) "native-routing" else "vpn"} before_up=${before.upload} before_down=${before.download} " +
                        "after_up=${after.upload} after_down=${after.download} upload_speed=positive download_speed=positive\n")
            })
        } catch (error: Throwable) { primary = error; throw error }
        finally {
            val errors = mutableListOf<Throwable>()
            runCatching { stopped(ownedPorts) }.exceptionOrNull()?.let(errors::add)
            runCatching { context.unregisterReceiver(receiver) }.exceptionOrNull()?.let(errors::add)
            runCatching { origin?.close() }.exceptionOrNull()?.let(errors::add)
            if (errors.isNotEmpty()) {
                val error = primary ?: AssertionError("Public statistics fixture cleanup failed")
                errors.forEach(error::addSuppressed)
                if (primary == null) throw error
            }
        }
    }

    @Test fun vpnPublishesTotalsAndSpeedsWithCallerLevelsAndEmptySystem() = exercise(proxyOnly = false)
    @Test fun proxyOnlyPublishesTotalsAndSpeedsWithCallerLevelsAndEmptySystem() = exercise(proxyOnly = true)
    @Test fun nativeRoutingVpnPublishesTotalsAndSpeedsWithCallerLevelsAndEmptySystem() = exercise(proxyOnly = false, nativeRouting = true)
}
