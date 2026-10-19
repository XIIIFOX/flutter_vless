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
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.filters.SdkSuppress
import com.github.tfox.flutter_vless.xray.core.XrayCoreManager
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetSocketAddress
import java.net.Socket
import java.io.ByteArrayOutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

@RunWith(AndroidJUnit4::class)
class ControlledDomainRoutingTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private fun snapshot() = XrayCoreManager.getProviderDebugSnapshot(context)
    private fun captured() = context.getSystemService(ConnectivityManager::class.java)
        .getNetworkCapabilities(context.getSystemService(ConnectivityManager::class.java).activeNetwork)
        ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    private fun awaitReady(previousConnections: Int = 0) {
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(45)
        while (System.nanoTime() < end) {
            if (captured() && snapshot().lineSequence().count { it == "CONNECTED" } > previousConnections) return
            Thread.sleep(100)
        }
        fail("Routing session unavailable; events=${snapshot()}")
    }
    private fun request(host: String): String = Socket().use {
        it.soTimeout = 4000; it.connect(InetSocketAddress("10.0.2.2", 18083), 4000)
        it.getOutputStream().write("GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n".toByteArray())
        it.getInputStream().bufferedReader().readText()
    }
    private fun traffic(): Map<String, Long> {
        val stats = NativeOwnedStatsReader.read(context)
        val result = mutableMapOf("direct" to 0L, "proxy" to 0L)
        for (i in 0 until stats.length()) {
            val entry = stats.getJSONObject(i)
            val name = entry.getString("name")
            for (tag in result.keys.toList()) if (name.startsWith("outbound>>>$tag>>>traffic>>>")) result[tag] = result.getValue(tag) + entry.optLong("value", 0L)
        }
        return result
    }
    private fun assertRoutes() {
        val beforeDirect = traffic()
        assertTrue("Domain direct route must reach the physical control origin", request("direct-site.invalid").contains("flutter-vless-direct-bypass"))
        val afterDirect = traffic()
        assertTrue("Direct outbound must carry application bytes", afterDirect.getValue("direct") > beforeDirect.getValue("direct"))
        assertTrue("Domain proxy route must reach the proxy control origin", request("proxy-site.invalid").contains("flutter-vless-protected-host"))
        val afterProxy = traffic()
        assertTrue("Proxy outbound must carry application bytes", afterProxy.getValue("proxy") > afterDirect.getValue("proxy"))
        assertEquals("Proxy request must not use direct outbound", afterDirect.getValue("direct"), afterProxy.getValue("direct"))
    }
    @Test fun sniffedDomainRulesSelectDirectAndProxyAndSurviveRecovery() {
        val config = XrayConfig(REMARK = "Controlled routing", V2RAY_FULL_JSON_CONFIG = """
            {"inbounds":[],"dns":{"hosts":{"direct-site.invalid":"10.0.2.2","proxy-site.invalid":"10.0.2.2"},"servers":[]},
             "outbounds":[{"tag":"proxy","protocol":"socks","settings":{"address":"10.0.2.2","port":18080}},
                          {"tag":"direct","protocol":"freedom","settings":{"domainStrategy":"UseIP"}},
                          {"tag":"blocked","protocol":"blackhole"}],
             "routing":{"rules":[{"type":"field","domain":["domain:gstatic.com"],"outboundTag":"blocked"},
                                   {"type":"field","domain":["full:direct-site.invalid"],"outboundTag":"direct"},
                                   {"type":"field","domain":["full:proxy-site.invalid"],"outboundTag":"proxy"}]}}
        """.trimIndent())
        try {
            context.startForegroundService(Intent(context, XrayVPNService::class.java)
                .putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE).putExtra("V2RAY_CONFIG", config))
            awaitReady(); assertRoutes()
            // A deliberately blocked Internet probe site must not tear down a
            // working session at the periodic readiness check either.
            Thread.sleep(33_000)
            assertTrue(captured())
            assertEquals("Readiness must not restart a working session", 1, snapshot().lineSequence().count { it == "CONNECTED" })
            assertFalse(snapshot().contains("AUTH_PROBE_FAILED"))
            assertRoutes()
            val prior = snapshot().lineSequence().count { it == "CONNECTED" }
            assertEquals(0, ProcessBuilder("pkill", "-9", "-x", "libxray.so").start().waitFor())
            awaitReady(prior); assertRoutes()
        } finally {
            context.startService(Intent(context, XrayVPNService::class.java).putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE))
            Thread.sleep(500)
        }
    }

    private data class PublicTraffic(val receivedAt: Long, val seconds: Long,
        val uploadSpeed: Long, val downloadSpeed: Long, val upload: Long, val download: Long)

    private fun stopPublicCounterSession() {
        val completed = CountDownLatch(1); val result = AtomicInteger(-1)
        context.startService(Intent(context, XrayVPNService::class.java)
            .putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE)
            .putExtra("stop_receiver", object : ResultReceiver(null) {
                override fun onReceiveResult(code: Int, data: Bundle?) { result.set(code); completed.countDown() }
            }))
        assertTrue("Public counter Stop acknowledgement was lost", completed.await(15, TimeUnit.SECONDS))
        assertEquals("Public counter Stop was refused", 0, result.get())
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        fun ownedFilesRemain() = context.noBackupFilesDir.listFiles().orEmpty().any {
            it.name.startsWith("xray-") || it.name.startsWith("tun-") || it.name.startsWith("validate-")
        }
        while ((captured() || ownedFilesRemain()) && System.nanoTime() < deadline) Thread.sleep(50)
        assertFalse("Public counter Stop retained capture", captured())
        assertFalse("Public counter Stop retained runtime inputs", ownedFilesRemain())
        assertFalse("Public counter Stop retained authorization",
            java.io.File(context.noBackupFilesDir, "flutter_vless_authorized_v1.bin").exists())
        InstrumentationRegistry.getInstrumentation().waitForIdleSync()
    }

    private fun publicCounterHttp() {
        val expected = "flutter-vless-direct-bypass".toByteArray(Charsets.US_ASCII)
        Socket().use { socket ->
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(4)
            socket.connect(InetSocketAddress("10.0.2.2", 18083), 4000)
            socket.getOutputStream().write("GET / HTTP/1.1\r\nHost: public-counter.invalid\r\nConnection: close\r\n\r\n".toByteArray())
            val input = socket.getInputStream()
            fun readByte(): Int {
                val remaining = deadline - System.nanoTime()
                check(remaining > 0) { "Controlled public counter HTTP deadline" }
                socket.soTimeout = TimeUnit.NANOSECONDS.toMillis(remaining).coerceIn(1, 4000).toInt()
                return input.read().also { check(it >= 0) { "Controlled public counter HTTP incomplete frame" } }
            }
            val header = ByteArrayOutputStream(); var tail = 0
            while (header.size() < 4096 && tail != 0x0d0a0d0a) {
                val value = readByte(); header.write(value); tail = (tail shl 8) or value
            }
            check(tail == 0x0d0a0d0a) { "Controlled public counter HTTP oversized header" }
            val lines = header.toString("US-ASCII").split("\r\n")
            assertTrue("Controlled public counter HTTP status", lines.first().startsWith("HTTP/1.1 200 ") ||
                lines.first().startsWith("HTTP/1.0 200 "))
            val length = lines.filter { it.startsWith("Content-Length:", ignoreCase = true) }
                .singleOrNull()?.substringAfter(':')?.trim()?.toIntOrNull()
            assertEquals("Controlled public counter HTTP body length", expected.size, length)
            assertFalse("Controlled public counter HTTP transfer encoding", lines.any { it.startsWith("Transfer-Encoding:", true) })
            val body = ByteArray(expected.size) { readByte().toByte() }
            assertArrayEquals("Controlled public counter HTTP body", expected, body)
            // The complete declared body qualifies; no dependency on a later TCP FIN.
        }
    }

    @SdkSuppress(minSdkVersion = 26)
    @Test fun publicOwnedInputTrafficSurvivesCustomDefaultTagAndDisabledCallerPolicy() {
        stopPublicCounterSession()
        for (enabled in listOf(true, false)) {
            val source = JSONObject("""{"inbounds":[],"stats":{},
                "policy":{"system":{"statsInboundUplink":$enabled,"statsInboundDownlink":$enabled,
                    "statsOutboundUplink":$enabled,"statsOutboundDownlink":$enabled}},
                "outbounds":[{"tag":"edge-live","protocol":"freedom"},{"tag":"blocked","protocol":"blackhole"}],
                "routing":{"rules":[{"type":"field","port":"1-18082,18084-65535","outboundTag":"blocked"}]}}""")
            val original = source.toString()
            val updates = LinkedBlockingQueue<PublicTraffic>(32)
            var connecting = false
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(context: Context?, intent: Intent?) {
                    if (intent?.action != AppConfigs.V2RAY_CONNECTION_INFO) return
                    @Suppress("DEPRECATION")
                    val state = intent.getSerializableExtra("STATE") as? AppConfigs.V2RAY_STATES ?: return
                    if (state == AppConfigs.V2RAY_STATES.V2RAY_CONNECTING) { connecting = true; updates.clear() }
                    if (state == AppConfigs.V2RAY_STATES.V2RAY_CONNECTED && connecting) {
                        updates.offer(PublicTraffic(System.nanoTime(), intent.getStringExtra("DURATION")?.toLongOrNull() ?: -1,
                            intent.getLongExtra("UPLOAD_SPEED", -1), intent.getLongExtra("DOWNLOAD_SPEED", -1),
                            intent.getLongExtra("UPLOAD_TRAFFIC", -1), intent.getLongExtra("DOWNLOAD_TRAFFIC", -1)))
                    }
                }
            }
            fun next(deadline: Long): PublicTraffic {
                val sample = updates.poll((deadline - System.nanoTime()).coerceAtLeast(1), TimeUnit.NANOSECONDS)
                    ?: throw AssertionError("Fresh public counter status did not arrive")
                assertTrue("Public counter status fields are incomplete", listOf(sample.seconds, sample.uploadSpeed,
                    sample.downloadSpeed, sample.upload, sample.download).all { it >= 0 })
                return sample
            }
            val filter = IntentFilter(AppConfigs.V2RAY_CONNECTION_INFO)
            if (Build.VERSION.SDK_INT >= 33) context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
            else @Suppress("DEPRECATION") context.registerReceiver(receiver, filter)
            try {
                assertNull("Disposable public counter VPN consent is required", android.net.VpnService.prepare(context))
                context.startForegroundService(Intent(context, XrayVPNService::class.java)
                    .putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE)
                    .putExtra("V2RAY_CONFIG", XrayConfig(REMARK = "Public owned counter control", V2RAY_FULL_JSON_CONFIG = original,
                        ENABLE_TRAFFIC_STATICS = true, PLUGIN_OPTIONS_JSON = """{"reconnect":{"enabled":false}}""")))
                val before = next(System.nanoTime() + TimeUnit.SECONDS.toNanos(45))
                assertTrue("Public counter session did not capture VPN traffic", captured())
                val runtime = try {
                    val file = context.noBackupFilesDir.listFiles().orEmpty().single {
                        it.name.startsWith("xray-") && it.name.endsWith(".json") && !it.name.endsWith(".spec.json")
                    }
                    JSONObject(file.readText())
                } catch (error: Exception) { throw AssertionError("Public counter runtime unavailable (${error.javaClass.simpleName})") }
                assertEquals(source.getJSONObject("policy").toString(), runtime.getJSONObject("policy").toString())
                assertEquals(source.getJSONObject("stats").toString(), runtime.getJSONObject("stats").toString())
                assertEquals("edge-live", runtime.getJSONArray("outbounds").getJSONObject(0).getString("tag"))
                assertFalse((0 until runtime.getJSONArray("outbounds").length()).any {
                    runtime.getJSONArray("outbounds").getJSONObject(it).optString("tag") == "proxy"
                })
                if (!enabled) assertEquals(listOf(0L, 0L, 0L, 0L),
                    listOf(before.uploadSpeed, before.downloadSpeed, before.upload, before.download))
                publicCounterHttp()
                val responseCompleted = System.nanoTime()
                val deadline = responseCompleted + TimeUnit.SECONDS.toNanos(5)
                var after = before
                var zeroTicks = 0
                while (System.nanoTime() < deadline) {
                    val sample = next(deadline)
                    if (sample.receivedAt < responseCompleted || sample.seconds <= after.seconds) continue
                    after = sample
                    if (enabled) {
                        if (after.upload > before.upload && after.download > before.download) break
                    } else {
                        assertEquals("Disabled caller policy must not fabricate public traffic", listOf(0L, 0L, 0L, 0L),
                            listOf(after.uploadSpeed, after.downloadSpeed, after.upload, after.download))
                        zeroTicks++
                        if (zeroTicks == 2) break
                    }
                }
                if (enabled) {
                    assertTrue("Owned public upload did not grow after controlled HTTP", after.upload > before.upload)
                    assertTrue("Owned public download did not grow after controlled HTTP", after.download > before.download)
                } else assertEquals("Two fresh disabled-policy status ticks are required", 2, zeroTicks)
                assertEquals(original, source.toString())
                InstrumentationRegistry.getInstrumentation().addResults(Bundle().apply {
                    putString(if (enabled) "PUBLIC_OWNED_TRAFFIC_ENABLED" else "PUBLIC_OWNED_TRAFFIC_DISABLED",
                        "PUBLIC_OWNED_TRAFFIC enabled=${if (enabled) 1 else 0} before_up=${before.upload} " +
                        "before_down=${before.download} after_up=${after.upload} after_down=${after.download} zero_ticks=$zeroTicks\n")
                })
            } finally {
                try { stopPublicCounterSession() } finally { context.unregisterReceiver(receiver) }
            }
        }
    }
}
