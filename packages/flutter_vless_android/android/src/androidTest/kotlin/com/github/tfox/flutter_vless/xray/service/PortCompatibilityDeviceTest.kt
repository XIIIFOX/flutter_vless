package com.github.tfox.flutter_vless.xray.service

import android.content.Intent
import android.net.ConnectivityManager
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.NetworkCapabilities
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.ResultReceiver
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.DataInputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Actual imported listeners + HTTP bytes through TUN; dedicated emulator only. */
@RunWith(AndroidJUnit4::class)
class PortCompatibilityDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private fun captured(): Boolean {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        return manager.getNetworkCapabilities(manager.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }
    private fun command(start: Boolean, input: JSONObject? = null) {
        val completion = CountDownLatch(1)
        var code = -1
        val intent = Intent(context, XrayVPNService::class.java)
            .putExtra("COMMAND", if (start) AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE else AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE)
            .putExtra(if (start) "start_receiver" else "stop_receiver", object : ResultReceiver(Handler(Looper.getMainLooper())) {
                override fun onReceiveResult(result: Int, data: Bundle?) { code = result; completion.countDown() }
            })
        if (start) {
            val profile = JSONObject().put("inbounds", JSONArray().put(input))
                .put("outbounds", JSONArray().put(JSONObject("""{"protocol":"socks","tag":"proxy","settings":{"address":"10.0.2.2","port":18080}}""")))
            intent.putExtra("V2RAY_CONFIG", XrayConfig(REMARK = "Port corpus", V2RAY_FULL_JSON_CONFIG = profile.toString()))
            context.startForegroundService(intent)
        } else context.startService(intent)
        assertTrue("Native command acknowledgement", completion.await(15, TimeUnit.SECONDS))
        assertEquals("Native command result", 0, code)
    }
    private fun http(input: InputStream, output: OutputStream, absolute: Boolean = false): String {
        val target = if (absolute) "http://10.0.2.2:18083/" else "/"
        output.write("GET $target HTTP/1.1\r\nHost: 10.0.2.2:18083\r\nConnection: close\r\n\r\n".toByteArray())
        return input.bufferedReader().readText()
    }
    private fun importedSocks(input: InputStream, output: OutputStream): String {
        val reader = DataInputStream(input)
        output.write(byteArrayOf(5, 1, 0))
        assertEquals(5, reader.readUnsignedByte()); assertEquals(0, reader.readUnsignedByte())
        output.write(byteArrayOf(5, 1, 0, 1, 10, 0, 2, 2, 70, 163.toByte())) // 18083
        assertEquals(5, reader.readUnsignedByte()); assertEquals(0, reader.readUnsignedByte())
        reader.readUnsignedByte()
        val addressBytes = when (reader.readUnsignedByte()) {
            1 -> 4
            4 -> 16
            3 -> reader.readUnsignedByte()
            else -> error("Invalid SOCKS reply address")
        }
        reader.readFully(ByteArray(addressBytes + 2))
        return http(reader, output)
    }
    @Test fun listsRangesZeroAndUnixInputsPreserveRealForwarding() {
        assertNull(android.net.VpnService.prepare(context))
        val name = "flutter-vless-port-corpus-${System.nanoTime()}"
        val inputs = listOf(
            JSONObject("""{"protocol":"socks","listen":"127.0.0.1","port":"18090,18091-18092","tag":"caller-input","settings":{"auth":"noauth"}}"""),
            // Pinned Core's SOCKS inbound advertises TCP only. HTTP advertises
            // UNIX as well, so it is the real supported Unix-listener control.
            JSONObject().put("protocol", "http").put("listen", "@$name").put("port", "0-65535")
                .put("tag", "caller-input").put("settings", JSONObject()),
            JSONObject().put("protocol", "socks").put("listen", "127.0.0.1").put("port", 0)
        )
        for ((index, input) in inputs.withIndex()) {
            try {
                command(true, input)
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
                var transferred = false
                while (System.nanoTime() < deadline && !transferred) {
                    transferred = captured() && runCatching {
                        Socket().use {
                            it.soTimeout = 1500; it.connect(InetSocketAddress("10.0.2.2", 18083), 500)
                            http(it.getInputStream(), it.getOutputStream()).contains("flutter-vless-protected-host")
                        }
                    }.getOrDefault(false)
                    if (!transferred) Thread.sleep(100)
                }
                assertTrue("Actual protected HTTP bytes for input $index", transferred)
                if (index == 0) for (port in 18090..18092) {
                    Socket("127.0.0.1", port).use {
                        it.soTimeout = 10000
                        assertTrue(importedSocks(it.getInputStream(), it.getOutputStream()).contains("flutter-vless-protected-host"))
                    }
                }
                if (index == 1) LocalSocket().use {
                    it.connect(LocalSocketAddress(name, LocalSocketAddress.Namespace.ABSTRACT)); it.soTimeout = 10000
                    assertTrue(http(it.inputStream, it.outputStream, absolute = true).contains("flutter-vless-protected-host"))
                }
            } finally {
                command(false)
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
                while (captured() && System.nanoTime() < deadline) Thread.sleep(100)
                assertFalse("Explicit Stop must release test capture", captured())
            }
        }
    }
}
