package com.github.tfox.flutter_vless.xray.service

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.RouteInfo
import android.os.Build
import java.io.ByteArrayOutputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.TimeUnit

/** Dedicated fixture precondition, separate from the S/Q operation under test. */
internal object NativePreviewFixtureNetwork {
    private val destination = InetAddress.getByAddress(byteArrayOf(10, 0, 2, 2))

    private fun eligible(manager: ConnectivityManager, network: Network): Boolean {
        val caps = manager.getNetworkCapabilities(network) ?: return false
        val links = manager.getLinkProperties(network) ?: return false
        return !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            links.linkAddresses.any { it.address is Inet4Address } &&
            links.routes.any { it.type == RouteInfo.RTN_UNICAST && it.destination.address is Inet4Address && it.matches(destination) }
    }

    fun describe(context: Context, network: Network?): String {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        return "default=${manager.activeNetwork?.networkHandle}; captured=${network?.networkHandle}; " +
            "caps=${network?.let(manager::getNetworkCapabilities)}; links=${network?.let(manager::getLinkProperties)}"
    }

    fun capture(context: Context): Network {
        check(Build.HARDWARE in setOf("ranchu", "goldfish")) { "Dedicated emulator fixture required" }
        val manager = context.getSystemService(ConnectivityManager::class.java)
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (System.nanoTime() < end) {
            val network = manager.activeNetwork
            if (network != null && eligible(manager, network)) return network
            Thread.sleep(25) // Wait only for the previous fixture's OS default restoration.
        }
        error("Fixture physical default/IPv4 route unavailable before S/Q: ${describe(context, manager.activeNetwork)}")
    }

    /** One bounded control connection; never retry the actual protected operation. */
    fun verify(context: Context, network: Network) {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        val details = describe(context, network)
        android.util.Log.i("NativePreviewFixture", "Before numeric control: $details")
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        fun timeout(): Int = TimeUnit.NANOSECONDS.toMillis(end - System.nanoTime()).toInt().coerceAtMost(1000)
            .also { check(it > 0) { "Fixture numeric control deadline" } }
        try {
            check(manager.activeNetwork == network && eligible(manager, network))
            network.socketFactory.createSocket().use { socket ->
                socket.connect(InetSocketAddress(destination, 18083), timeout())
                socket.getOutputStream().write("GET /native-preview-control HTTP/1.1\r\nHost: 10.0.2.2\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(512)
                while (output.size() < 8192) {
                    socket.soTimeout = timeout()
                    val count = socket.getInputStream().read(buffer, 0, minOf(buffer.size, 8192 - output.size()))
                    if (count < 0) break
                    output.write(buffer, 0, count)
                }
                check(output.toString("US-ASCII").contains("flutter-vless-direct-bypass"))
            }
            check(manager.activeNetwork == network && eligible(manager, network))
        } catch (error: Exception) {
            throw AssertionError("Fixture bound numeric control failed before S/Q; before=$details; after=${describe(context, network)}", error)
        }
    }
}
