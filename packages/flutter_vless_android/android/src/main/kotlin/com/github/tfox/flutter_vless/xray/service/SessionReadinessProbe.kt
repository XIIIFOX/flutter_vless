package com.github.tfox.flutter_vless.xray.service

import org.json.JSONArray
import org.json.JSONObject
import com.github.tfox.flutter_vless.xray.core.XrayServiceTags
import com.github.tfox.flutter_vless.xray.core.StartupReadiness
import com.github.tfox.flutter_vless.xray.core.ReadinessFailure
import com.github.tfox.flutter_vless.xray.core.ReadinessStage
import java.io.Closeable
import java.io.DataInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Locale
import java.util.UUID

/** An owned response through SOCKS and TUN, independent of Internet-site policy. */
internal class SessionReadinessProbe(val host: String) : Closeable {
    private val token = UUID.randomUUID().toString().toByteArray(Charsets.US_ASCII)
    private val server = ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"))
    val port: Int get() = server.localPort
    @Volatile private var accepted: Socket? = null
    private val listener = Thread({
        while (!server.isClosed) {
            runCatching {
                server.accept().use { client ->
                    accepted = client
                    if (!server.isClosed) {
                        // Never wait for client input: a byte-dripping local
                        // connection must not hold up probes or retain a worker.
                        client.getOutputStream().write(token)
                    }
                }
            }
            accepted = null
        }
    }, "vpn-path-probe").apply { isDaemon = true; start() }

    fun configure(source: JSONObject, managedPort: Int): JSONObject {
        val json = JSONObject(source.toString())
        val inputs = json.getJSONArray("inbounds")
        val managedTag = (0 until inputs.length()).map(inputs::getJSONObject).single {
            it.optString("protocol") == "socks" && it.optInt("port") == managedPort && it.optString("listen") == "127.0.0.1"
        }.getString("tag")
        require(managedTag.isNotEmpty()) { "Private packet-path input is unavailable" }
        val tag = XrayServiceTags(json).next("flutter-vless-path-${UUID.randomUUID()}")
        json.getJSONArray("outbounds").put(JSONObject().put("tag", tag).put("protocol", "freedom")
            .put("settings", JSONObject().put("redirect", "127.0.0.1:$port")))
        val routing = json.getJSONObject("routing")
        val rules = JSONArray().put(JSONObject().put("type", "field").put("inboundTag", JSONArray().put(managedTag))
            .put("ip", JSONArray().put("$host/32"))
            .put("port", port.toString()).put("network", "tcp").put("outboundTag", tag))
        val existing = routing.getJSONArray("rules")
        for (index in 0 until existing.length()) rules.put(existing.get(index))
        routing.put("rules", rules)
        return json
    }

    fun verify(readiness: StartupReadiness? = null, stage: ReadinessStage = ReadinessStage.PACKET_CHALLENGE,
        connect: (() -> Socket)? = null) {
        val client = if (connect != null) connect() else Socket().also { socket ->
            try {
                readiness?.adopt(socket)
                socket.connect(InetSocketAddress(host, port), readiness?.remainingMillis() ?: 3000)
                readiness?.check()
            } catch (error: Exception) {
                try { socket.close(); readiness?.release(socket) } catch (cleanup: Exception) { error.addSuppressed(cleanup) }
                if (readiness != null) { readiness.check(); throw ReadinessFailure(stage) }
                throw error
            }
        }
        var primary: Throwable? = null
        try {
            readiness?.adopt(client)
            client.soTimeout = readiness?.remainingMillis() ?: 3000
            val response = ByteArray(token.size)
            if (readiness == null) DataInputStream(client.getInputStream()).readFully(response)
            else readiness.readFully(client, client.getInputStream(), response, stage)
            if (!response.contentEquals(token)) {
                if (readiness != null) throw ReadinessFailure(stage)
                error("Local packet path mismatch")
            }
            readiness?.check()
        } catch (error: Throwable) {
            primary = error
            if (readiness != null && error is Exception && error !is ReadinessFailure) {
                try { readiness.check() } catch (guard: ReadinessFailure) { primary = guard; throw guard }
                val failure = ReadinessFailure(stage)
                primary = failure
                throw failure
            }
            throw error
        } finally {
            try { client.close(); readiness?.release(client) }
            catch (cleanup: Throwable) { if (primary != null) primary.addSuppressed(cleanup) else throw cleanup }
        }
    }

    override fun close() {
        server.close()
        accepted?.close()
        listener.join(1500)
        check(!listener.isAlive) { "Local packet path listener did not stop" }
    }

    companion object {
        /** Keep the probe outside every FakeDNS pool, including its implicit default. */
        fun selectHost(config: JSONObject): String {
            fun field(objectValue: JSONObject, name: String): Any? {
                val keys = objectValue.keys().asSequence().filter {
                    it.replace('ſ', 's').replace('K', 'k').lowercase(Locale.ROOT) == name.lowercase(Locale.ROOT)
                }.toList()
                require(keys.size <= 1) { "Ambiguous FakeDNS fields" }
                return keys.firstOrNull()?.let { objectValue.opt(it) }
            }
            fun range(cidr: String): LongRange? {
                if (cidr.contains(':')) return null
                val parts = cidr.split('/')
                val bytes = parts[0].split('.').map { it.toInt() }
                require(parts.size == 2 && bytes.size == 4 && bytes.all { it in 0..255 })
                val prefix = parts[1].toInt(); require(prefix in 0..32)
                val ip = bytes.fold(0L) { value, byte -> (value shl 8) or byte.toLong() }
                val size = 1L shl (32 - prefix)
                val first = ip and (0xffffffffL xor (size - 1))
                return first..(first + size - 1)
            }
            val pools = when (val value = field(config, "fakedns")) {
                is JSONArray -> (0 until value.length()).map { value.getJSONObject(it) }
                is JSONObject -> listOf(value)
                else -> emptyList()
            }
            val excluded = mutableListOf(0L..0x00ffffffL, 0x7f000000L..0x7fffffffL, 0xe0000000L..0xffffffffL)
            excluded += range("198.18.0.0/15")!!
            pools.forEach { pool -> (field(pool, "ipPool") as? String)?.let { range(it)?.let(excluded::add) } }
            val sorted = excluded.sortedBy { it.first }
            fun free(start: Long): Long? {
                var candidate = start
                for (entry in sorted) if (candidate in entry) candidate = entry.last + 1
                return candidate.takeIf { it <= 0xdfffffffL }
            }
            val ip = free(0xc6336401L) ?: free(0x01000001L)
                ?: error("FakeDNS leaves no IPv4 address for VPN readiness")
            return (3 downTo 0).joinToString(".") { ((ip shr (it * 8)) and 255).toString() }
        }
    }
}
