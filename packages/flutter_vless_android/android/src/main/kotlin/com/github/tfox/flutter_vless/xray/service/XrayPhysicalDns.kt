package com.github.tfox.flutter_vless.xray.service

import android.net.DnsResolver
import android.net.Network
import android.os.Build
import android.os.CancellationSignal
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** System DNS on a physical Network retains Android's Private DNS policy. */
internal object XrayPhysicalDns {
    fun query(network: Network, query: ByteArray): ByteArray {
        if (Build.VERSION.SDK_INT < 29) return addressQuery(query) { network.getAllByName(it).map { ip -> ip.address } }
        val done = CountDownLatch(1)
        val cancel = CancellationSignal()
        var answer: ByteArray? = null
        try {
            DnsResolver.getInstance().rawQuery(network, query, DnsResolver.FLAG_EMPTY,
                { it.run() }, cancel, object : DnsResolver.Callback<ByteArray> {
                    override fun onAnswer(result: ByteArray, rcode: Int) { answer = result; done.countDown() }
                    override fun onError(error: DnsResolver.DnsException) { done.countDown() }
                })
            check(done.await(10, TimeUnit.SECONDS)) { "Physical DNS timeout" }
            return checkNotNull(answer) { "Physical DNS failed" }
        } finally { cancel.cancel() }
    }

    /** Android 23–28 has only the network-scoped address API. Non-address
     * system queries fail explicitly; they must use an explicit Xray DNS server. */
    internal fun addressQuery(query: ByteArray, lookup: (String) -> List<ByteArray>): ByteArray {
        require(query.size >= 12 && query[4].toInt() == 0 && query[5].toInt() == 1)
        var offset = 12
        val labels = mutableListOf<String>()
        while (true) {
            require(offset < query.size)
            val length = query[offset++].toInt() and 255
            if (length == 0) break
            require(length <= 63 && offset + length <= query.size)
            labels.add(String(query, offset, length, Charsets.US_ASCII))
            offset += length
        }
        require(offset + 4 <= query.size)
        val type = ((query[offset].toInt() and 255) shl 8) or (query[offset + 1].toInt() and 255)
        val clazz = ((query[offset + 2].toInt() and 255) shl 8) or (query[offset + 3].toInt() and 255)
        offset += 4
        val supported = clazz == 1 && (type == 1 || type == 28)
        val addresses = if (supported) lookup(labels.joinToString(".")).filter { it.size == if (type == 1) 4 else 16 } else emptyList()
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { out ->
            out.write(query, 0, 2)
            out.writeShort(if (supported) 0x8180 else 0x8184) // response / NOTIMP
            out.writeShort(1); out.writeShort(addresses.size); out.writeInt(0)
            out.write(query, 12, offset - 12)
            addresses.forEach { address ->
                out.writeShort(0xc00c); out.writeShort(type); out.writeShort(1)
                out.writeInt(0); out.writeShort(address.size); out.write(address)
            }
        }
        return bytes.toByteArray()
    }
}
