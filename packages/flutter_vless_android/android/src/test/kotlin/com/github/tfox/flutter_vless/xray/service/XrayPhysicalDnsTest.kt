package com.github.tfox.flutter_vless.xray.service

import org.junit.Assert.*
import org.junit.Test

class XrayPhysicalDnsTest {
    private fun query(type: Int) = byteArrayOf(0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        1, 'a'.code.toByte(), 4, 't'.code.toByte(), 'e'.code.toByte(), 's'.code.toByte(), 't'.code.toByte(), 0,
        0, type.toByte(), 0, 1)

    @Test fun oldAndroidAddressBridgePreservesQuestionAndFamily() {
        for (type in listOf(1, 28)) {
            val response = XrayPhysicalDns.addressQuery(query(type)) { name ->
                assertEquals("a.test", name)
                listOf(byteArrayOf(192.toByte(), 0, 2, 1), ByteArray(16) { 1 })
            }
            assertEquals(1, response[7].toInt())
            assertArrayEquals(query(type).copyOfRange(12, 24), response.copyOfRange(12, 24))
            assertEquals(if (type == 1) 40 else 52, response.size)
        }
        val unsupported = XrayPhysicalDns.addressQuery(query(16)) { error("Must not use a different resolver") }
        assertEquals(4, unsupported[3].toInt() and 15)
    }

    @Test(expected = IllegalArgumentException::class)
    fun malformedQuestionFailsClosed() {
        XrayPhysicalDns.addressQuery(query(1).copyOf(15)) { emptyList() }
    }

    @Test fun proxyModeDeniesEveryPhysicalQueryAfterEndpointPinning() {
        assertFalse(XrayPhysicalDns.isQueryAllowed(query(1), emptySet()))
        assertFalse(XrayPhysicalDns.isQueryAllowed(query(28), emptySet()))
        assertTrue(XrayPhysicalDns.isQueryAllowed(query(1), null))
        assertTrue(XrayPhysicalDns.isQueryAllowed(query(16), null))
    }

    @Test fun scopedBrokerAllowsOnlyExplicitEndpointAddressQueries() {
        for (type in listOf(1, 28)) {
            assertTrue(XrayPhysicalDns.isQueryAllowed(query(type), setOf("A.TEST.")))
            assertFalse(XrayPhysicalDns.isQueryAllowed(query(type), setOf("proxy.test")))
            assertFalse(XrayPhysicalDns.isQueryAllowed(query(type), setOf("test")))
            assertFalse(XrayPhysicalDns.isQueryAllowed(query(type), setOf("control.a.test")))
        }
        assertFalse(XrayPhysicalDns.isQueryAllowed(query(16), setOf("a.test")))
        assertFalse(XrayPhysicalDns.isQueryAllowed(query(33), setOf("a.test")))
        // A user-controlled second question/additional record cannot ride an endpoint query.
        assertFalse(XrayPhysicalDns.isQueryAllowed(query(1).also { it[5] = 2 }, setOf("a.test")))
        assertFalse(XrayPhysicalDns.isQueryAllowed(query(1) + query(1), setOf("a.test")))
        assertFalse(XrayPhysicalDns.isQueryAllowed(query(1).also { it[2] = 0x81.toByte() }, setOf("a.test")))
        assertFalse(XrayPhysicalDns.isQueryAllowed(query(1).also { it[12] = 0xc0.toByte() }, setOf("a.test")))
        assertFalse(XrayPhysicalDns.isQueryAllowed(query(1).also { it[it.lastIndex] = 3 }, setOf("a.test")))
        assertFalse(XrayPhysicalDns.isQueryAllowed(query(1).copyOf(15), setOf("a.test")))
    }

    @Test fun scopedBrokerAcceptsEmptyEdnsOptButRejectsAdditionalPayload() {
        val edns = query(1).also { it[11] = 1 } + byteArrayOf(0, 0, 41, 4, 0, 0, 0, 0, 0, 0, 0)
        assertTrue(XrayPhysicalDns.isQueryAllowed(edns, setOf("a.test")))
        assertFalse(XrayPhysicalDns.isQueryAllowed(edns + 1.toByte(), setOf("a.test")))
        assertFalse(XrayPhysicalDns.isQueryAllowed(edns.also { it[it.lastIndex] = 1 }, setOf("a.test")))
    }
}
