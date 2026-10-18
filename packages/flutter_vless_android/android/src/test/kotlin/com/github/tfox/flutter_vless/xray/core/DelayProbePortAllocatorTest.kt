package com.github.tfox.flutter_vless.xray.core

import java.io.File
import java.io.IOException
import java.net.BindException
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class DelayProbePortAllocatorTest {
    private class Listener(override val port: Int, private val closeError: IOException? = null) : DelayProbePortAllocator.Listener {
        var closes = 0
        override fun close() {
            closes++
            closeError?.let { throw it }
        }
    }

    @Test fun busyAdjacentApiPortRejectsTheCandidateWithoutClosingTheOtherOwner() {
        val callerApi = Listener(41001)
        val firstSocks = Listener(41000)
        val socks = Listener(42000)
        val api = Listener(42001)
        val requested = mutableListOf<Int>()
        val pair = DelayProbePortAllocator.reserve { port ->
            requested.add(port)
            when (requested.size) {
                1 -> firstSocks
                2 -> { assertEquals(callerApi.port, port); throw BindException("synthetic occupied listener") }
                3 -> socks
                4 -> api
                else -> error("Unexpected allocation attempt")
            }
        }
        assertEquals(listOf(0, 41001, 0, 42001), requested)
        assertEquals(1, firstSocks.closes)
        assertEquals(0, callerApi.closes)
        assertEquals(42000, pair.socksPort)
        assertEquals(42001, pair.apiPort)
        assertEquals(0, socks.closes)
        assertEquals(0, api.closes)
        pair.close(); pair.close()
        assertEquals(1, socks.closes)
        assertEquals(1, api.closes)
        assertEquals(0, callerApi.closes)
    }

    @Test fun occupiedAdjacentPortsHaveExactlyThirtyTwoBoundedAttemptsAndNoLeaks() {
        val candidates = mutableListOf<Listener>()
        var apiAttempts = 0
        assertThrows(BindException::class.java) {
            DelayProbePortAllocator.reserve { port ->
                if (port == 0) Listener(41000).also(candidates::add)
                else { assertEquals(41001, port); apiAttempts++; throw BindException("occupied") }
            }
        }
        assertEquals(32, candidates.size)
        assertEquals(32, apiAttempts)
        assertTrue(candidates.all { it.closes == 1 })
    }

    @Test fun maximumPortCannotOverflowTheAdjacentApiAndEveryCandidateIsClosed() {
        val candidates = mutableListOf<Listener>()
        assertThrows(BindException::class.java) {
            DelayProbePortAllocator.reserve { port ->
                assertEquals("Port 65536 must never reach bind", 0, port)
                Listener(65535).also(candidates::add)
            }
        }
        assertEquals(32, candidates.size)
        assertTrue(candidates.all { it.closes == 1 })
    }

    @Test fun unexpectedBindFailurePropagatesAfterClosingTheOwnedCandidate() {
        val socks = Listener(41000)
        val error = IOException("synthetic unexpected bind failure")
        var calls = 0
        val thrown = assertThrows(IOException::class.java) {
            DelayProbePortAllocator.reserve { port ->
                calls++
                if (port == 0) socks else throw error
            }
        }
        assertSame(error, thrown)
        assertEquals(2, calls)
        assertEquals(1, socks.closes)
    }

    @Test fun unexpectedApiPortClosesBothListenersWithoutRetrying() {
        val socks = Listener(41000)
        val api = Listener(42000)
        var calls = 0
        assertThrows(IllegalStateException::class.java) {
            DelayProbePortAllocator.reserve { port -> calls++; if (port == 0) socks else api }
        }
        assertEquals(2, calls)
        assertEquals(1, socks.closes)
        assertEquals(1, api.closes)
    }

    @Test fun failedConfigPreparationReleasesBothReservedPorts() {
        val socks = Listener(41000)
        val api = Listener(41001)
        assertThrows(IllegalArgumentException::class.java) {
            DelayProbePortAllocator.reserve { port -> if (port == 0) socks else api }.use { pair ->
                assertEquals(0, socks.closes)
                assertEquals(0, api.closes)
                XrayCoreManager.buildDelayConfigJson("{}", pair.socksPort, File("."), LocalProxyCredentials.generate())
            }
        }
        assertEquals(1, socks.closes)
        assertEquals(1, api.closes)
    }

    @Test fun reservedPairMatchesTheDelayListenersAndPreservesTheCallerDocument() {
        val socks = Listener(41000)
        val api = Listener(41001)
        val source = JSONObject("""{
            "inbounds":[{"protocol":"socks","port":18080}],
            "API":{"tag":"proxy","listen":"127.0.0.1:18081","services":["StatsService"]},
            "Metric\u017f":{"tag":"proxy","Li\u017ften":"127.0.0.1:18082"},
            "outbounds":[{"tag":"proxy","protocol":"freedom"}]
        }""")
        val original = source.toString()
        DelayProbePortAllocator.reserve { port -> if (port == 0) socks else api }.use { pair ->
            val (runtime, selected) = XrayCoreManager.buildDelayConfigJson(original, pair.socksPort,
                File("."), LocalProxyCredentials.generate())
            assertEquals(pair.socksPort, selected)
            val inputs = runtime.getJSONArray("inbounds")
            val ports = (0 until inputs.length()).map { inputs.getJSONObject(it).getInt("port") }.toSet()
            assertEquals(setOf(pair.socksPort, pair.apiPort), ports)
            assertEquals(source.getJSONArray("outbounds").toString(), runtime.getJSONArray("outbounds").toString())
            assertEquals(original, source.toString())
            assertFalse(runtime.has("Metric\u017f"))
            assertFalse(runtime.getJSONObject("api").has("listen"))
            assertEquals(0, socks.closes)
            assertEquals(0, api.closes)
        }
        assertEquals(1, socks.closes)
        assertEquals(1, api.closes)
    }

    @Test fun apiCloseFailureStillClosesSocksAndIsNotSilentlyHidden() {
        val socks = Listener(41000)
        val error = IOException("synthetic close failure")
        val api = Listener(41001, error)
        val pair = DelayProbePortAllocator.reserve { port -> if (port == 0) socks else api }
        assertSame(error, assertThrows(IOException::class.java) { pair.close() })
        pair.close()
        assertEquals(1, socks.closes)
        assertEquals(1, api.closes)
    }
}
