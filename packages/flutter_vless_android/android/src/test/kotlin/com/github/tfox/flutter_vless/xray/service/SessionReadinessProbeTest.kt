package com.github.tfox.flutter_vless.xray.service

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.net.Socket
import java.net.ServerSocket
import java.io.IOException
import org.mockito.Mockito

class SessionReadinessProbeTest {
    @Test fun boundProbeListenerClosesDeclaredCollisionBeforeRetainingNextCandidate() {
        val collision=Mockito.mock(ServerSocket::class.java);val accepted=Mockito.mock(ServerSocket::class.java)
        Mockito.`when`(collision.localPort).thenReturn(10807);Mockito.`when`(accepted.localPort).thenReturn(49000)
        var attempts=0
        val selected=SessionReadinessProbe.bindAvailableListener(setOf(10807)) {
            if (attempts++==0) collision else accepted.also { Mockito.verify(collision).close() }
        }
        assertEquals(2,attempts);assertSame(accepted,selected)
        Mockito.verify(accepted,Mockito.never()).close();selected.close()
    }

    @Test fun boundProbeListenerExhaustionClosesExactly32CollidingCandidates() {
        val candidates=(0 until 32).map { Mockito.mock(ServerSocket::class.java).also { socket ->
            Mockito.`when`(socket.localPort).thenReturn(10807)
        } }
        var attempts=0
        assertThrows(IllegalStateException::class.java) {
            SessionReadinessProbe.bindAvailableListener(setOf(10807)) { candidates[attempts++] }
        }
        assertEquals(32,attempts);candidates.forEach { Mockito.verify(it).close() }
    }

    @Test fun boundProbeListenerGetterAndCloseFailuresCannotSelectAnotherCandidate() {
        val getter=IllegalStateException("Synthetic bound-port getter failure")
        val cleanup=IOException("Synthetic listener close failure")
        val candidate=Mockito.mock(ServerSocket::class.java)
        Mockito.`when`(candidate.localPort).thenThrow(getter)
        Mockito.doThrow(cleanup).`when`(candidate).close()
        var attempts=0
        val failure=assertThrows(IllegalStateException::class.java) {
            SessionReadinessProbe.bindAvailableListener(emptySet()) { attempts++;candidate }
        }
        assertSame(getter,failure);assertSame(cleanup,failure.suppressed.single());assertEquals(1,attempts)
        val collision=Mockito.mock(ServerSocket::class.java)
        Mockito.`when`(collision.localPort).thenReturn(10807);Mockito.doThrow(cleanup).`when`(collision).close()
        attempts=0
        assertSame(cleanup,assertThrows(IOException::class.java) {
            SessionReadinessProbe.bindAvailableListener(setOf(10807)) { attempts++;collision }
        })
        assertEquals(1,attempts)
    }

    @Test fun probePreservesDefaultOutboundAndUserRulesAndCannotBeStalledByIdleClients() {
        val source = JSONObject("""{"inbounds":[{"tag":"fixture-tun","protocol":"socks","listen":"127.0.0.1","port":19000}],"outbounds":[{"protocol":"blackhole","tag":"block"}],"routing":{"rules":[{"domain":["full:www.gstatic.com"],"outboundTag":"block"}]}}""")
        val original = source.toString()
        SessionReadinessProbe(SessionReadinessProbe.selectHost(source)).use { probe ->
            val runtime = probe.configure(source, 19000)
            assertEquals(original, source.toString())
            assertEquals("block", runtime.getJSONArray("outbounds").getJSONObject(0).getString("tag"))
            val rules = runtime.getJSONObject("routing").getJSONArray("rules")
            assertEquals(source.getJSONObject("routing").getJSONArray("rules").get(0).toString(), rules.get(1).toString())
            assertEquals("${probe.host}/32", rules.getJSONObject(0).getJSONArray("ip").getString(0))
            assertEquals("fixture-tun", rules.getJSONObject(0).getJSONArray("inboundTag").getString(0))
            assertThrows(NoSuchElementException::class.java) { probe.configure(source, 19001) }
            probe.verify { Socket("127.0.0.1", probe.port) }
            Socket("127.0.0.1", probe.port).use { idle ->
                idle.soTimeout = 2000
                probe.verify { Socket("127.0.0.1", probe.port) }
                probe.close()
                assertEquals(36, idle.getInputStream().readBytes().size)
            }
        }
    }

    @Test(expected = IllegalStateException::class)
    fun rejectsFakeDnsCoveringAllUnicastAddresses() {
        SessionReadinessProbe.selectHost(JSONObject("""{"fakedns":[{"ipPool":"0.0.0.0/0"}]}"""))
    }

    @Test fun avoidsDefaultAndCustomFakeDnsPoolsWithoutChangingSniffing() {
        val config = JSONObject("""{"FakeDnſ":[{"ipPool":"198.51.100.0/24"},{"ipPool":"2001:db8::/32"}]}""")
        assertEquals("198.51.101.0", SessionReadinessProbe.selectHost(config))
        assertEquals("198.51.100.1", SessionReadinessProbe.selectHost(JSONObject()))
    }
}
