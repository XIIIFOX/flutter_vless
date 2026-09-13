package com.github.tfox.flutter_vless.xray.service

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.net.Socket

class SessionReadinessProbeTest {
    @Test fun probePreservesDefaultOutboundAndUserRulesAndCannotBeStalledByIdleClients() {
        val source = JSONObject("""{"outbounds":[{"protocol":"blackhole","tag":"block"}],"routing":{"rules":[{"domain":["full:www.gstatic.com"],"outboundTag":"block"}]}}""")
        val original = source.toString()
        SessionReadinessProbe(SessionReadinessProbe.selectHost(source)).use { probe ->
            val runtime = probe.configure(source)
            assertEquals(original, source.toString())
            assertEquals("block", runtime.getJSONArray("outbounds").getJSONObject(0).getString("tag"))
            val rules = runtime.getJSONObject("routing").getJSONArray("rules")
            assertEquals(source.getJSONObject("routing").getJSONArray("rules").get(0).toString(), rules.get(1).toString())
            assertEquals("${probe.host}/32", rules.getJSONObject(0).getJSONArray("ip").getString(0))
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
