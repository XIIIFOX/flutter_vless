package com.github.tfox.flutter_vless.xray.service

import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.github.tfox.flutter_vless.xray.core.AndroidTunnelDnsPolicy
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.mockito.Answers
import org.mockito.ArgumentCaptor
import org.mockito.ArgumentMatchers.anyInt
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito

/** Exercise the actual service's Builder calls without establishing a TUN. */
class AndroidIpv6CaptureTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test(timeout = 15000) fun productionTunCapturesBothFamiliesWithoutAllowFamilyBypass() {
        // A constructor-free mock avoids creating a service worker or Android lifecycle.
        val service = Mockito.mock(XrayVPNService::class.java, Answers.CALLS_REAL_METHODS)
        Mockito.doReturn(temporary.root).`when`(service).filesDir
        XrayVPNService::class.java.getDeclaredField("dnsServers").apply { isAccessible = true }
            .set(service, listOf(AndroidTunnelDnsPolicy.VIRTUAL_SERVER))
        val descriptor = Mockito.mock(ParcelFileDescriptor::class.java)
        Mockito.mockConstruction(VpnService.Builder::class.java,
            Mockito.withSettings().defaultAnswer(Answers.RETURNS_SELF)) { builder, _ ->
            Mockito.`when`(builder.establish()).thenReturn(descriptor)
        }.use { construction ->
            val profile = XrayConfig(REMARK = "Pure dual-stack capture test")
            XrayVPNService::class.java.getDeclaredMethod("setupVpn", XrayConfig::class.java)
                .apply { isAccessible = true }.invoke(service, profile)
            val builder = construction.constructed().single()
            val addresses = ArgumentCaptor.forClass(String::class.java)
            Mockito.verify(builder, Mockito.atLeastOnce()).addAddress(addresses.capture(), anyInt())
            assertTrue("TUN must own an IPv6 address before capturing IPv6", addresses.allValues.any { ':' in it })
            Mockito.verify(builder).addAddress("26.26.26.1", 30)
            Mockito.verify(builder).addRoute("0.0.0.0", 0)
            Mockito.verify(builder).addRoute("::", 0)
            Mockito.verify(builder, Mockito.never()).allowFamily(anyInt())
            Mockito.verify(builder).addDnsServer(AndroidTunnelDnsPolicy.VIRTUAL_SERVER)
            Mockito.verify(builder).setMtu(1500)
            Mockito.verify(builder).establish()
            assertEquals(1, construction.constructed().size)
        }
    }
}
