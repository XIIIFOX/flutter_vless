package com.github.tfox.flutter_vless.xray.service

import org.junit.Assert.*
import org.junit.Test

class NativeVlessOptionsTest {
    private fun parse(section: String, key: String, value: Any?) = NativeVlessOptions.parse(mapOf(section to mapOf(key to value)))
    private fun rejects(block: () -> Unit) { try { block(); fail("Expected invalid options") } catch (_: IllegalArgumentException) {} }
    @Test fun defaultsPreserveExistingProtectionAndDisableTile() {
        val o = NativeVlessOptions.parse(null)
        assertFalse(o.quickAccess.enabled); assertTrue(o.reconnect.enabled)
        assertEquals("required",o.protection.killSwitch); assertEquals("system",o.protection.alwaysOn)
        assertEquals("DISCONNECT",o.notification.buttonLabel); assertTrue(o.diagnostics.enabled)
        o.validateAndroid(23)
    }
    @Test fun allBlocksDecodeNativeWireValues() {
        val o = NativeVlessOptions.parse(mapOf("version" to 1,
            "notification" to mapOf("iconResourceType" to "drawable","iconResourceName" to "vpn_icon","buttonLabel" to "Stop","action" to "openApp"),
            "quickAccess" to mapOf("enabled" to true,"surface" to "quickTile","label" to "Private VPN","action" to "toggle","requireUnlock" to false,"androidIconResourceName" to "vpn_tile","appleSymbol" to "shield","windowsIconPath" to "C:\\icons\\vpn.ico"),
            "reconnect" to mapOf("enabled" to false,"initialDelayMs" to 200,"maxDelayMs" to 800,"maxAttempts" to 3),
            "protection" to mapOf("killSwitch" to "platformDefault","onDemand" to "disabled","alwaysOn" to "requireEnabled"),
            "diagnostics" to mapOf("enabled" to false,"maxBytes" to 4096,"maxLines" to 7)))
        assertEquals(NativeVlessOptions.Notice("drawable","vpn_icon","Stop","openApp"),o.notification)
        assertEquals(NativeVlessOptions.QuickAccess(true,"quickTile","Private VPN","toggle",false,"vpn_tile","shield","C:\\icons\\vpn.ico"),o.quickAccess)
        assertEquals(NativeVlessOptions.Reconnect(false,200,800,3),o.reconnect)
        assertEquals(NativeVlessOptions.Protection("platformDefault","disabled","requireEnabled"),o.protection)
        assertEquals(NativeVlessOptions.Diagnostics(false,4096,7),o.diagnostics)
        o.validateAndroid(34)
    }
    @Test fun backoffCapsWithoutOverflowAndRespectsAttemptLimit() {
        val r=NativeVlessOptions.Reconnect(true,200,800,3)
        assertEquals(listOf(200L,400L,800L,800L), (0..3).map(r::delay))
        assertEquals(800L,r.delay(Int.MAX_VALUE)); assertEquals(200L,r.delay(-1))
        assertTrue(r.mayRetry(2)); assertFalse(r.mayRetry(3)); assertFalse(r.copy(enabled=false).mayRetry(0))
        assertTrue(r.copy(maxAttempts=0).mayRetry(10000))
    }
    @Test fun rejectsWrongTypesAndRangesForEveryBlock() {
        for ((section,key,value) in listOf(
            Triple("notification","iconResourceType","file"),Triple("notification","iconResourceName","../bad"),Triple("notification","buttonLabel","bad\nlabel"),Triple("notification","action","callback"),
            Triple("quickAccess","enabled",1),Triple("quickAccess","surface","unknown"),Triple("quickAccess","label"," "),Triple("quickAccess","action","callback"),Triple("quickAccess","requireUnlock",0),Triple("quickAccess","androidIconResourceName","x.svg"),Triple("quickAccess","appleSymbol","\u0000"),Triple("quickAccess","windowsIconPath","relative.ico"),
            Triple("reconnect","enabled","true"),Triple("reconnect","initialDelayMs",99),Triple("reconnect","initialDelayMs",1.5),Triple("reconnect","maxDelayMs",600001),Triple("reconnect","maxAttempts",1001),
            Triple("protection","killSwitch","off"),Triple("protection","onDemand","off"),Triple("protection","alwaysOn","off"),
            Triple("diagnostics","enabled","false"),Triple("diagnostics","maxBytes",4095),Triple("diagnostics","maxLines",301))) {
            rejects { parse(section,key,value) }
        }
        rejects { NativeVlessOptions.parse(mapOf("version" to 2)) }
        rejects { NativeVlessOptions.parse(mapOf("notification" to "wrong")) }
        rejects { NativeVlessOptions.parse(mapOf("reconnect" to mapOf("enabled" to false),"protection" to mapOf("onDemand" to "enabled"))) }
    }
    @Test fun rejectsUnsupportedPlatformFeaturesBeforeStarting() {
        rejects { parse("quickAccess","enabled",true).validateAndroid(23) }
        rejects { NativeVlessOptions.parse(mapOf("quickAccess" to mapOf("enabled" to true,"surface" to "systemTray"))).validateAndroid(34) }
        rejects { parse("protection","onDemand","enabled").validateAndroid(34) }
        rejects { parse("protection","alwaysOn","requireEnabled").validateAndroid(28) }
    }
    @Test fun tilePolicyHonorsBusyPermissionAndSystemManagedStop() {
        assertEquals(QuickTilePolicy.State.UNAVAILABLE,QuickTilePolicy.state(false,true,false,false,false))
        assertEquals(QuickTilePolicy.State.UNAVAILABLE,QuickTilePolicy.state(true,false,false,false,false))
        assertEquals(QuickTilePolicy.State.ACTIVE,QuickTilePolicy.state(true,true,true,false,false))
        assertEquals(QuickTilePolicy.State.INACTIVE,QuickTilePolicy.state(true,true,false,false,false))
        assertEquals(QuickTilePolicy.Action.OPEN_APP,QuickTilePolicy.action(QuickTilePolicy.State.UNAVAILABLE,false,false))
        assertEquals(QuickTilePolicy.Action.OPEN_APP,QuickTilePolicy.action(QuickTilePolicy.State.ACTIVE,false,true))
        assertEquals(QuickTilePolicy.Action.OPEN_APP,QuickTilePolicy.action(QuickTilePolicy.State.INACTIVE,true,false))
        assertEquals(QuickTilePolicy.Action.TOGGLE,QuickTilePolicy.action(QuickTilePolicy.State.INACTIVE,false,false))
    }
}
