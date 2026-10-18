package com.github.tfox.flutter_vless.xray.service

import android.app.ActivityManager
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.github.tfox.flutter_vless.xray.core.XrayCoreManager
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import com.github.tfox.flutter_vless.R
import com.google.gson.Gson
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.TimeUnit

/** Real SystemUI tile/native workers; never creates a Flutter engine. */
@RunWith(AndroidJUnit4::class)
class NativeQuickTileDeviceTest {
    private val instrumentation=InstrumentationRegistry.getInstrumentation()
    private val context=instrumentation.targetContext
    private val component="${context.packageName}/com.github.tfox.flutter_vless.VlessTileService"
    private fun shell(command:String)=instrumentation.uiAutomation.executeShellCommand(command).use { android.os.ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText() }
    private fun captured()=context.getSystemService(ConnectivityManager::class.java).getNetworkCapabilities(context.getSystemService(ConnectivityManager::class.java).activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true
    private fun snapshot()=XrayCoreManager.getProviderDebugSnapshot(context)
    private fun tileState(state: Int, subtitle: String): Boolean =
        shell("dumpsys activity service com.android.systemui/.SystemUIService QSTileHost")
            .lineSequence().any { it.contains("spec=custom($component),") &&
                it.contains(",state=$state,") && it.contains(",secondaryLabel=$subtitle,") }
    private fun addConnectedTile() {
        shell("cmd statusbar add-tile $component")
        await("SystemUI tile reports current connection") {
            tileState(2, context.getString(R.string.flutter_vless_tile_connected))
        }
    }
    private fun await(description:String, predicate:()->Boolean) {
        val end=System.nanoTime()+TimeUnit.SECONDS.toNanos(45)
        while(System.nanoTime()<end) { if(predicate())return; Thread.sleep(100) }
        fail("$description; ${snapshot()}")
    }
    private fun start(options:NativeVlessOptions) {
        check(Build.HARDWARE in setOf("ranchu","goldfish"))
        assertNull(VpnService.prepare(context)); NativeOptionsStore(context).write(options)
        context.startForegroundService(Intent(context,XrayVPNService::class.java)
            .putExtra("COMMAND",AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE)
            .putExtra("V2RAY_CONFIG",XrayConfig(REMARK="Tile fixture",V2RAY_FULL_JSON_CONFIG="""{"inbounds":[],"outbounds":[{"tag":"proxy","protocol":"socks","settings":{"address":"10.0.2.2","port":18080}}]}""",PLUGIN_OPTIONS_JSON=Gson().toJson(options))))
        await("initial native connection") { captured() && snapshot().contains("CONNECTED") }
    }
    private fun cleanup() {
        context.startService(Intent(context,XrayVPNService::class.java).putExtra("COMMAND",AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE))
        await("stop fixture") { !captured() }
        shell("cmd statusbar remove-tile $component")
        AuthorizedProfileStore(context).disarm(); AuthorizedProfileStore(context,AuthorizedProfileStore.Kind.QUICK_ACCESS).disarm()
        NativeOptionsStore(context).write(NativeVlessOptions())
    }
    @Test fun systemTileStopsAndColdStartsFromEncryptedProfileWithoutFlutter() {
        try {
            start(NativeVlessOptions(quickAccess=NativeVlessOptions.QuickAccess(enabled=true,requireUnlock=false)))
            assertTrue(AuthorizedProfileStore(context,AuthorizedProfileStore.Kind.QUICK_ACCESS).exists())
            addConnectedTile()
            shell("cmd statusbar click-tile $component")
            await("SystemUI tile disconnect") { !captured() && !AuthorizedProfileStore(context).exists() }
            assertTrue(AuthorizedProfileStore(context,AuthorizedProfileStore.Kind.QUICK_ACCESS).exists())
            context.getSystemService(ActivityManager::class.java).runningAppProcesses.firstOrNull { it.processName=="${context.packageName}:RunSoLibXrayDaemon" }?.let { daemon ->
                android.os.Process.killProcess(daemon.pid)
                await("old native daemon exited") {
                    context.getSystemService(ActivityManager::class.java).runningAppProcesses.none { it.pid == daemon.pid }
                }
            }
            await("SystemUI tile reports stopped native session") {
                tileState(1, context.getString(R.string.flutter_vless_tile_disconnected))
            }
            shell("cmd statusbar click-tile $component")
            await("SystemUI cold tile reconnect") { captured() && snapshot().contains("CONNECTED") }
            context.startService(Intent(context,XrayVPNService::class.java).setAction(XrayVPNService.ACTION_CLEAR_QUICK_ACCESS))
            await("clear retained profile") { !AuthorizedProfileStore(context,AuthorizedProfileStore.Kind.QUICK_ACCESS).exists() }
            assertTrue("Forget must leave the active tunnel alone",captured())
        } finally { cleanup() }
    }
    @Test fun systemTileStopsRetainedProtectionDuringWorkerRecovery() {
        try {
            start(NativeVlessOptions(
                quickAccess=NativeVlessOptions.QuickAccess(enabled=true,requireUnlock=false),
                reconnect=NativeVlessOptions.Reconnect(enabled=true,initialDelayMs=15000,maxDelayMs=15000,maxAttempts=1)))
            addConnectedTile()
            assertEquals(0,ProcessBuilder("pkill","-9","-x","libxray.so").start().waitFor())
            await("worker loss with captured protection") { captured() && snapshot().contains("WORKER_EXIT") }
            await("SystemUI tile reports cancellable recovery") {
                tileState(2, context.getString(R.string.flutter_vless_tile_connecting))
            }
            assertTrue("Recovery must retain TUN protection", captured())
            assertTrue(AuthorizedProfileStore(context).exists())
            shell("cmd statusbar click-tile $component") // Exactly one click during backoff.
            await("SystemUI tile stops recovery and disarms authorization") {
                !captured() && !AuthorizedProfileStore(context).exists()
            }
            assertTrue(AuthorizedProfileStore(context,AuthorizedProfileStore.Kind.QUICK_ACCESS).exists())
            assertFalse(shell("ps -A -o NAME").lineSequence().any { it.trim() == "libxray.so" })
            await("SystemUI tile reports stopped recovery") {
                tileState(1, context.getString(R.string.flutter_vless_tile_disconnected))
            }
        } finally { cleanup() }
    }
    @Test fun disabledAutoReconnectRetainsCaptureAndDoesNotRestartKilledWorkers() {
        try {
            start(NativeVlessOptions(reconnect=NativeVlessOptions.Reconnect(enabled=false)))
            assertEquals(0,ProcessBuilder("pkill","-9","-x","libxray.so").start().waitFor())
            await("worker loss") { snapshot().contains("WORKER_EXIT") }
            Thread.sleep(2500)
            assertTrue("Protection must remain after retry is disabled",captured())
            val text=shell("ps -A -o NAME")
            assertFalse("Xray must not be restarted",text.lineSequence().any { it.trim()=="libxray.so" })
        } finally { cleanup() }
    }
}
