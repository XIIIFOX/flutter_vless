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
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.TimeUnit

/** Partial dumps cannot prove an asynchronous tile/binding is absent. */
private fun completeTileLifecycleDump(text: String, header: String): Boolean {
    val lower = text.lowercase(java.util.Locale.ROOT)
    return text.lineSequence().any { it.trim() == header } &&
        !text.endsWith("<truncated>") &&
        listOf("timeout", "timed out", "exception", "error dumping", "permission denial", "can't find service")
            .none { lower.contains(it) }
}

/** Real SystemUI tile/native workers; never creates a Flutter engine. */
@RunWith(AndroidJUnit4::class)
class NativeQuickTileDeviceTest {
    private val instrumentation=InstrumentationRegistry.getInstrumentation()
    private val context=instrumentation.targetContext
    private val component="${context.packageName}/com.github.tfox.flutter_vless.VlessTileService"
    private var lastTileDump = "not observed"
    private var lastTileServiceDump = "not observed"
    private var completeTileDump = false
    private fun shell(command:String, limit:Int=32768)=instrumentation.uiAutomation.executeShellCommand(command).use {
        android.os.ParcelFileDescriptor.AutoCloseInputStream(it).use { input ->
            val output=java.io.ByteArrayOutputStream()
            val buffer=ByteArray(1024)
            while(output.size()<=limit) {
                val count=input.read(buffer,0,minOf(buffer.size,limit+1-output.size()))
                if(count<0)break
                output.write(buffer,0,count)
            }
            val bytes=output.toByteArray()
            String(bytes,0,minOf(bytes.size,limit),Charsets.UTF_8)+if(bytes.size>limit)"\n<truncated>" else ""
        }
    }
    private fun captured()=context.getSystemService(ConnectivityManager::class.java).getNetworkCapabilities(context.getSystemService(ConnectivityManager::class.java).activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true
    private fun snapshot()=XrayCoreManager.getProviderDebugSnapshot(context)
    private fun tileLines():List<String> {
        lastTileDump=shell("dumpsys -t 3 activity service com.android.systemui/.SystemUIService QSTileHost")
        completeTileDump=completeTileLifecycleDump(lastTileDump,"QSTileHost:")
        return lastTileDump.lineSequence().filter { it.contains("spec=custom($component),") }.toList()
    }
    private fun tileState(state: Int, subtitle: String): Boolean =
        tileLines().any { it.contains(",state=$state,") &&
                it.contains(",secondaryLabel=$subtitle,") }
    private fun tileServiceGone():Boolean {
        lastTileServiceDump=shell("dumpsys -t 3 activity services $component")
        return completeTileLifecycleDump(lastTileServiceDump,"ACTIVITY MANAGER SERVICES (dumpsys activity services)") &&
            lastTileServiceDump.lineSequence().none { it.contains("ServiceRecord{") && it.contains("VlessTileService") }
    }
    private fun awaitRemovedTile() = await("SystemUI removed fixture tile and released its old binding") {
        tileLines().isEmpty() && completeTileDump && tileServiceGone()
    }
    @Before fun initialTileLifecycleIsEmpty() {
        shell("cmd statusbar remove-tile $component")
        awaitRemovedTile()
    }
    private fun addConnectedTile() {
        // Shell statusbar commands enqueue work in SystemUI. A returned command
        // does not mean the previous CustomTile/binding has been disposed.
        awaitRemovedTile()
        shell("cmd statusbar add-tile $component")
        await("SystemUI tile reports current connection") {
            tileState(2, context.getString(R.string.flutter_vless_tile_connected))
        }
    }
    private fun await(description:String, predicate:()->Boolean) {
        val end=System.nanoTime()+TimeUnit.SECONDS.toNanos(45)
        while(System.nanoTime()<end) { if(predicate())return; Thread.sleep(100) }
        // Preserve the actual presentation/lifecycle before the caller's finally
        // removes the tile and destroys the evidence. Never retry a tile click.
        val beforeCleanup=shell("dumpsys -t 3 activity service com.android.systemui/.SystemUIService QSTileHost",8192)
        val qsLog=shell("dumpsys -t 3 activity service com.android.systemui/.SystemUIService QSLog",16384)
        fail("$description; ${snapshot()}; lastTile=$lastTileDump; lastService=$lastTileServiceDump; preCleanupTile=$beforeCleanup; preCleanupQSLog=$qsLog")
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
        awaitRemovedTile()
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
