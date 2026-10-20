package com.github.tfox.flutter_vless

import android.app.Activity
import android.app.KeyguardManager
import android.app.StatusBarManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.service.quicksettings.TileService
import com.github.tfox.flutter_vless.xray.service.AuthorizedProfileStore
import com.github.tfox.flutter_vless.xray.service.NativeOptionsStore
import com.github.tfox.flutter_vless.xray.service.NativeVlessOptions
import com.github.tfox.flutter_vless.xray.service.QuickAccessAction
import com.github.tfox.flutter_vless.xray.service.XrayVPNService
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import io.flutter.plugin.common.MethodChannel

internal object NativeQuickAccess {
    fun locked(context: Context) = context.getSystemService(KeyguardManager::class.java).isKeyguardLocked
    fun putAction(intent: Intent, action: QuickAccessAction): Intent = intent
        .putExtra("qa_revision", action.revision).putExtra("qa_configured", action.configuredAction)
        .putExtra("qa_operation", action.operation.name).putExtra("qa_session", action.session)
        .putExtra("qa_profile", action.profile)
    fun action(intent: Intent?): QuickAccessAction? = runCatching {
        requireNotNull(intent)
        QuickAccessAction(requireNotNull(intent.getStringExtra("qa_revision")),
            requireNotNull(intent.getStringExtra("qa_configured")),
            QuickAccessAction.Operation.valueOf(requireNotNull(intent.getStringExtra("qa_operation"))),
            intent.getLongExtra("qa_session", 0), intent.getStringExtra("qa_profile"))
            .also { require(it.valid()) }
    }.getOrNull()
    fun capabilities() = mapOf(
        "optionsVersion" to 1,
        "quickAccessSurfaces" to if (Build.VERSION.SDK_INT >= 24) listOf("quickTile") else emptyList<String>(),
        "requestAddQuickTile" to (Build.VERSION.SDK_INT >= 33),
        "controlCenterExtensionConfigured" to false,
        "customReconnectBackoff" to true, "onDemand" to false,
        "alwaysOn" to (Build.VERSION.SDK_INT >= 29),
        "alwaysOnEnabled" to AppConfigs.ALWAYS_ON_ENABLED,
        "lockdownEnabled" to AppConfigs.LOCKDOWN_ENABLED, "killSwitch" to true)

    fun refresh(context: Context) {
        if (Build.VERSION.SDK_INT >= 24) runCatching {
            VlessTileService.refreshListeningInstance()
            TileService.requestListeningState(context, ComponentName(context,VlessTileService::class.java))
        }
    }
    fun profile(context: Context) = AuthorizedProfileStore(context, AuthorizedProfileStore.Kind.QUICK_ACCESS)

    fun addTile(context: Context, activity: Activity?, result: MethodChannel.Result) {
        if (Build.VERSION.SDK_INT < 33) { result.success("unsupported"); return }
        if (activity == null) { result.error("NO_ACTIVITY","Add Tile requires a foreground activity",null); return }
        val settings = NativeOptionsStore(context).read().quickAccess
        if (!settings.enabled) { result.error("QUICK_ACCESS_DISABLED","Enable QuickAccessOptions first",null); return }
        val resource = context.resources.getIdentifier(settings.androidIconResourceName,"drawable",context.packageName)
            .takeIf { it != 0 } ?: R.drawable.flutter_vless_ic_quick_tile
        try {
            activity.getSystemService(StatusBarManager::class.java).requestAddTileService(
                ComponentName(context,VlessTileService::class.java),settings.label,
                Icon.createWithResource(context,resource),activity.mainExecutor) { code ->
                    when (code) {
                        StatusBarManager.TILE_ADD_REQUEST_RESULT_TILE_ADDED -> result.success("added")
                        StatusBarManager.TILE_ADD_REQUEST_RESULT_TILE_ALREADY_ADDED -> result.success("alreadyAdded")
                        StatusBarManager.TILE_ADD_REQUEST_RESULT_TILE_NOT_ADDED -> result.success("declined")
                        else -> result.error("QUICK_TILE_REQUEST_FAILED","The system could not add the tile",code)
                    }
                }
        } catch (_: Exception) { result.error("QUICK_TILE_REQUEST_FAILED","The system could not add the tile",null) }
    }
}
