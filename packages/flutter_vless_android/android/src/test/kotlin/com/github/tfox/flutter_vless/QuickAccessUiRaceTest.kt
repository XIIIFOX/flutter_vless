package com.github.tfox.flutter_vless

import android.app.KeyguardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import com.github.tfox.flutter_vless.xray.service.*
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import org.junit.Assert.*
import org.junit.Test
import org.mockito.Answers
import org.mockito.Mockito
import java.lang.reflect.InvocationTargetException

/** Actual delayed tile callback / permission continuation; Android dispatch is entirely mocked. */
class QuickAccessUiRaceTest {
    private val revision="a".repeat(32)
    private val profile="b".repeat(64)
    private val enabled=NativeVlessOptions(quickAccess=NativeVlessOptions.QuickAccess(enabled=true,requireUnlock=true))
    private fun anyRunnable(): Runnable { Mockito.any(Runnable::class.java); return Runnable {} }
    private fun permissionResult(activity: VlessTilePermissionActivity, requestCode: Int, resultCode: Int, data: Intent?) {
        try {
            VlessTilePermissionActivity::class.java.getDeclaredMethod("onActivityResult",
                java.lang.Integer.TYPE, java.lang.Integer.TYPE, Intent::class.java)
                .apply { isAccessible = true }.invoke(activity, requestCode, resultCode, data)
        } catch (error: InvocationTargetException) { throw error.targetException }
    }
    private fun intent(ticket: QuickAccessAction): Intent = Mockito.mock(Intent::class.java).also {
        Mockito.`when`(it.getStringExtra("qa_revision")).thenReturn(ticket.revision)
        Mockito.`when`(it.getStringExtra("qa_configured")).thenReturn(ticket.configuredAction)
        Mockito.`when`(it.getStringExtra("qa_operation")).thenReturn(ticket.operation.name)
        Mockito.`when`(it.getLongExtra("qa_session",0)).thenReturn(ticket.session)
        Mockito.`when`(it.getStringExtra("qa_profile")).thenReturn(ticket.profile)
    }
    @Test fun actualUnlockCallbackCannotUseAChangedDisabledOrStrongerPolicy() {
        val previous=AppConfigs.V2RAY_STATE
        AppConfigs.V2RAY_STATE=AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED
        val currentRecovery=XrayVPNService::class.java.getDeclaredField("currentRecovery").apply { isAccessible=true }
        val old=currentRecovery.get(null);currentRecovery.set(null,null)
        try {
            for (replacement in listOf(
                enabled.copy(quickAccess=enabled.quickAccess.copy(enabled=false)),
                enabled.copy(quickAccess=enabled.quickAccess.copy(action="openApp")),
                enabled)) {
                var snapshot=QuickAccessSnapshot(enabled,revision)
                val service=Mockito.mock(VlessTileService::class.java,Answers.CALLS_REAL_METHODS)
                val keyguard=Mockito.mock(KeyguardManager::class.java)
                Mockito.doReturn(keyguard).`when`(service).getSystemService(KeyguardManager::class.java)
                Mockito.`when`(keyguard.isKeyguardLocked).thenReturn(false)
                Mockito.doReturn(true).`when`(service).isLocked
                var waiting: Runnable?=null
                Mockito.doAnswer { waiting=it.getArgument(0); null }.`when`(service).unlockAndRun(anyRunnable())
                Mockito.mockConstruction(NativeOptionsStore::class.java) { store,_ ->
                    Mockito.`when`(store.readSnapshot()).thenAnswer { snapshot }
                    Mockito.`when`(store.beginAction()).thenAnswer { snapshot }
                    Mockito.`when`(store.read()).thenAnswer { snapshot.options }
                }.use {
                Mockito.mockConstruction(AuthorizedProfileStore::class.java) { store,_ ->
                    Mockito.`when`(store.exists()).thenReturn(true)
                    Mockito.`when`(store.revision()).thenReturn(profile)
                }.use {
                    service.onClick()
                    assertNotNull("Actual onClick must wait for unlock",waiting)
                    snapshot=QuickAccessSnapshot(replacement,"c".repeat(32))
                    waiting!!.run()
                    assertEquals(0,Mockito.mockingDetails(service).invocations.count {
                        it.method.name in listOf("startService","startForegroundService","startActivityAndCollapse") })
                } }
            }
        } finally { currentRecovery.set(null,old);AppConfigs.V2RAY_STATE=previous }
    }
    @Test fun unchangedOpenAppRemainsOpenAndNeverBecomesToggle() {
        val service=Mockito.mock(VlessTileService::class.java,Answers.CALLS_REAL_METHODS)
        val keyguard=Mockito.mock(KeyguardManager::class.java)
        val packages=Mockito.mock(PackageManager::class.java)
        Mockito.doReturn(keyguard).`when`(service).getSystemService(KeyguardManager::class.java)
        Mockito.doReturn(packages).`when`(service).packageManager
        Mockito.doReturn("synthetic.package").`when`(service).packageName
        val options=enabled.copy(quickAccess=enabled.quickAccess.copy(action="openApp"))
        Mockito.mockConstruction(NativeOptionsStore::class.java) { store,_ ->
            Mockito.`when`(store.readSnapshot()).thenReturn(QuickAccessSnapshot(options,revision))
        }.use {
            service.performAction(QuickAccessAction(revision,"openApp",QuickAccessAction.Operation.OPEN))
            Mockito.verify(packages).getLaunchIntentForPackage("synthetic.package")
            assertEquals(0,Mockito.mockingDetails(service).invocations.count { it.method.name in listOf("startService","startForegroundService") })
        }
    }
    @Test fun oldStopCannotStopNewlyAcceptedSessionAfterUnlock() {
        val oldState=AppConfigs.V2RAY_STATE
        val current=XrayVPNService::class.java.getDeclaredField("currentRecovery").apply {isAccessible=true}
        val old=current.get(null)
        val recovery=SessionRecoveryPolicy();val oldOwner=recovery.activate();recovery.activate()
        current.set(null,recovery)
        val tile=Mockito.mock(VlessTileService::class.java,Answers.CALLS_REAL_METHODS)
        val guard=Mockito.mock(KeyguardManager::class.java)
        Mockito.doReturn(guard).`when`(tile).getSystemService(KeyguardManager::class.java)
        try {
            Mockito.mockConstruction(NativeOptionsStore::class.java) {store,_ ->
                Mockito.`when`(store.readSnapshot()).thenReturn(QuickAccessSnapshot(enabled,revision))
            }.use {
                tile.performAction(QuickAccessAction(revision,"toggle",QuickAccessAction.Operation.STOP,session=oldOwner))
                assertTrue(recovery.authorized)
                assertEquals(0,Mockito.mockingDetails(tile).invocations.count {it.method.name in listOf("startService","startForegroundService")})
            }
        } finally {current.set(null,old);AppConfigs.V2RAY_STATE=oldState}
    }
    @Test fun actualPermissionResultRejectsDisabledRetargetedAndUnlockUpgradedRequests() {
        val ticket=QuickAccessAction(revision,"toggle",QuickAccessAction.Operation.START,profile=profile)
        for (changed in listOf(enabled.copy(quickAccess=enabled.quickAccess.copy(enabled=false)),
            enabled.copy(quickAccess=enabled.quickAccess.copy(action="openApp")),enabled)) {
            val activity=Mockito.mock(VlessTilePermissionActivity::class.java,Answers.CALLS_REAL_METHODS)
            Mockito.doReturn(intent(ticket)).`when`(activity).intent
            val guard=Mockito.mock(KeyguardManager::class.java)
            Mockito.doReturn(guard).`when`(activity).getSystemService(KeyguardManager::class.java)
            Mockito.`when`(guard.isKeyguardLocked).thenReturn(true)
            Mockito.mockConstruction(NativeOptionsStore::class.java) { store,_ ->
                Mockito.`when`(store.readSnapshot()).thenReturn(QuickAccessSnapshot(changed,"c".repeat(32)))
            }.use {
                permissionResult(activity,24,android.app.Activity.RESULT_OK,null)
                Mockito.verify(activity).finish()
                assertEquals(0,Mockito.mockingDetails(activity).invocations.count { it.method.name in listOf("startService","startForegroundService") })
            }
        }
    }
    @Test fun permissionContinuationPreservesExactUnchangedTicket() {
        val recoveryField=XrayVPNService::class.java.getDeclaredField("currentRecovery").apply {isAccessible=true}
        val previous=recoveryField.get(null);recoveryField.set(null,null)
        val activity=Mockito.mock(VlessTilePermissionActivity::class.java,Answers.CALLS_REAL_METHODS)
        val ticket=QuickAccessAction(revision,"toggle",QuickAccessAction.Operation.START,profile=profile)
        Mockito.doReturn(intent(ticket)).`when`(activity).intent
        val keyguard=Mockito.mock(KeyguardManager::class.java)
        Mockito.doReturn(keyguard).`when`(activity).getSystemService(KeyguardManager::class.java)
        try {
            Mockito.mockConstruction(NativeOptionsStore::class.java) {store,_ ->
                Mockito.`when`(store.readSnapshot()).thenReturn(QuickAccessSnapshot(enabled,revision))
            }.use {
            Mockito.mockConstruction(AuthorizedProfileStore::class.java) {store,_ -> Mockito.`when`(store.revision()).thenReturn(profile) }.use {
            Mockito.mockStatic(VpnService::class.java).use { permission ->
                permission.`when`<Intent?> { VpnService.prepare(activity) }.thenReturn(null)
                Mockito.mockConstruction(Intent::class.java) { out,_ ->
                    Mockito.`when`(out.setAction(Mockito.anyString())).thenReturn(out)
                    Mockito.`when`(out.putExtra(Mockito.anyString(),Mockito.nullable(String::class.java))).thenReturn(out)
                    Mockito.`when`(out.putExtra(Mockito.anyString(),Mockito.anyLong())).thenReturn(out)
                }.use { intents ->
                    permissionResult(activity,24,android.app.Activity.RESULT_OK,null)
                    val sent=intents.constructed().single()
                    Mockito.verify(sent).putExtra("qa_revision",revision)
                    Mockito.verify(sent).putExtra("qa_profile",profile)
                    Mockito.verify(sent).putExtra("qa_operation","START")
                    assertEquals(1,Mockito.mockingDetails(activity).invocations.count { it.method.name in listOf("startService","startForegroundService") })
                }
            } } }
        } finally { recoveryField.set(null,previous) }
    }
}
