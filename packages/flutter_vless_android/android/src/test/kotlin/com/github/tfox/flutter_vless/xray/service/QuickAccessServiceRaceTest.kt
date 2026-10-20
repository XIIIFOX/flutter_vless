package com.github.tfox.flutter_vless.xray.service

import android.app.KeyguardManager
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import org.junit.Assert.*
import org.junit.Test
import org.mockito.Answers
import org.mockito.Mockito
import java.util.concurrent.atomic.AtomicLong

/** Actual request revoke and final native launch admission. launch itself is an inert lambda. */
class QuickAccessServiceRaceTest {
    private fun field(name:String)=XrayVPNService::class.java.getDeclaredField(name).apply {isAccessible=true}
    private fun anyAction():QuickAccessAction {Mockito.any(QuickAccessAction::class.java);return QuickAccessAction("a".repeat(32),"openApp",QuickAccessAction.Operation.OPEN)}
    private fun anyLocked():()->Boolean {Mockito.any<()->Boolean>();return {false}}
    private fun anyBody():(NativeVlessOptions)->Process {Mockito.any<(NativeVlessOptions)->Process>();return {error("unreachable")}}
    private fun anyWork():()->Unit {Mockito.any<()->Unit>();return {}}
    private val options=NativeVlessOptions(quickAccess=NativeVlessOptions.QuickAccess(enabled=true))
    private val action=QuickAccessAction("a".repeat(32),"toggle",QuickAccessAction.Operation.START,profile="b".repeat(64))
    @Test fun disableRevokesOnlyPendingTileRequestBeforeQueuedCleanup() {
        val service=Mockito.mock(XrayVPNService::class.java,Answers.CALLS_REAL_METHODS)
        val requests=AtomicLong(10);val pending=PendingQuickStart(10,action)
        val queue=Mockito.mock(SessionWorkQueue::class.java);val jobs=mutableListOf<()->Unit>()
        Mockito.doAnswer {jobs+=it.getArgument<()->Unit>(0);true}.`when`(queue).execute(anyWork())
        field("requests").set(service,requests);field("pendingQuickStart").set(service,pending);field("worker").set(service,queue)
        service.revokePendingQuickStart()
        assertEquals(11L,requests.get());assertSame(pending,field("pendingQuickStart").get(service));assertEquals(1,jobs.size)
        // A later explicit app Start owns request 12; replaying old CLEAR must not increment it.
        requests.set(12);service.revokePendingQuickStart();assertEquals(12L,requests.get())
        val replacement=PendingQuickStart(12,action)
        field("pendingQuickStart").set(service,replacement)
        jobs.forEach {it()}
        assertSame(replacement,field("pendingQuickStart").get(service))
    }
    @Test fun actualStopAdmissionRejectsReplacedOwnerAndRevokesOnlyMatchingOwner() {
        val service=Mockito.mock(XrayVPNService::class.java,Answers.CALLS_REAL_METHODS)
        val requests=AtomicLong(10);val recovery=SessionRecoveryPolicy()
        val oldOwner=recovery.activate();val newOwner=recovery.activate()
        val guard=Mockito.mock(KeyguardManager::class.java)
        Mockito.doReturn(guard).`when`(service).getSystemService(KeyguardManager::class.java)
        field("requests").set(service,requests);field("recovery").set(service,recovery)
        Mockito.mockConstruction(NativeOptionsStore::class.java,Mockito.withSettings().defaultAnswer {call ->
            if(call.method.name=="withSnapshot") call.getArgument<(NativeVlessOptions)->Any?>(2)(options)
            else Answers.RETURNS_DEFAULTS.answer(call)
        }).use {
            assertNull(service.acceptQuickStop(action.copy(operation=QuickAccessAction.Operation.STOP,session=oldOwner,profile=null)))
            assertEquals(10L,requests.get());assertTrue(recovery.owns(newOwner))
            assertEquals(11L,service.acceptQuickStop(action.copy(operation=QuickAccessAction.Operation.STOP,session=newOwner,profile=null)))
            assertFalse(recovery.authorized)
        }
    }
    @Test fun finalLaunchGateRefusesChangedPolicyWithoutExecutingProcessFactory() {
        val service=Mockito.mock(XrayVPNService::class.java,Answers.CALLS_REAL_METHODS)
        val recovery=SessionRecoveryPolicy();val owner=recovery.activate()
        val pending=PendingQuickStart(10,action).also {it.owner=owner}
        val guard=Mockito.mock(KeyguardManager::class.java)
        Mockito.doReturn(guard).`when`(service).getSystemService(KeyguardManager::class.java)
        field("requests").set(service,AtomicLong(10));field("pendingQuickStart").set(service,pending);field("recovery").set(service,recovery)
        var launches=0
        Mockito.mockConstruction(NativeOptionsStore::class.java) {store,_ ->
            // Actual withSnapshot failure result: the newly persisted policy has a different revision.
            Mockito.doReturn(null).`when`(store).withSnapshot(anyAction(),anyLocked(),anyBody())
        }.use {
            assertThrows(IllegalStateException::class.java) {service.launchQuickStart(pending,owner) {launches++;Mockito.mock(Process::class.java)}}
            assertEquals(0,launches);assertSame(pending,field("pendingQuickStart").get(service));assertTrue(recovery.owns(owner))
        }
    }
    @Test fun actualLaunchThrowRetainsTicketThenDiscardsOnlyItsUnstartedRecovery() {
        val directory=java.nio.file.Files.createTempDirectory("quick-launch-refusal").toFile()
        val service=Mockito.mock(XrayVPNService::class.java,Answers.CALLS_REAL_METHODS)
        Mockito.doReturn(directory).`when`(service).filesDir
        Mockito.doReturn(directory).`when`(service).noBackupFilesDir
        val recovery=SessionRecoveryPolicy();val owner=recovery.activate()
        val pending=PendingQuickStart(10,action).also {it.owner=owner;it.persisted=true}
        val guard=Mockito.mock(KeyguardManager::class.java)
        Mockito.doReturn(guard).`when`(service).getSystemService(KeyguardManager::class.java)
        val profiles=Mockito.mock(AuthorizedProfileStore::class.java)
        field("requests").set(service,AtomicLong(10));field("pendingQuickStart").set(service,pending)
        field("recovery").set(service,recovery);field("profiles").set(service,profiles)
        val manager=com.github.tfox.flutter_vless.xray.core.XrayCoreManager
        val members=listOf("xrayProcess","runtimeInputs","lastProxyUplink","lastProxyDownlink").associateWith {
            manager.javaClass.getDeclaredField(it).apply {isAccessible=true}
        }
        val before=members.mapValues {it.value.get(manager)}
        val state=AppConfigs.V2RAY_STATE
        try {
            members.values.forEach {it.set(manager,null)}
            Mockito.mockConstruction(NativeOptionsStore::class.java,Mockito.withSettings().defaultAnswer {call ->
                if(call.method.name=="withSnapshot") call.getArgument<(NativeVlessOptions)->Any?>(2)(options)
                else Answers.RETURNS_DEFAULTS.answer(call)
            }).use {
                val failure=IllegalStateException("synthetic launch refused")
                assertSame(failure,assertThrows(IllegalStateException::class.java) {
                    service.launchQuickStart(pending,owner) {throw failure}
                })
                assertSame("A launch throw cannot consume the ticket",pending,field("pendingQuickStart").get(service))
                Mockito.mockConstruction(android.content.Intent::class.java,Mockito.withSettings().defaultAnswer {call ->
                    if(call.method.returnType==android.content.Intent::class.java) call.mock else Answers.RETURNS_DEFAULTS.answer(call)
                }).use {
                    // Actual common recover path must NOT advance generation/schedule an unowned retry before launch.
                    val worker=Mockito.mock(SessionWorkQueue::class.java);field("worker").set(service,worker)
                    val event=com.github.tfox.flutter_vless.xray.core.XrayDiagnosticsStore.Event.WORKER_START_FAILED
                    XrayVPNService::class.java.getDeclaredMethod("recover",event.javaClass,java.lang.Long::class.java)
                        .apply {isAccessible=true}.invoke(service,event,null)
                    assertEquals(0,Mockito.mockingDetails(worker).invocations.size)
                }
                assertFalse("No retry authorization remains after an unstarted tile failure",recovery.authorized)
                assertNull(field("pendingQuickStart").get(service))
                Mockito.verify(profiles).disarm()
                assertNull(field("pendingRuntime").get(service))
            }
        } finally {
            members.forEach {(name,member)->member.set(manager,before[name])}
            AppConfigs.V2RAY_STATE=state;directory.deleteRecursively()
        }
    }
    @Test fun finalGateRechecksOwnerAndStableLaunchConsumesOnlyItsTicket() {
        for (stale in listOf(false,true)) {
            val service=Mockito.mock(XrayVPNService::class.java,Answers.CALLS_REAL_METHODS)
            val recovery=SessionRecoveryPolicy();val owner=recovery.activate()
            val pending=PendingQuickStart(10,action).also {it.owner=owner}
            val guard=Mockito.mock(KeyguardManager::class.java)
            Mockito.doReturn(guard).`when`(service).getSystemService(KeyguardManager::class.java)
            field("requests").set(service,AtomicLong(if(stale)11 else 10));field("pendingQuickStart").set(service,pending);field("recovery").set(service,recovery)
            var launches=0;val process=Mockito.mock(Process::class.java)
            Mockito.mockConstruction(NativeOptionsStore::class.java) {store,_ ->
                Mockito.doAnswer {it.getArgument<(NativeVlessOptions)->Process>(2)(options)}.`when`(store)
                    .withSnapshot(anyAction(),anyLocked(),anyBody())
            }.use {
                if(stale) assertThrows(IllegalStateException::class.java) {service.launchQuickStart(pending,owner) {launches++;process}}
                else assertSame(process,service.launchQuickStart(pending,owner) {assertSame(pending,field("pendingQuickStart").get(service));launches++;process})
                assertEquals(if(stale)0 else 1,launches)
                assertEquals(!stale,field("pendingQuickStart").get(service)==null)
                assertTrue("Policy disable after admitted launch does not disarm established protection",recovery.owns(owner))
            }
        }
    }
}
