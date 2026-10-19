package com.github.tfox.flutter_vless.xray.service

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkRequest
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import org.mockito.Answers
import org.mockito.Mockito
import java.nio.file.Files
import java.util.concurrent.TimeUnit

/** Exercises the callback registered by onCreate; no real worker, process, socket or Android service. */
@RunWith(Parameterized::class)
class NetworkCallbackOwnershipTest(private val available: Boolean) {
    companion object {
        @JvmStatic @Parameterized.Parameters(name = "available={0}")
        fun events() = listOf(arrayOf(true), arrayOf(false))
    }

    private class Fixture(
        val service: XrayVPNService,
        val recovery: SessionRecoveryPolicy,
        val pending: MutableList<() -> Unit>,
        val child: Process,
        val callback: ConnectivityManager.NetworkCallback,
        val stopReached: IllegalStateException
    ) {
        fun enqueue(available: Boolean) {
            val network = Mockito.mock(Network::class.java)
            if (available) callback.onAvailable(network) else callback.onLost(network)
            assertEquals("Actual registered callback must enqueue exactly one task", 1, pending.size)
        }
        fun deliver(): Result<Unit> = runCatching { pending.removeAt(0).invoke() }
    }

    private fun set(service: XrayVPNService, name: String, value: Any?) =
        XrayVPNService::class.java.getDeclaredField(name).apply { isAccessible = true }.set(service, value)

    private fun fixture(body: (Fixture) -> Unit) {
        val directory = Files.createTempDirectory("network-callback-ownership").toFile()
        val service = Mockito.mock(XrayVPNService::class.java, Answers.CALLS_REAL_METHODS)
        val recovery = SessionRecoveryPolicy().apply { activate() }
        val pending = mutableListOf<() -> Unit>()
        val worker = Mockito.mock(SessionWorkQueue::class.java)
        Mockito.doAnswer { invocation -> pending.add(invocation.getArgument(0)); true }
            .`when`(worker).execute(anyAction())
        val child = Mockito.mock(Process::class.java)
        // The real recovery path reaches destroy before this inert boundary;
        // it must never proceed to global Core state, foreground work or retries.
        val stopReached = IllegalStateException("Synthetic owned worker stop reached")
        Mockito.doThrow(stopReached).`when`(child).waitFor(1L, TimeUnit.SECONDS)
        val manager = Mockito.mock(ConnectivityManager::class.java)
        Mockito.doReturn(manager).`when`(service).getSystemService(ConnectivityManager::class.java)
        Mockito.doReturn(directory).`when`(service).filesDir
        Mockito.doReturn(directory).`when`(service).noBackupFilesDir
        set(service, "worker", worker); set(service, "recovery", recovery)
        set(service, "config", XrayConfig(REMARK = "Synthetic session A")); set(service, "process", child)
        var callback: ConnectivityManager.NetworkCallback? = null
        Mockito.doAnswer { invocation -> callback = invocation.getArgument(1); null }
            .`when`(manager).registerNetworkCallback(Mockito.any(NetworkRequest::class.java),
                Mockito.any(ConnectivityManager.NetworkCallback::class.java))
        val current = XrayVPNService::class.java.getDeclaredField("currentRecovery").apply { isAccessible = true }
        val priorRecovery = current.get(null)
        val priorState = AppConfigs.V2RAY_STATE
        try {
            Mockito.mockConstruction(AuthorizedProfileStore::class.java).use {
                Mockito.mockConstruction(NetworkRequest.Builder::class.java,
                    Mockito.withSettings().defaultAnswer(Answers.RETURNS_SELF)) { builder, _ ->
                    Mockito.`when`(builder.build()).thenReturn(Mockito.mock(NetworkRequest::class.java))
                }.use {
                    service.onCreate()
                    assertEquals("Cold-start cleanup is queued but must not run in this unit test", 1, pending.size)
                    pending.clear()
                    AppConfigs.V2RAY_STATE = AppConfigs.V2RAY_STATES.V2RAY_CONNECTED
                    body(Fixture(service, recovery, pending, child, requireNotNull(callback), stopReached))
                }
            }
        } finally {
            current.set(null, priorRecovery)
            AppConfigs.V2RAY_STATE = priorState
            directory.deleteRecursively()
        }
    }

    private fun anyAction(): () -> Unit { Mockito.any<() -> Unit>(); return {} }

    @Test fun queuedOldSessionEventCannotRecoverOrStopReplacement() = fixture { fixture ->
        fixture.enqueue(available)
        val replacement = XrayConfig(REMARK = "Synthetic session B")
        val owner = fixture.recovery.activate()
        set(fixture.service, "config", replacement)
        val outcome = fixture.deliver()
        assertEquals("Queued session A callback must not recover session B", owner, fixture.recovery.generation)
        assertTrue("Stale callback must return without entering worker cleanup", outcome.isSuccess)
        Mockito.verify(fixture.child, Mockito.never()).destroy()
    }

    @Test fun currentSessionEventStillRecoversItsOwnedWorkers() = fixture { fixture ->
        val owner = fixture.recovery.generation
        fixture.enqueue(available)
        val outcome = fixture.deliver()
        assertEquals(owner + 1, fixture.recovery.generation)
        assertSame(fixture.stopReached, outcome.exceptionOrNull())
        Mockito.verify(fixture.child).destroy()
    }

    @Test fun stoppedSessionDoesNotRecoverOrStopWorkers() = fixture { fixture ->
        fixture.enqueue(available)
        fixture.recovery.disarm()
        val stopped = fixture.recovery.generation
        assertTrue(fixture.deliver().isSuccess)
        assertEquals(stopped, fixture.recovery.generation)
        Mockito.verify(fixture.child, Mockito.never()).destroy()
    }
}
