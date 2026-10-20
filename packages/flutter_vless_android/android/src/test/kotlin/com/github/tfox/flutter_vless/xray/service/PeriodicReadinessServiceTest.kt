package com.github.tfox.flutter_vless.xray.service

import android.content.Intent
import android.app.Notification
import android.content.pm.PackageManager
import com.github.tfox.flutter_vless.xray.core.LocalProxyCredentials
import com.github.tfox.flutter_vless.xray.core.ReadinessFailure
import com.github.tfox.flutter_vless.xray.core.ReadinessStage
import com.github.tfox.flutter_vless.xray.core.StartupReadiness
import com.github.tfox.flutter_vless.xray.core.XrayCoreManager
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import org.junit.Assert.*
import org.junit.Test
import org.mockito.Answers
import org.mockito.Mockito
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.lang.reflect.InvocationTargetException
import java.net.Socket
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** Actual scheduled tick and Stop command; all probes/sockets/processes are mocks. */
class PeriodicReadinessServiceTest {
    private class Fixture(
        val service: XrayVPNService, val recovery: SessionRecoveryPolicy,
        val probe: SessionReadinessProbe, val child: Process,
        val scheduled: MutableList<() -> Unit>, val cleanup: MutableList<() -> Unit>,
        val broadcasts: MutableList<Intent>
    ) {
        fun arm() {
            XrayVPNService::class.java.getDeclaredMethod("tick", Long::class.javaPrimitiveType, Int::class.javaPrimitiveType)
                .apply { isAccessible = true }.invoke(service, recovery.generation, 30)
            assertEquals(1, scheduled.size)
        }
        fun fire() {
            try { scheduled.removeAt(0).invoke() }
            catch (error: InvocationTargetException) { throw error.targetException }
        }
        fun stop() {
            val intent = Mockito.mock(Intent::class.java)
            Mockito.`when`(intent.getSerializableExtra("COMMAND"))
                .thenReturn(AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE)
            service.onStartCommand(intent, 0, 1)
        }
        fun replaceCore() {
            val replacement = Mockito.mock(Process::class.java)
            Mockito.`when`(replacement.isAlive).thenReturn(true)
            XrayCoreManager::class.java.getDeclaredField("xrayProcess").apply { isAccessible = true }
                .set(XrayCoreManager, replacement)
        }
    }

    private fun set(target: Any, name: String, value: Any?) = target.javaClass.getDeclaredField(name)
        .apply { isAccessible = true }.set(target, value)
    private fun activePhase(service: XrayVPNService) = XrayVPNService::class.java.getDeclaredField("periodicReadiness")
        .apply { isAccessible = true }.get(service)
    private fun anyAction(): () -> Unit { Mockito.any<() -> Unit>(); return {} }
    private fun anyUnit(): TimeUnit { Mockito.any(TimeUnit::class.java); return TimeUnit.MILLISECONDS }
    private fun anyStage(): ReadinessStage { Mockito.any(ReadinessStage::class.java); return ReadinessStage.DEADLINE }

    private fun fixture(body: (Fixture) -> Unit) {
        val directory = Files.createTempDirectory("periodic-readiness").toFile()
        val service = Mockito.mock(XrayVPNService::class.java, Answers.CALLS_REAL_METHODS)
        Mockito.doReturn("periodic.fixture").`when`(service).packageName
        Mockito.doReturn(directory).`when`(service).filesDir
        Mockito.doReturn(directory).`when`(service).noBackupFilesDir
        val profile = XrayConfig(LOCAL_SOCKS5_PORT = 18111, BLOCKED_APPS = arrayListOf())
        val recovery = SessionRecoveryPolicy().apply { activate(); options = NativeVlessOptions.Reconnect(enabled = false) }
        val worker = Mockito.mock(SessionWorkQueue::class.java)
        val scheduled = mutableListOf<() -> Unit>(); val cleanup = mutableListOf<() -> Unit>()
        Mockito.doAnswer { scheduled.add(it.getArgument(0)); true }.`when`(worker)
            .schedule(anyAction(), Mockito.anyLong(), anyUnit())
        Mockito.doAnswer { cleanup.add(it.getArgument(0)); true }.`when`(worker).execute(anyAction())
        val probe = Mockito.mock(SessionReadinessProbe::class.java, Answers.CALLS_REAL_METHODS)
        set(probe, "token", "owned-periodic-challenge".toByteArray())
        set(probe, "host", "198.51.100.1")
        Mockito.doReturn(18112).`when`(probe).port
        val child = Mockito.mock(Process::class.java)
        Mockito.`when`(child.isAlive).thenReturn(true)
        set(service, "config", profile); set(service, "readinessProbe", probe)
        set(service, "credentials", LocalProxyCredentials("owned-user", "owned-password"))
        set(service, "worker", worker); set(service, "recovery", recovery)
        set(service, "requests", AtomicLong())
        set(service, "profiles", Mockito.mock(AuthorizedProfileStore::class.java))
        val broadcasts = mutableListOf<Intent>()
        Mockito.doAnswer { broadcasts.add(it.getArgument(0)); null }.`when`(service).sendBroadcast(Mockito.any(Intent::class.java))
        val core = XrayCoreManager::class.java.getDeclaredField("xrayProcess").apply { isAccessible = true }
        val priorCore = core.get(XrayCoreManager)
        val priorState = AppConfigs.V2RAY_STATE; val priorConfig = AppConfigs.V2RAY_CONFIG
        val priorAlways = AppConfigs.ALWAYS_ON_ENABLED; val priorLockdown = AppConfigs.LOCKDOWN_ENABLED
        core.set(XrayCoreManager, child)
        AppConfigs.V2RAY_STATE = AppConfigs.V2RAY_STATES.V2RAY_CONNECTED
        AppConfigs.V2RAY_CONFIG = profile
        AppConfigs.ALWAYS_ON_ENABLED = false; AppConfigs.LOCKDOWN_ENABLED = false
        try {
            Mockito.mockConstruction(Intent::class.java, Mockito.withSettings().defaultAnswer(Answers.RETURNS_SELF)).use {
                body(Fixture(service, recovery, probe, child, scheduled, cleanup, broadcasts))
            }
        } finally {
            core.set(XrayCoreManager, priorCore)
            AppConfigs.V2RAY_STATE = priorState; AppConfigs.V2RAY_CONFIG = priorConfig
            AppConfigs.ALWAYS_ON_ENABLED = priorAlways; AppConfigs.LOCKDOWN_ENABLED = priorLockdown
            directory.deleteRecursively()
        }
    }

    private fun onProbe(probe: SessionReadinessProbe, action: (StartupReadiness?, ReadinessStage) -> Unit) {
        Mockito.doAnswer { action(it.getArgument(0), it.getArgument(1)); null }.`when`(probe)
            .verify(Mockito.nullable(StartupReadiness::class.java), anyStage(), Mockito.nullable(Function0::class.java) as (() -> Socket)?)
    }

    @Test fun periodicPrivateAndPacketChecksShareOneOwnedBudget() = fixture { f ->
        val phases = mutableListOf<StartupReadiness?>(); val stages = mutableListOf<ReadinessStage>()
        onProbe(f.probe) { phase, stage -> phases.add(phase); stages.add(stage) }
        f.arm(); f.fire()
        assertEquals(listOf(ReadinessStage.PRIVATE_CHALLENGE, ReadinessStage.PACKET_CHALLENGE), stages)
        assertNotNull("Periodic checks must not bypass the absolute readiness budget", phases[0])
        assertSame(phases[0], phases[1])
        assertTrue(requireNotNull(phases[0]).timerTerminated)
        assertNull(activePhase(f.service))
        assertEquals(1, f.broadcasts.size); assertEquals(1, f.scheduled.size)
    }

    @Test fun revokedOwnerAfterPrivateChallengeCannotAdmitPacketOrPublish() = fixture { f ->
        val stages = mutableListOf<ReadinessStage>()
        onProbe(f.probe) { _, stage -> stages.add(stage); if (stage == ReadinessStage.PRIVATE_CHALLENGE) f.recovery.disarm() }
        f.arm(); f.fire()
        assertEquals(listOf(ReadinessStage.PRIVATE_CHALLENGE), stages)
        assertTrue(f.broadcasts.isEmpty()); assertTrue(f.scheduled.isEmpty())
        Mockito.verify(f.child, Mockito.never()).destroy()
    }

    @Test fun revokedOwnerAtCompletionCannotPublishConnectedOrRearm() = fixture { f ->
        onProbe(f.probe) { _, stage -> if (stage == ReadinessStage.PACKET_CHALLENGE) f.recovery.disarm() }
        f.arm(); f.fire()
        assertTrue("A completed old challenge cannot publish Connected", f.broadcasts.isEmpty())
        assertTrue(f.scheduled.isEmpty())
    }

    @Test fun replacedCoreAfterPrivateChallengeCannotAdmitPacketOrPublish() = fixture { f ->
        val stages = mutableListOf<ReadinessStage>()
        onProbe(f.probe) { _, stage -> stages.add(stage); if (stage == ReadinessStage.PRIVATE_CHALLENGE) f.replaceCore() }
        f.arm(); f.fire()
        assertEquals(listOf(ReadinessStage.PRIVATE_CHALLENGE), stages)
        assertTrue(f.broadcasts.isEmpty()); assertTrue(f.scheduled.isEmpty())
        Mockito.verify(f.child, Mockito.never()).destroy()
    }

    @Test fun replacedCoreCannotBeRecoveredByAnOldFailedProbe() = fixture { f ->
        val owner = f.recovery.generation
        onProbe(f.probe) { _, _ ->
            f.replaceCore()
            throw ReadinessFailure(ReadinessStage.DEADLINE)
        }
        f.arm()
        val result = runCatching { f.fire() }
        assertEquals("An old failed probe must not restart the replacement Core's session", owner, f.recovery.generation)
        assertTrue(result.isSuccess)
        assertTrue(f.broadcasts.isEmpty()); assertTrue(f.scheduled.isEmpty())
    }

    private fun withRecoveryBoundary(f: Fixture, body: () -> Unit) {
        // Recovery itself is real; its child/probe cleanup and notification boundary are inert.
        Mockito.`when`(f.child.waitFor(Mockito.anyLong(), anyUnit())).thenReturn(true)
        Mockito.doNothing().`when`(f.probe).close()
        Mockito.doReturn(Mockito.mock(PackageManager::class.java)).`when`(f.service).packageManager
        set(f.service, "sessionOptions", NativeVlessOptions())
        Mockito.mockConstruction(Notification.Builder::class.java,
            Mockito.withSettings().defaultAnswer(Answers.RETURNS_SELF)) { builder, _ ->
            Mockito.doReturn(Mockito.mock(Notification::class.java)).`when`(builder).build()
        }.use { body() }
    }

    private fun sameDeadCoreMustRecover(duringProbe: Boolean) = fixture { f ->
        val owner = f.recovery.generation
        var attempts = 0
        onProbe(f.probe) { _, _ ->
            attempts++
            Mockito.`when`(f.child.isAlive).thenReturn(false)
            throw ReadinessFailure(ReadinessStage.DEADLINE)
        }
        if (!duringProbe) Mockito.`when`(f.child.isAlive).thenReturn(false)
        withRecoveryBoundary(f) { f.arm(); f.fire() }
        assertEquals("The same dead Core must enter recovery exactly once", owner + 1, f.recovery.generation)
        assertEquals(if (duringProbe) 1 else 0, attempts)
        Mockito.verify(f.child, Mockito.times(1)).destroy()
        assertEquals(AppConfigs.V2RAY_STATES.V2RAY_CONNECTING, AppConfigs.V2RAY_STATE)
        assertEquals(1, f.broadcasts.size)
        assertTrue(f.scheduled.isEmpty()) // Reconnect disabled: preserve capture without a retry loop.
    }

    @Test fun sameCoreDeadBeforePeriodicCheckStillRecoversOnce() = sameDeadCoreMustRecover(false)

    @Test fun sameCoreDyingDuringFailedPeriodicCheckStillRecoversOnce() = sameDeadCoreMustRecover(true)

    @Test fun sameCoreDyingAtFirstPostHelperCheckStillRecoversOnce() = fixture { f ->
        val owner = f.recovery.generation
        var checksAfterPacket = 0
        onProbe(f.probe) { _, stage ->
            if (stage == ReadinessStage.PACKET_CHALLENGE) Mockito.`when`(f.child.isAlive).thenAnswer {
                // First: phase completion. Second: helper's final check.
                // Third: tick's first post-helper liveness admission.
                ++checksAfterPacket < 3
            }
        }
        withRecoveryBoundary(f) { f.arm(); f.fire() }
        assertEquals(3, checksAfterPacket)
        assertEquals("Post-helper death must not silently terminate the owner's tick chain", owner + 1, f.recovery.generation)
        Mockito.verify(f.child, Mockito.times(1)).destroy()
        assertEquals(AppConfigs.V2RAY_STATES.V2RAY_CONNECTING, AppConfigs.V2RAY_STATE)
        assertEquals(1, f.broadcasts.size); assertTrue(f.scheduled.isEmpty())
    }

    @Test fun sameCoreDyingAfterPublishStillRecoversOnce() = fixture { f ->
        val owner = f.recovery.generation
        onProbe(f.probe) { _, _ -> }
        Mockito.doAnswer {
            f.broadcasts.add(it.getArgument(0))
            if (f.broadcasts.size == 1) Mockito.`when`(f.child.isAlive).thenReturn(false)
            null
        }.`when`(f.service).sendBroadcast(Mockito.any(Intent::class.java))
        withRecoveryBoundary(f) { f.arm(); f.fire() }
        assertEquals("Post-publish death must not silently terminate the owner's tick chain", owner + 1, f.recovery.generation)
        Mockito.verify(f.child, Mockito.times(1)).destroy()
        assertEquals(AppConfigs.V2RAY_STATES.V2RAY_CONNECTING, AppConfigs.V2RAY_STATE)
        assertEquals(2, f.broadcasts.size); assertTrue(f.scheduled.isEmpty())
    }

    @Test fun currentOwnerStillCompletesBothChecksAndPublishesOnce() = fixture { f ->
        val stages = mutableListOf<ReadinessStage>()
        onProbe(f.probe) { _, stage -> stages.add(stage) }
        f.arm(); f.fire()
        assertEquals(listOf(ReadinessStage.PRIVATE_CHALLENGE, ReadinessStage.PACKET_CHALLENGE), stages)
        assertEquals(1, f.broadcasts.size); assertEquals(1, f.scheduled.size)
        assertTrue(f.recovery.authorized)
    }

    @Test fun actualPeriodicStagesCannotRefreshTheAbsoluteBudget() = fixture { f ->
        var clock = System.nanoTime()
        val socket = Mockito.mock(Socket::class.java)
        val stages = mutableListOf<ReadinessStage>(); var failure: ReadinessFailure? = null
        onProbe(f.probe) { maybePhase, stage ->
            val phase = requireNotNull(maybePhase)
            set(phase, "nanoTime", { clock })
            stages.add(stage)
            val input = object : InputStream() {
                override fun read(): Int = error("Bulk reads only")
                override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                    clock += TimeUnit.SECONDS.toNanos(3); bytes[offset] = 1; return 1
                }
            }
            try { phase.readFully(socket, input, ByteArray(1), stage) }
            catch (error: ReadinessFailure) { failure = error; f.recovery.disarm(); throw error }
        }
        f.arm(); f.fire()
        assertEquals(listOf(ReadinessStage.PRIVATE_CHALLENGE, ReadinessStage.PACKET_CHALLENGE), stages)
        assertEquals(ReadinessStage.DEADLINE, requireNotNull(failure).stage)
        assertTrue(f.broadcasts.isEmpty()); assertTrue(f.scheduled.isEmpty())
        assertNull(activePhase(f.service))
    }

    @Test fun periodicLocalRefusalRemainsOneAttemptRatherThanStartupRetry() = fixture { f ->
        var attempts = 0
        onProbe(f.probe) { _, _ ->
            attempts++
            if (attempts > 1) f.recovery.disarm() // Bound a regression's startup retry loop.
            throw ReadinessFailure(ReadinessStage.LOCAL_CONNECT, StartupReadiness.CONNECTION_REFUSED)
        }
        val method = XrayVPNService::class.java.getDeclaredMethod("checkAuthenticatedPath",
            Long::class.javaPrimitiveType, Boolean::class.javaPrimitiveType).apply { isAccessible = true }
        val thrown = assertThrows(InvocationTargetException::class.java) { method.invoke(f.service, f.recovery.generation, true) }
        assertEquals(ReadinessStage.LOCAL_CONNECT, (thrown.targetException as ReadinessFailure).stage)
        assertEquals(1, attempts); assertTrue(f.recovery.authorized)
        assertNull(activePhase(f.service))
    }

    @Test fun oldPhaseFinallyCannotClearOrCancelTheReplacementPhase() = fixture { f ->
        var replacement: Pair<Long, StartupReadiness>? = null
        onProbe(f.probe) { _, stage ->
            assertEquals(ReadinessStage.PRIVATE_CHALLENGE, stage)
            val owner = f.recovery.restart()
            replacement = owner to StartupReadiness(isCurrent = { f.recovery.owns(owner) })
            set(f.service, "periodicReadiness", replacement)
        }
        try {
            f.arm(); f.fire()
            assertSame(replacement, activePhase(f.service))
            requireNotNull(replacement).second.check()
            assertFalse(requireNotNull(replacement).second.timerTerminated)
            assertTrue(f.broadcasts.isEmpty()); assertTrue(f.scheduled.isEmpty())
        } finally {
            replacement?.second?.close(); set(f.service, "periodicReadiness", null)
        }
    }

    @Test(timeout = 10000) fun actualStopCommandClosesBlockedPeriodicSocketWithoutWaitingForWorker() = fixture { f ->
        val entered = CountDownLatch(1); val closed = CountDownLatch(1); val finished = CountDownLatch(1)
        val thrown = AtomicReference<Throwable?>()
        val socket = AtomicReference<Socket?>()
        f.arm()
        val thread = Thread({
            try {
                Mockito.mockConstruction(Socket::class.java) { owned, _ ->
                    socket.set(owned)
                    Mockito.`when`(owned.inputStream).thenReturn(ByteArrayInputStream(ByteArray(0)))
                    Mockito.`when`(owned.outputStream).thenReturn(object : OutputStream() {
                        override fun write(value: Int) {
                            entered.countDown()
                            check(closed.await(3, TimeUnit.SECONDS)) { "Synthetic blocked write was not released" }
                            throw IOException("Synthetic owned socket closed")
                        }
                        override fun write(bytes: ByteArray, offset: Int, length: Int) = write(0)
                    })
                    Mockito.doAnswer { closed.countDown(); null }.`when`(owned).close()
                }.use { f.fire() }
            } catch (error: Throwable) { thrown.set(error) }
            finally { finished.countDown() }
        }, "periodic-readiness-inert-test")
        thread.start()
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            f.stop()
            assertFalse(f.recovery.authorized)
            assertEquals("Stop queues cleanup rather than running it on the caller", 1, f.cleanup.size)
            assertTrue("Stop must cancel the active owned socket, not wait for its I/O timeout", finished.await(700, TimeUnit.MILLISECONDS))
            assertNull(thrown.get())
            Mockito.verify(requireNotNull(socket.get()), Mockito.atLeastOnce()).close()
            assertTrue(f.broadcasts.isEmpty()); assertTrue(f.scheduled.isEmpty())
        } finally {
            closed.countDown(); thread.join(3000)
            assertFalse("Owned inert worker leaked", thread.isAlive)
        }
    }
}
