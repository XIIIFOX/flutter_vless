package com.github.tfox.flutter_vless.xray.service

import android.system.ErrnoException
import com.github.tfox.flutter_vless.xray.core.LocalProxyCredentials
import com.github.tfox.flutter_vless.xray.core.XrayCoreManager
import com.github.tfox.flutter_vless.xray.core.ReadinessFailure
import com.github.tfox.flutter_vless.xray.core.ReadinessStage
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import org.junit.Assert.*
import org.junit.Test
import org.mockito.Answers
import org.mockito.Mockito
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.lang.reflect.InvocationTargetException
import java.net.ConnectException
import java.net.Socket
import java.net.SocketTimeoutException

/** No real sockets, service worker, child process, Core or Android lifecycle. */
class StartupReadinessServiceTest {
    private val token = "owned-startup-challenge".toByteArray()
    private val accepted = byteArrayOf(5, 2, 1, 0, 5, 0, 0, 1, 127, 0, 0, 1, 0, 80)

    private fun connectFailure(errno: Int?): ConnectException = ConnectException("Synthetic local connect failure").also {
        if (errno != null) {
            val native = ErrnoException("connect", errno)
            // The mockable Android jar stubs this constructor on the JVM.
            ErrnoException::class.java.getDeclaredField("errno").setInt(native, errno)
            it.initCause(native)
        }
    }

    private class Fixture(val service: XrayVPNService, val recovery: SessionRecoveryPolicy, val child: Process) {
        fun probe() {
            try {
                XrayVPNService::class.java.getDeclaredMethod("probeAuthenticatedPath", Long::class.javaPrimitiveType)
                    .apply { isAccessible = true }.invoke(service, 1L)
            } catch (error: InvocationTargetException) { throw error.targetException }
        }
    }

    private fun withFixture(body: (Fixture) -> Unit) {
        val service = Mockito.mock(XrayVPNService::class.java, Answers.CALLS_REAL_METHODS)
        Mockito.doReturn("startup.fixture").`when`(service).packageName
        val profile = XrayConfig(LOCAL_SOCKS5_PORT = 18111, BLOCKED_APPS = arrayListOf("startup.fixture"))
        val recovery = SessionRecoveryPolicy().apply { activate(); options = NativeVlessOptions.Reconnect(enabled = false) }
        val probe = Mockito.mock(SessionReadinessProbe::class.java, Answers.CALLS_REAL_METHODS)
        fun field(target: Any, name: String, value: Any) = target.javaClass.getDeclaredField(name)
            .apply { isAccessible = true }.set(target, value)
        field(probe, "token", token)
        field(probe, "host", "198.51.100.1")
        Mockito.doReturn(18112).`when`(probe).port
        field(service, "config", profile); field(service, "credentials", LocalProxyCredentials("owned-user", "owned-password"))
        field(service, "readinessProbe", probe); field(service, "recovery", recovery)
        val child = Mockito.mock(Process::class.java)
        Mockito.`when`(child.isAlive).thenReturn(true)
        val processField = XrayCoreManager::class.java.getDeclaredField("xrayProcess").apply { isAccessible = true }
        val prior = processField.get(XrayCoreManager)
        processField.set(XrayCoreManager, child)
        try { body(Fixture(service, recovery, child)) }
        finally { processField.set(XrayCoreManager, prior) }
    }

    private fun sockets(failures: List<Throwable?> = emptyList(),
        response: (Int) -> InputStream = { ByteArrayInputStream(accepted + token) },
        body: (List<Socket>) -> Unit) {
        Mockito.mockConstruction(Socket::class.java) { socket, context ->
            val index = context.count - 1
            Mockito.`when`(socket.inputStream).thenReturn(response(index))
            Mockito.`when`(socket.outputStream).thenReturn(ByteArrayOutputStream())
            failures.getOrNull(index)?.let { error ->
                Mockito.doThrow(error).`when`(socket).connect(Mockito.any(), Mockito.anyInt())
            }
        }.use { construction -> body(construction.constructed()) }
    }

    @Test(timeout = 15000) fun localListenerRefusalCanBecomeAuthenticatedWithoutRestartingTheChild() = withFixture { fixture ->
        sockets(listOf(connectFailure(111), null)) { connections ->
            fixture.probe()
            assertEquals("Only local listener availability may be retried", 2, connections.size)
            connections.forEach { Mockito.verify(it).close() }
            Mockito.verify(fixture.child, Mockito.never()).destroy()
            assertEquals(1L, fixture.recovery.generation)
        }
    }

    @Test(timeout = 15000) fun deniedConnectIsNotTreatedAsAStartingListener() = withFixture { fixture ->
        sockets(listOf(connectFailure(13), null)) { connections ->
            assertThrows(Exception::class.java, fixture::probe)
            assertEquals(1, connections.size); Mockito.verify(connections.single()).close()
        }
    }

    @Test(timeout = 15000) fun unknownConnectCauseIsNeverRetried() = withFixture { fixture ->
        sockets(listOf(connectFailure(null), null)) { connections ->
            assertThrows(Exception::class.java, fixture::probe)
            assertEquals(1, connections.size); Mockito.verify(connections.single()).close()
        }
    }

    @Test(timeout = 15000) fun wrongMethodAndPasswordNeverRetryOrFallBack() {
        for (reply in listOf(byteArrayOf(5, 0), byteArrayOf(5, 2, 1, 1))) withFixture { fixture ->
            sockets(response = { ByteArrayInputStream(reply) }) { connections ->
                assertThrows(Exception::class.java, fixture::probe)
                assertEquals(1, connections.size); Mockito.verify(connections.single()).close()
                assertFalse(fixture.recovery.mayRetry())
                Mockito.verify(fixture.child, Mockito.never()).destroy()
            }
        }
    }

    @Test(timeout = 15000) fun wrongChallengeIsPermanent() = withFixture { fixture ->
        sockets(response = { ByteArrayInputStream(accepted + ByteArray(token.size)) }) { connections ->
            assertThrows(Exception::class.java, fixture::probe)
            assertEquals(1, connections.size); Mockito.verify(connections.single()).close()
        }
    }

    @Test(timeout = 15000) fun challengeEofIsPermanent() = withFixture { fixture ->
        sockets(response = { ByteArrayInputStream(accepted) }) { connections ->
            assertThrows(Exception::class.java, fixture::probe)
            assertEquals(1, connections.size); Mockito.verify(connections.single()).close()
        }
    }

    @Test(timeout = 15000) fun readTimeoutIsPermanent() = withFixture { fixture ->
        sockets(response = { object : InputStream() { override fun read(): Int = throw SocketTimeoutException("Synthetic read timeout") } }) { connections ->
            assertThrows(Exception::class.java, fixture::probe)
            assertEquals(1, connections.size); Mockito.verify(connections.single()).close()
        }
    }

    @Test(timeout = 15000) fun revokedOwnerCannotStartAnAuthenticatedProbe() = withFixture { fixture ->
        fixture.recovery.disarm()
        sockets { connections ->
            assertThrows(Exception::class.java, fixture::probe)
            assertTrue(connections.isEmpty())
        }
    }

    @Test(timeout = 15000) fun deadChildCannotStartAnAuthenticatedProbe() = withFixture { fixture ->
        Mockito.`when`(fixture.child.isAlive).thenReturn(false)
        sockets { connections ->
            assertThrows(Exception::class.java, fixture::probe)
            assertTrue(connections.isEmpty())
        }
    }

    @Test(timeout = 15000) fun oldAuthorizedGenerationCannotBeRecapturedAsTheNewOwner() = withFixture { fixture ->
        fixture.recovery.restart()
        assertTrue(fixture.recovery.authorized)
        sockets { connections ->
            assertThrows(Exception::class.java, fixture::probe)
            assertTrue(connections.isEmpty())
        }
    }

    @Test(timeout = 15000) fun unexcludedStartupAlsoRequiresTheRealPacketChallenge() = withFixture { fixture ->
        val profile = XrayVPNService::class.java.getDeclaredField("config").apply { isAccessible = true }
            .get(fixture.service) as XrayConfig
        profile.BLOCKED_APPS.clear()
        sockets(response = { index -> ByteArrayInputStream(if (index == 0) accepted + token else token) }) { connections ->
            fixture.probe()
            assertEquals(2, connections.size)
            connections.forEach { Mockito.verify(it).close() }
        }
    }

    @Test(timeout = 15000) fun packetChallengeFailureIsNotRetriedOrReportedAsAuthentication() = withFixture { fixture ->
        val profile = XrayVPNService::class.java.getDeclaredField("config").apply { isAccessible = true }
            .get(fixture.service) as XrayConfig
        profile.BLOCKED_APPS.clear()
        sockets(response = { index -> ByteArrayInputStream(if (index == 0) accepted + token else ByteArray(token.size)) }) { connections ->
            val failure = assertThrows(ReadinessFailure::class.java, fixture::probe)
            assertEquals(ReadinessStage.PACKET_CHALLENGE, failure.stage)
            assertEquals(2, connections.size)
            connections.forEach { Mockito.verify(it).close() }
        }
    }

    @Test(timeout = 15000) fun rejectedConnectReplyNeverRetries() = withFixture { fixture ->
        sockets(response = { ByteArrayInputStream(byteArrayOf(5, 2, 1, 0, 5, 5)) }) { connections ->
            assertEquals(ReadinessStage.SOCKS_REPLY, assertThrows(ReadinessFailure::class.java, fixture::probe).stage)
            assertEquals(1, connections.size); Mockito.verify(connections.single()).close()
        }
    }

    @Test(timeout = 15000) fun newlyAuthorizedOwnerCannotAdoptAnOldCompletedChallenge() = withFixture { fixture ->
        sockets(response = {
            object : ByteArrayInputStream(accepted + token) {
                override fun read(bytes: ByteArray, offset: Int, length: Int): Int = super.read(bytes, offset, length).also {
                    if (available() == 0) fixture.recovery.restart()
                }
            }
        }) { connections ->
            assertEquals(ReadinessStage.OWNER, assertThrows(ReadinessFailure::class.java, fixture::probe).stage)
            assertEquals(1, connections.size); Mockito.verify(connections.single()).close()
        }
    }

    @Test(timeout = 15000) fun replacedChildCannotAdoptAnOldCompletedChallenge() = withFixture { fixture ->
        val replacement = Mockito.mock(Process::class.java)
        Mockito.`when`(replacement.isAlive).thenReturn(true)
        sockets(response = {
            object : ByteArrayInputStream(accepted + token) {
                override fun read(bytes: ByteArray, offset: Int, length: Int): Int = super.read(bytes, offset, length).also {
                    if (available() == 0) XrayCoreManager::class.java.getDeclaredField("xrayProcess")
                        .apply { isAccessible = true }.set(XrayCoreManager, replacement)
                }
            }
        }) { connections ->
            assertEquals(ReadinessStage.OWNER, assertThrows(ReadinessFailure::class.java, fixture::probe).stage)
            assertEquals(1, connections.size); Mockito.verify(connections.single()).close()
        }
    }
}
