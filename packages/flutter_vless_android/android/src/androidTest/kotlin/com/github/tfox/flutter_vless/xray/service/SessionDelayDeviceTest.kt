package com.github.tfox.flutter_vless.xray.service

import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import android.os.ResultReceiver
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.github.tfox.flutter_vless.xray.core.XrayCoreManager
import com.github.tfox.flutter_vless.xray.core.XrayDiagnosticsStore
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.net.Authenticator
import java.net.PasswordAuthentication
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

@RunWith(AndroidJUnit4::class)
class SessionDelayDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private fun stop() = context.startService(Intent(context, XrayVPNService::class.java)
        .putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE))

    @Test fun temporaryAndConnectedMeasurementsAuthenticateWithoutGlobalCredentials() {
        // This isolated instrumentation process owns a canary authenticator. Native measurements
        // must neither invoke it nor replace it with service credentials.
        val authenticatorCalls = java.util.concurrent.atomic.AtomicInteger()
        val canary = object : Authenticator() {
            override fun getPasswordAuthentication(): PasswordAuthentication {
                authenticatorCalls.incrementAndGet()
                return PasswordAuthentication("test-authenticator", "test-only-canary".toCharArray())
            }
        }
        Authenticator.setDefault(canary)
        val executor = Executors.newSingleThreadExecutor()
        val originExecutor = Executors.newSingleThreadExecutor()
        val temporarySecrets = mutableSetOf<Pair<String, String>>()
        val cleanupErrors = mutableListOf<Throwable>()
        var primaryFailure: Throwable? = null
        try {
            stop(); Thread.sleep(750)
            repeat(2) { index ->
                // This isolated fixture stopped the service above. Each probe
                // owns a fresh, explicitly enabled, bounded diagnostic window.
                XrayDiagnosticsStore.configure(context.filesDir, NativeVlessOptions.Diagnostics(enabled = true))
                XrayDiagnosticsStore.reset(context.filesDir)
                ServerSocket(0).use { origin ->
                    origin.soTimeout = 5000
                    val accepted = AtomicReference<Socket?>()
                    val phase = AtomicReference("accepting")
                    val served = originExecutor.submit<Unit> {
                        origin.accept().use { socket ->
                            accepted.set(socket)
                            check(!origin.isClosed) { "HTTP fixture was cancelled" }
                            socket.soTimeout = 3000
                            phase.set("reading-request")
                            val request = socket.getInputStream().bufferedReader().let { reader ->
                                buildString { while (true) { val line = reader.readLine() ?: break; if (line.isEmpty()) break; appendLine(line) } }
                            }
                            phase.set("checking-authorization")
                            val files = context.noBackupFilesDir.listFiles().orEmpty().filter { it.name.startsWith("delay-") }
                            assertEquals("One isolated native delay runtime must own its file", 1, files.size)
                            val inputs = JSONObject(files.single().readText()).getJSONArray("inbounds")
                            val socks = (0 until inputs.length()).map { inputs.getJSONObject(it) }.single { it.optString("protocol") == "socks" }
                            val settings = socks.getJSONObject("settings")
                            assertEquals("password", settings.getString("auth"))
                            val account = settings.getJSONArray("accounts").getJSONObject(0)
                            val secret = account.getString("user") to account.getString("pass")
                            assertTrue("Each delay runtime needs independent credentials", temporarySecrets.add(secret))
                            assertFalse(request.contains(secret.first)); assertFalse(request.contains(secret.second))
                            assertFalse(request.contains("Proxy-Authorization", ignoreCase = true))
                            phase.set("writing-response")
                            socket.getOutputStream().write("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".toByteArray())
                            socket.getOutputStream().flush()
                            phase.set("responded")
                        }
                    }
                    val measured = executor.submit<Long> {
                        XrayCoreManager.getServerDelay(context,
                            """{"inbounds":[],"outbounds":[{"tag":"proxy","protocol":"freedom"}]}""",
                            "http://127.0.0.1:${origin.localPort}/delay-control")
                    }
                    try {
                        SessionDelayObservation.await(measured, served, index + 1, phase::get)
                        // Future completion follows the manager's finally: a
                        // valid latency cannot conceal a failed child cleanup.
                        SessionDelayObservation.requireSuccessfulCleanup(
                            XrayCoreManager.getProviderDebugSnapshot(context), index + 1)
                    } catch (error: AssertionError) {
                        val snapshot = runCatching { XrayCoreManager.getProviderDebugSnapshot(context) }.getOrElse {
                            error.addSuppressed(it)
                            "Provider diagnostics unavailable"
                        }
                        throw AssertionError("${error.message}\n$snapshot", error)
                    } finally {
                        // Closing the listener before consuming the published
                        // accepted socket also covers accept/close handoff.
                        runCatching { origin.close() }.exceptionOrNull()?.let(cleanupErrors::add)
                        runCatching { accepted.getAndSet(null)?.close() }.exceptionOrNull()?.let(cleanupErrors::add)
                        measured.cancel(true); served.cancel(true)
                    }
                    assertTrue(context.noBackupFilesDir.listFiles().orEmpty().none { it.name.startsWith("delay-") })
                }
            }
            val config = XrayConfig(REMARK = "Connected delay control", V2RAY_FULL_JSON_CONFIG =
                """{"inbounds":[],"outbounds":[{"tag":"proxy","protocol":"socks","settings":{"address":"10.0.2.2","port":18080}}]}""")
            check(android.net.VpnService.prepare(context) == null) { "Disposable test VPN consent is required" }
            context.startForegroundService(Intent(context, XrayVPNService::class.java)
                .putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE).putExtra("V2RAY_CONFIG", config))
            val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(45)
            var ready = false
            while (System.nanoTime() < end) {
                val manager = context.getSystemService(ConnectivityManager::class.java)
                ready = manager.getNetworkCapabilities(manager.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true &&
                    XrayCoreManager.getProviderDebugSnapshot(context).contains("CONNECTED")
                if (ready) break
                Thread.sleep(100)
            }
            assertTrue("Real VPN path must be ready before measuring its service-owned listener", ready)
            val latch = CountDownLatch(1)
            val delay = AtomicLong(-1)
            val receiver = object : ResultReceiver(null) {
                override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
                    delay.set(resultData?.getLong("delay", -1) ?: -1); latch.countDown()
                }
            }
            context.startService(Intent(context, XrayVPNService::class.java).setAction(XrayVPNService.ACTION_MEASURE_DELAY)
                .putExtra("url", "http://192.0.2.99:18081/delay-control").putExtra("receiver", receiver))
            assertTrue("Connected delay IPC must return from the separate VPN service process", latch.await(15, TimeUnit.SECONDS))
            assertTrue("Connected measurement must authenticate and transfer bytes", delay.get() >= 0)
            assertEquals("Measurements must not request process-wide credentials", 0, authenticatorCalls.get())
            val response = Authenticator.requestPasswordAuthentication("localhost", null, 1234, "socks", "test", "SOCKS")
            assertEquals("Library must preserve the caller's process-wide Authenticator", "test-authenticator", response?.userName)
            assertEquals(1, authenticatorCalls.get())
        } catch (error: Throwable) {
            primaryFailure = error
            throw error
        } finally {
            runCatching { stop() }.exceptionOrNull()?.let(cleanupErrors::add)
            listOf("measurement" to executor, "HTTP origin" to originExecutor).forEach { (name, worker) ->
                runCatching {
                    worker.shutdownNow()
                    check(worker.awaitTermination(3, TimeUnit.SECONDS)) { "$name fixture executor did not terminate" }
                }.exceptionOrNull()?.let(cleanupErrors::add)
            }
            runCatching { Authenticator.setDefault(null) }.exceptionOrNull()?.let(cleanupErrors::add)
            if (cleanupErrors.isNotEmpty()) {
                val failure = primaryFailure ?: AssertionError("Delay fixture cleanup failed")
                cleanupErrors.forEach(failure::addSuppressed)
                if (primaryFailure == null) throw failure
            }
        }
    }
}

/** Test-only outcome ordering; no Android/native/network operation occurs here. */
private object SessionDelayObservation {
    fun requireSuccessfulCleanup(snapshot: String, attempt: Int) {
        val events = snapshot.lineSequence().map { it.substringBefore(' ') }.toSet()
        check("DELAY_CORE_STARTED" in events && "DELAY_COMPLETE" in events) {
            "Standalone delay attempt $attempt lacks enabled, scoped completion diagnostics"
        }
        check("DELAY_CLEANUP_FAILED" !in events) {
            "Standalone delay attempt $attempt did not clean up its owned child/file"
        }
    }

    fun await(measured: Future<Long>, served: Future<Unit>, attempt: Int, phase: () -> String,
              budgetNanos: Long = TimeUnit.SECONDS.toNanos(5)): Long {
        val deadline = System.nanoTime() + budgetNanos
        var value: Long? = null
        fun observedFailure(stage: String, error: Exception? = null): AssertionError {
            fun unwrap(error: Exception): Throwable = if (error is ExecutionException) error.cause ?: error else error
            val cause = error?.let(::unwrap)
            val failure = AssertionError("Standalone delay attempt $attempt failed during $stage; " +
                "measurement=${value ?: "not-returned"}; originPhase=${phase()}; originDone=${served.isDone}", cause)
            if (served.isDone) {
                try { served.get(0, TimeUnit.NANOSECONDS) }
                catch (originError: Exception) {
                    val originCause = unwrap(originError)
                    if (originCause !== cause) failure.addSuppressed(originCause)
                }
            }
            return failure
        }
        val result = try { measured.get((deadline - System.nanoTime()).coerceAtLeast(0), TimeUnit.NANOSECONDS) }
        catch (error: Exception) { throw observedFailure("measurement", error) }
        value = result
        if (result < 0) throw observedFailure("measurement result")
        try { served.get((deadline - System.nanoTime()).coerceAtLeast(0), TimeUnit.NANOSECONDS) }
        catch (error: Exception) { throw observedFailure("HTTP origin", error) }
        return result
    }
}
