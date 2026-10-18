package com.github.tfox.flutter_vless.xray.service

import android.content.Context
import android.net.ConnectivityManager
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.system.Os
import android.system.OsConstants
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.github.tfox.flutter_vless.xray.core.AuthenticatedSocksClient
import com.github.tfox.flutter_vless.xray.core.LocalProxyCredentials
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.File
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Opt-in composed Core + captured-Network broker acceptance, without a TUN.
 * This does not qualify VPN bypass, platform DNS, recovery or network handover.
 */
@RunWith(AndroidJUnit4::class)
class NativePreviewRuntimeDeviceTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val manager = context.getSystemService(ConnectivityManager::class.java)

    private class PreparedService(context: Context) : VpnService() {
        init { attachBaseContext(context) }
    }

    private fun capturedNetwork(): Network = NativePreviewFixtureNetwork.capture(context).also {
        NativePreviewFixtureNetwork.verify(context, it)
    }

    private fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it.toInt() and 255) }

    private fun executable(): File {
        val expected = InstrumentationRegistry.getArguments().getString("previewSha256")
        require(expected != null && expected.matches(Regex("[a-f0-9]{64}"))) {
            "Explicit previewSha256 instrumentation argument is required"
        }
        // The opt-in payload belongs only to the instrumentation APK. Never
        // copy it into writable data or substitute the ordinary target Core.
        return File(instrumentation.context.applicationInfo.nativeLibraryDir, "libxray_dns_preview.so").also {
            assertTrue("Composed opt-in preview executable is missing", it.isFile && it.canExecute())
            assertEquals("Packaged preview binary does not match the explicit host digest", expected, digest(it.readBytes()))
        }
    }

    private fun deadline(milliseconds: Long) = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(milliseconds)
    private fun remaining(until: Long): Long = (until - System.nanoTime()).also {
        check(it > 0) { "Owned preview operation exceeded its bounded deadline" }
    }

    /** Stdout is a closed JSON protocol; neither raw child output nor config is reported. */
    private inner class Child(binary: File, command: String, document: File? = null,
        broker: XraySocketProtector? = null) : Closeable {
        private val io = Executors.newFixedThreadPool(2) { task ->
            Thread(task, "native-preview-owned-io").apply { isDaemon = true }
        }
        private val failure = AtomicReference<String?>()
        private val messages = LinkedBlockingQueue<JSONObject>(8)
        private val statuses = mutableListOf<String>()
        private val stderrBytes = AtomicInteger()
        val process: Process
        private val stdout: java.util.concurrent.Future<*>
        private val stderr: java.util.concurrent.Future<*>

        init {
            val arguments = mutableListOf(binary.absolutePath, command)
            if (document != null) arguments.addAll(listOf("--config", document.absolutePath,
                "--resolver", "10.0.2.2:18284", "--egress-index", "1",
                "--capability", CAPABILITY, "--timeout-ms", "4000"))
            val builder = ProcessBuilder(arguments).directory(context.noBackupFilesDir)
            // Explicit private inputs only; inherited Core environment cannot
            // add config, assets, transport hooks or a different broker.
            builder.environment().keys.toList().filter {
                val key = it.uppercase(java.util.Locale.ROOT)
                key.startsWith("XRAY_") || key.startsWith("V2RAY_") ||
                    key.startsWith("FLUTTER_VLESS_") || key.startsWith("XRAY.") || key.startsWith("V2RAY.")
            }.forEach { builder.environment().remove(it) }
            if (broker != null) builder.environment()["FLUTTER_VLESS_PROTECT_SOCKET"] = broker.socketName
            process = try { builder.start() } catch (error: Throwable) { io.shutdownNow(); throw error }
            try {
                stdout = io.submit { drain(process.inputStream, true) }
                stderr = io.submit { drain(process.errorStream, false) }
            } catch (error: Throwable) {
                try { close() } catch (cleanup: Throwable) { error.addSuppressed(cleanup) }
                throw error
            }
        }

        private fun drain(input: InputStream, protocol: Boolean) {
            try {
                input.use {
                    val line = ByteArrayOutputStream()
                    var total = 0
                    val buffer = ByteArray(512)
                    while (true) {
                        val count = it.read(buffer)
                        if (count < 0) break
                        if (!protocol) stderrBytes.addAndGet(count)
                        total += count
                        if (total > MAX_OUTPUT) {
                            failure.compareAndSet(null, "Preview output exceeded its private bound")
                            continue // Keep draining so an owned child cannot block on its pipe.
                        }
                        if (protocol) for (index in 0 until count) {
                            val value = buffer[index].toInt() and 255
                            if (value == 10) {
                                val message = try { JSONObject(line.toString("UTF-8")) } catch (_: Exception) {
                                    failure.compareAndSet(null, "Preview emitted non-schema output"); null
                                }
                                line.reset()
                                if (message != null && !messages.offer(message))
                                    failure.compareAndSet(null, "Preview emitted too many protocol messages")
                            } else line.write(value)
                        }
                    }
                    if (protocol && line.size() != 0)
                        failure.compareAndSet(null, "Preview stdout ended with an incomplete protocol line")
                }
            } catch (_: Exception) {
                failure.compareAndSet(null, "Owned preview output drain failed")
            }
        }

        fun message(status: String, sourceDigest: String? = null, stage: String? = null,
            until: Long = deadline(5000)) {
            val value = messages.poll(remaining(until), TimeUnit.NANOSECONDS)
                ?: error("Preview did not emit the required bounded protocol event")
            val expectedKeys = mutableSetOf("schema", "capability", "core_commit", "status",
                "host_qualified", "system_resolver_attempts")
            if (sourceDigest != null) expectedKeys.add("source_digest")
            if (stage != null) expectedKeys.add("stage")
            assertEquals("Preview protocol schema changed", expectedKeys, value.keys().asSequence().toSet())
            assertEquals(1, value.getInt("schema"))
            assertEquals(CAPABILITY, value.getString("capability"))
            assertEquals(CORE_COMMIT, value.getString("core_commit"))
            assertEquals(status, value.getString("status"))
            assertFalse(value.getBoolean("host_qualified"))
            assertEquals(0L, value.getLong("system_resolver_attempts"))
            if (sourceDigest != null) assertEquals(sourceDigest, value.getString("source_digest"))
            if (stage != null) assertEquals(stage, value.getString("stage"))
            statuses.add(status)
            failure.get()?.let { error(it) }
        }

        fun exited(code: Int, expectedStatuses: List<String>, until: Long = deadline(5000)) {
            assertTrue("Owned preview child did not exit before the deadline",
                process.waitFor(remaining(until), TimeUnit.NANOSECONDS))
            assertEquals("Preview child exit status mismatch", code, process.exitValue())
            stdout.get(remaining(until), TimeUnit.NANOSECONDS)
            stderr.get(remaining(until), TimeUnit.NANOSECONDS)
            failure.get()?.let { error(it) }
            assertEquals("Preview stderr must remain empty", 0, stderrBytes.get())
            assertTrue("Unexpected additional preview stdout events", messages.isEmpty())
            assertEquals(expectedStatuses, statuses)
            assertFalse(process.isAlive)
        }

        fun stop(sourceDigest: String, eof: Boolean = false, until: Long = deadline(5000)) {
            if (!eof) { process.outputStream.write("stop\n".toByteArray(Charsets.US_ASCII)); process.outputStream.flush() }
            process.outputStream.close()
            message("stopped", sourceDigest, until = until)
            exited(0, listOf("started", "stopped"), until)
        }

        override fun close() {
            var clean = true
            var interrupted = Thread.interrupted()
            var primary: Throwable? = null
            fun record(error: Throwable) {
                if (primary == null) primary = error else primary!!.addSuppressed(error)
            }
            fun attempt(action: () -> Unit) {
                try { action() } catch (_: InterruptedException) { interrupted = true }
                catch (error: Throwable) { record(error) }
            }
            try {
                if (process.isAlive) {
                    clean = false
                    runCatching { process.outputStream.close() }
                    if (!interrupted) attempt { process.waitFor(500, TimeUnit.MILLISECONDS) }
                    if (process.isAlive) attempt { process.destroyForcibly() }
                    val reap = deadline(1000)
                    while (process.isAlive && System.nanoTime() < reap) {
                        attempt { process.waitFor(remaining(reap), TimeUnit.NANOSECONDS) }
                    }
                    attempt { assertFalse("Owned preview child survived bounded forced cleanup", process.isAlive) }
                }
            } finally {
                attempt { process.outputStream.close() }
                attempt { process.inputStream.close() }
                attempt { process.errorStream.close() }
                io.shutdownNow()
                val drain = deadline(2000)
                while (!io.isTerminated && System.nanoTime() < drain) {
                    attempt { io.awaitTermination(remaining(drain), TimeUnit.NANOSECONDS) }
                }
                attempt { assertTrue("Owned preview pipe workers survived cleanup", io.isTerminated) }
                if (interrupted) Thread.currentThread().interrupt()
            }
            if (!clean) record(AssertionError("Preview required fallback child cleanup"))
            primary?.let { throw it }
        }
    }

    private fun <T> owned(resource: Closeable, body: () -> T): T {
        var primary: Throwable? = null
        try { return body() } catch (error: Throwable) { primary = error; throw error }
        finally {
            try { resource.close() } catch (cleanup: Throwable) {
                if (primary != null) primary.addSuppressed(cleanup) else throw cleanup
            }
        }
    }

    private class ResourceScope : Closeable {
        private val resources = mutableListOf<Closeable>()
        fun <T : Closeable> add(resource: T): T { resources.add(resource); return resource }
        override fun close() {
            var primary: Throwable? = null
            resources.asReversed().forEach {
                try { it.close() } catch (error: Throwable) {
                    if (primary == null) primary = error else primary!!.addSuppressed(error)
                }
            }
            primary?.let { throw it }
        }
    }

    private inner class Fixture(scope: ResourceScope) {
        val run = UUID.randomUUID().toString().replace("-", "").take(12)
        val network = capturedNetwork()
        val generation = NativePreviewNetworkGeneration()
        val service = PreparedService(context)
        val broker = XraySocketProtector.forNumericPreview(service, network, generation).also {
            scope.add(Closeable {
                generation.revoke(); it.close()
                assertTrue("Owned preview broker did not drain", it.awaitClosed())
            })
        }
        val reservation = scope.add(ServerSocket(0, 1, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))))
        val port = reservation.localPort
        val credentials = LocalProxyCredentials.generate()
        val directory = File(context.noBackupFilesDir, "native-preview-$run").also {
            check(it.mkdir())
            scope.add(Closeable {
                var deleted = true
                it.listFiles().orEmpty().forEach { file -> if (!file.delete()) deleted = false }
                val directoryDeleted = it.delete()
                assertTrue("Owned preview configs/directory were not deleted", deleted && directoryDeleted)
                assertFalse(it.exists())
            })
            check(it.setReadable(false, false) && it.setReadable(true, true))
            check(it.setWritable(false, false) && it.setWritable(true, true))
            check(it.setExecutable(false, false) && it.setExecutable(true, true))
        }
        val source = JSONObject().put("inbounds", JSONArray().put(JSONObject()
            .put("listen", "127.0.0.1").put("port", port).put("protocol", "socks")
            .put("settings", JSONObject().put("auth", "password").put("udp", false)
                .put("accounts", JSONArray().put(JSONObject().put("user", credentials.username).put("pass", credentials.password))))))
            .put("outbounds", JSONArray()
                .put(JSONObject().put("protocol", "freedom").put("settings", JSONObject().put("domainStrategy", "UseIPv4")))
                .put(JSONObject().put("protocol", "freedom")))
            .put("dns", JSONObject().put("queryStrategy", "UseIPv4")
                .put("hosts", JSONObject().put("static-$run.dns-audit.invalid", "10.0.2.2"))
                .put("servers", JSONArray().put(JSONObject().put("address", "tcp://10.0.2.2:18285")
                    .put("domains", JSONArray().put("full:caller-$run.dns-audit.invalid")).put("skipFallback", true))
                    .put("localhost")))
        val original = source.toString().toByteArray(Charsets.UTF_8)
        val document = privateFile("source.json", original)
        val sourceDigest = digest(original)

        private fun privateFile(name: String, data: ByteArray) = File(directory, name).also {
            it.writeBytes(data)
            check(it.setReadable(false, false) && it.setReadable(true, true))
            check(it.setWritable(false, false) && it.setWritable(true, true))
        }

        fun candidate() = privateFile("rejected.json", JSONObject(source.toString())
            .put("api", JSONObject().put("services", JSONArray().put("StatsService")))
            .toString().toByteArray(Charsets.UTF_8))

        fun start(binary: File): Child {
            reservation.close() // The unavoidable bind handoff is limited to immediate start.
            return Child(binary, "run", document, broker)
        }

        fun status(until: Long = deadline(1000)): JSONObject = network.socketFactory.createSocket().use { socket ->
            socket.connect(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(10, 0, 2, 2)), 18283),
                TimeUnit.NANOSECONDS.toMillis(remaining(until)).coerceIn(1, 1000).toInt())
            socket.soTimeout = TimeUnit.NANOSECONDS.toMillis(remaining(until)).coerceIn(1, 1000).toInt()
            socket.outputStream.write("GET /native-preview?run=$run HTTP/1.1\r\nHost: 10.0.2.2\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
            val response = boundedRead(socket.inputStream) {
                socket.soTimeout = TimeUnit.NANOSECONDS.toMillis(remaining(until)).coerceIn(1, 1000).toInt()
            }
            check(response.startsWith("HTTP/1.0 200 ") || response.startsWith("HTTP/1.1 200 ")) { "Native fixture status HTTP failed" }
            JSONObject(response.substringAfter("\r\n\r\n")).also { assertEquals(run, it.getString("run")) }
        }

        fun awaitStatus(until: Long, predicate: (JSONObject) -> Boolean): JSONObject {
            while (true) {
                remaining(until)
                val value = status(minOf(until, deadline(1000)))
                remaining(until)
                if (predicate(value)) return value
                remaining(until)
                Thread.sleep(20)
            }
        }

        fun receivedHttp(name: String): Boolean =
            AuthenticatedSocksClient.connect(port, credentials, name, 18083).use { socket ->
                socket.soTimeout = 3000
                socket.outputStream.write("GET /native-preview-$run HTTP/1.1\r\nHost: $name\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
                val response = boundedRead(socket.inputStream)
                response.contains("flutter-vless-direct-bypass")
            }

        fun http(name: String) {
            assertTrue("Composed Core must transfer actual controlled HTTP bytes", receivedHttp(name))
        }

        fun assertQuery(status: JSONObject, prefix: String, transport: String) {
            val queries = status.getJSONArray("queries")
            assertTrue("Actual named DNS query did not reach its selected numeric transport",
                (0 until queries.length()).any {
                    val value = queries.getJSONObject(it)
                    value.optString("qname") == "$prefix-$run.dns-audit.invalid" &&
                        value.optString("transport") == transport && value.optInt("qtype") == 1
                })
            assertFalse("Static host unexpectedly left Core as a remote DNS query",
                (0 until queries.length()).any { queries.getJSONObject(it).optString("qname") == "static-$run.dns-audit.invalid" })
        }

        fun unchanged() {
            assertArrayEquals("Preview changed the caller's original JSON bytes", original, document.readBytes())
            assertArrayEquals(original, source.toString().toByteArray(Charsets.UTF_8))
        }

    }

    private fun boundedRead(input: InputStream, beforeRead: () -> Unit = {}): String {
        val bytes = ByteArrayOutputStream()
        val buffer = ByteArray(1024)
        while (true) {
            beforeRead()
            val count = input.read(buffer)
            if (count < 0) break
            check(bytes.size() + count <= MAX_OUTPUT) { "Controlled HTTP response exceeded its bound" }
            bytes.write(buffer, 0, count)
        }
        return bytes.toString("UTF-8")
    }

    private fun <T> fixture(body: (Fixture) -> T): T {
        assertNull("Disposable test package must already have VPN consent", VpnService.prepare(context))
        val scope = ResourceScope()
        return owned(scope) {
            val value = Fixture(scope)
            owned(Closeable { value.unchanged() }) { body(value) }
        }
    }

    private fun handshake(broker: XraySocketProtector, allowClosed: Boolean = false): Int {
        val fd = Os.socket(OsConstants.AF_INET, OsConstants.SOCK_DGRAM, 0)
        try {
            return try {
                LocalSocket().use { socket ->
                    socket.connect(LocalSocketAddress(broker.socketName, LocalSocketAddress.Namespace.ABSTRACT))
                    socket.soTimeout = 500
                    socket.setFileDescriptorsForSend(arrayOf(fd)); socket.outputStream.write('S'.code)
                    socket.setFileDescriptorsForSend(null); socket.inputStream.read()
                }
            } catch (error: Exception) {
                if (allowClosed) -1 else throw AssertionError("Live scoped broker exchange failed", error)
            }
        } finally { Os.close(fd) }
    }

    @Test fun composedCorePreservesCallerDnsHostsAndOldRuntimeAfterRejectedCandidate() {
        val binary = executable()
        val capability = Child(binary, "capabilities")
        owned(capability) {
            // Capabilities/check never need a broker or contact a resolver.
            // The child used here is intentionally separate from the live runtime.
            capability.message("available")
            capability.exited(0, listOf("available"))
        }
        fixture { f ->
            val before = f.status()
            assertEquals(0, before.getInt("native_default")); assertEquals(0, before.getInt("native_caller"))
            val prepared = Child(binary, "check", f.document)
            owned(prepared) {
                prepared.message("prepared", f.sourceDigest)
                prepared.exited(0, listOf("prepared"))
            }
            assertEquals(0, f.status().getInt("native_default"))
            assertEquals(0, f.status().getInt("native_caller"))
            val child = f.start(binary)
            owned(child) {
                child.message("started", f.sourceDigest)
                assertTrue(f.broker.awaitVerified())
                f.http("default-${f.run}.dns-audit.invalid")
                val default = f.status()
                assertTrue(default.getInt("native_default") > 0); assertEquals(0, default.getInt("native_caller"))
                f.assertQuery(default, "default", "native-default")
                f.http("caller-${f.run}.dns-audit.invalid")
                val caller = f.status()
                assertEquals(default.getInt("native_default"), caller.getInt("native_default"))
                assertTrue(caller.getInt("native_caller") > 0)
                f.assertQuery(caller, "caller", "native-caller")
                f.http("static-${f.run}.dns-audit.invalid")
                val hosts = f.status()
                assertEquals(caller.getInt("native_default"), hosts.getInt("native_default"))
                assertEquals(caller.getInt("native_caller"), hosts.getInt("native_caller"))
                f.assertQuery(hosts, "default", "native-default")
                val rejected = Child(binary, "check", f.candidate())
                owned(rejected) {
                    rejected.message("failed", stage = "prepare")
                    rejected.exited(1, listOf("failed"))
                }
                assertTrue("Rejected candidate must leave the original Core alive", child.process.isAlive)
                f.http("static-${f.run}.dns-audit.invalid")
                f.unchanged()
                child.stop(f.sourceDigest)
            }
        }
    }

    @Test fun stalledRealDnsStopsOnParentEofAfterGenerationRevocationBeforeNaturalTimeout() {
        val binary = executable()
        fixture { f ->
            val requests = Executors.newSingleThreadExecutor { task -> Thread(task, "native-preview-owned-request") }
            var primary: Throwable? = null
            try {
                val child = f.start(binary)
                owned(child) {
                    child.message("started", f.sourceDigest)
                    // One budget begins BEFORE the real request, so neither
                    // the 4s Core DNS bound nor a client read timeout can be
                    // mistaken for an owner-driven early EOF.
                    val stopDeadline = deadline(2000)
                    val lookup = requests.submit<Boolean> {
                        try { f.receivedHttp("stall-${f.run}.dns-audit.invalid") } catch (_: Exception) { false }
                    }
                    f.awaitStatus(stopDeadline) { it.getInt("native_stall_start") > 0 }
                    f.generation.revoke() // Denies new ACKs; existing Core sockets need owner close below.
                    assertEquals("Revoked live generation must refuse a new actual descriptor", 0, handshake(f.broker))
                    child.stop(f.sourceDigest, eof = true, until = stopDeadline)
                    assertFalse("A stopped stalled request must not publish successful HTTP bytes", lookup.get(remaining(stopDeadline), TimeUnit.NANOSECONDS))
                    val after = f.awaitStatus(stopDeadline) { it.getInt("native_stall_eof") > 0 }
                    assertEquals("Natural DNS timeout cannot stand in for owner-driven EOF", 0, after.getInt("native_stall_timeout"))
                    assertFalse(f.generation.isCurrent())
                    f.broker.close()
                    assertTrue(f.broker.awaitClosed(TimeUnit.NANOSECONDS.toMillis(remaining(stopDeadline)).coerceIn(1, 3000)))
                    assertNotEquals("Closed broker must never acknowledge a late descriptor", 1, handshake(f.broker, allowClosed = true))
                    assertFalse("No child restart is owned by this preview", child.process.isAlive)
                    f.unchanged()
                    remaining(stopDeadline)
                }
            } catch (error: Throwable) { primary = error; throw error }
            finally {
                requests.shutdownNow()
                try { assertTrue("Owned stalled request worker did not exit", requests.awaitTermination(2, TimeUnit.SECONDS)) }
                catch (cleanup: Throwable) { if (primary != null) primary.addSuppressed(cleanup) else throw cleanup }
            }
        }
    }

    companion object {
        private const val CAPABILITY = "native-instance-preview-1"
        private const val CORE_COMMIT = "92ccc939aaf4f8965f369cf0b142e005aeaa11d5"
        private const val MAX_OUTPUT = 16384
    }
}
