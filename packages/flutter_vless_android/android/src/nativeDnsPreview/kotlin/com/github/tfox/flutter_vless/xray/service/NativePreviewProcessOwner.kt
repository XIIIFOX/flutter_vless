package com.github.tfox.flutter_vless.xray.service

import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.InputStream
import java.util.Locale
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.json.JSONObject

/** Fixed development child protocol. Raw output and source data never escape this owner. */
internal class NativePreviewProcessOwner(private val spec: NativePreviewVpnSpec) : Closeable {
    private val io = Executors.newFixedThreadPool(2) { task ->
        Thread(task, "native-vpn-core-pipe").apply { isDaemon = true }
    }
    private val events = LinkedBlockingQueue<JSONObject>(8)
    private val pipeFailure = AtomicReference<String?>()
    private val stderrCount = AtomicInteger()
    @Volatile private var closing = false
    private var ownedProcess: Process? = null
    private val process: Process get() = requireNotNull(ownedProcess)
    private var stdout: Future<*>? = null
    private var stderr: Future<*>? = null
    private var monitor: Thread? = null
    val isAlive: Boolean get() = ownedProcess?.isAlive == true

    // The Session must retain this owner before launch can create any child.
    fun launch(command: String, broker: XraySocketProtector? = null) {
        check(ownedProcess == null && !closing)
        val builder = ProcessBuilder(spec.arguments(command)).directory(spec.directory)
        sanitize(builder)
        if (broker != null) builder.environment()["FLUTTER_VLESS_PROTECT_SOCKET"] = broker.socketName
        ownedProcess = builder.start()
        stdout = io.submit { drain(process.inputStream, true) }
        stderr = io.submit { drain(process.errorStream, false) }
    }

    fun prepared() {
        val until = deadline(5000)
        event("prepared", until)
        exited(until)
    }

    fun started(broker: XraySocketProtector, onExit: (NativePreviewProcessOwner) -> Unit) {
        event("started", deadline(5000))
        check(isAlive && broker.awaitVerified()) { "native-protection-not-ready" }
        monitor = Thread({
            runCatching { process.waitFor() }
            if (!closing) onExit(this)
        }, "native-vpn-core-monitor").apply { isDaemon = true }
        monitor!!.start()
    }

    private fun drain(input: InputStream, protocol: Boolean) {
        try {
            input.use { stream ->
                var total = 0L
                val line = ByteArrayOutputStream()
                val buffer = ByteArray(512)
                while (true) {
                    val count = stream.read(buffer)
                    if (count < 0) break
                    total += count
                    if (!protocol) stderrCount.addAndGet(count)
                    if (total > 16384) {
                        pipeFailure.compareAndSet(null, "output-limit")
                        continue // Drain without retaining any additional bytes.
                    }
                    if (protocol) for (index in 0 until count) {
                        val value = buffer[index].toInt() and 255
                        if (value == 10) {
                            val event = try { JSONObject(line.toString("UTF-8")) } catch (_: Exception) { null }
                            line.reset()
                            if (event == null || !events.offer(event)) pipeFailure.compareAndSet(null, "output-schema")
                        } else line.write(value)
                    }
                }
                if (protocol && line.size() != 0) pipeFailure.compareAndSet(null, "output-framing")
            }
        } catch (_: Exception) { pipeFailure.compareAndSet(null, "output-drain") }
    }

    private fun event(status: String, until: Long) {
        val message = events.poll(remaining(until), TimeUnit.NANOSECONDS) ?: error("native-event-timeout")
        val fields = setOf("schema", "capability", "core_commit", "status", "source_digest", "policy_epoch",
            "host_qualified", "system_resolver_attempts")
        check(message.keys().asSequence().toSet() == fields) { "native-event-schema" }
        check(message.getInt("schema") == 1 && message.getString("capability") == NativePreviewVpnInput.CAPABILITY &&
            message.getString("core_commit") == NativePreviewVpnInput.CORE_COMMIT && message.getString("status") == status &&
            message.getString("source_digest") == spec.input.sourceDigest && message.getString("policy_epoch") == spec.epoch &&
            !message.getBoolean("host_qualified") && message.getLong("system_resolver_attempts") == 0L) { "native-event-identity" }
        check(pipeFailure.get() == null) { "native-output-failure" }
    }

    private fun exited(until: Long) {
        check(process.waitFor(remaining(until), TimeUnit.NANOSECONDS)) { "native-exit-timeout" }
        check(process.exitValue() == 0) { "native-exit-status" }
        requireNotNull(stdout).get(remaining(until), TimeUnit.NANOSECONDS)
        requireNotNull(stderr).get(remaining(until), TimeUnit.NANOSECONDS)
        check(pipeFailure.get() == null && stderrCount.get() == 0 && events.isEmpty()) { "native-output-failure" }
    }

    fun stop() {
        closing = true // Invalidate monitor admission before any native I/O.
        val until = deadline(3500)
        process.outputStream.write("stop\n".toByteArray(Charsets.US_ASCII))
        process.outputStream.flush()
        process.outputStream.close()
        event("stopped", until)
        exited(until)
    }

    fun forceForTest() { ownedProcess?.destroyForcibly() }

    override fun close() {
        closing = true
        var interrupted = Thread.interrupted()
        var failure: Throwable? = null
        fun record(error: Throwable) {
            if (failure == null) failure = error else failure!!.addSuppressed(error)
        }
        fun attempt(action: () -> Unit) {
            try { action() } catch (_: InterruptedException) { interrupted = true }
            catch (error: Throwable) { record(error) }
        }
        try {
            if (isAlive) {
                attempt { process.outputStream.close() }
                if (!interrupted) attempt { process.waitFor(500, TimeUnit.MILLISECONDS) }
                if (process.isAlive) attempt { process.destroyForcibly() }
                val reap = deadline(1000)
                while (process.isAlive && System.nanoTime() < reap)
                    attempt { process.waitFor(remaining(reap), TimeUnit.NANOSECONDS) }
                attempt { check(!process.isAlive) { "native-child-not-reaped" } }
            }
        } finally {
            ownedProcess?.let { child ->
                attempt { child.outputStream.close() }
                attempt { child.inputStream.close() }
                attempt { child.errorStream.close() }
            }
            io.shutdownNow()
            val drain = deadline(2000)
            while (!io.isTerminated && System.nanoTime() < drain)
                attempt { io.awaitTermination(remaining(drain), TimeUnit.NANOSECONDS) }
            attempt { check(io.isTerminated) { "native-pipes-not-drained" } }
            monitor?.let { thread ->
                if (thread !== Thread.currentThread()) attempt { thread.join(1000); check(!thread.isAlive) { "native-monitor-not-drained" } }
            }
            if (interrupted) Thread.currentThread().interrupt()
        }
        failure?.let { throw it }
    }

    companion object {
        fun deadline(milliseconds: Long) = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(milliseconds)
        fun remaining(until: Long): Long = (until - System.nanoTime()).also { check(it > 0) { "native-deadline" } }

        fun sanitize(builder: ProcessBuilder) {
            builder.environment().keys.toList().filter {
                val key = it.uppercase(Locale.ROOT)
                key.startsWith("XRAY") || key.startsWith("V2RAY") || key.startsWith("FLUTTER_VLESS_") ||
                    key in setOf("SSLKEYLOGFILE", "GODEBUG", "GOTRACEBACK", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
            }.forEach { builder.environment().remove(it) }
        }

    }
}

/** Only the separately verified bind-before-UDP-associate development forwarder. */
internal class NativePreviewForwarderOwner(private val spec: NativePreviewVpnSpec,
    private val onExit: (NativePreviewForwarderOwner) -> Unit) : Closeable {
    @Volatile private var closing = false
    private var ownedProcess: Process? = null
    val isAlive: Boolean get() = ownedProcess?.isAlive == true
    private var monitor: Thread? = null

    // Assigned to Session.forwarder before a native child can exist.
    fun launch() {
        check(ownedProcess == null && !closing)
        val process = ProcessBuilder(spec.input.forwarder.absolutePath, "-sock-path", spec.fdSocket.absolutePath,
            "-config", spec.forwarderConfig.absolutePath).directory(spec.directory).redirectErrorStream(true)
            .also(NativePreviewProcessOwner::sanitize).start()
        ownedProcess = process
        monitor = Thread({
            runCatching { process.inputStream.use { input ->
                val buffer = ByteArray(4096)
                while (input.read(buffer) >= 0) { /* Never retain or report native output. */ }
            } }
            runCatching { process.waitFor() }
            if (!closing) onExit(this)
        }, "native-vpn-forwarder-monitor").apply { isDaemon = true }
        monitor!!.start()
    }

    fun forceForTest() { ownedProcess?.destroyForcibly() }

    override fun close() {
        closing = true
        var interrupted = Thread.interrupted()
        var failure: Throwable? = null
        fun attempt(action: () -> Unit) {
            try { action() } catch (_: InterruptedException) { interrupted = true }
            catch (error: Throwable) { if (failure == null) failure = error else failure!!.addSuppressed(error) }
        }
        try {
            ownedProcess?.let { process ->
                attempt { process.destroy() }
                if (!interrupted) attempt { process.waitFor(500, TimeUnit.MILLISECONDS) }
                if (process.isAlive) attempt { process.destroyForcibly() }
                val until = NativePreviewProcessOwner.deadline(1000)
                while (process.isAlive && System.nanoTime() < until)
                    attempt { process.waitFor(NativePreviewProcessOwner.remaining(until), TimeUnit.NANOSECONDS) }
                attempt { check(!process.isAlive) { "forwarder-child-not-reaped" } }
            }
        } finally {
            ownedProcess?.let { process ->
                attempt { process.outputStream.close() }
                attempt { process.inputStream.close() }
                attempt { process.errorStream.close() }
            }
            monitor?.let { thread ->
                if (thread !== Thread.currentThread()) attempt { thread.join(1000); check(!thread.isAlive) { "forwarder-monitor-not-drained" } }
            }
            if (interrupted) Thread.currentThread().interrupt()
        }
        failure?.let { throw it }
    }
}
