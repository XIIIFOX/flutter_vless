package com.github.tfox.flutter_vless.xray.service

import android.content.Context
import android.util.AtomicFile
import com.google.gson.Gson
import java.io.File
import java.io.RandomAccessFile
import java.security.MessageDigest
import java.util.UUID

/** Non-secret preferences only. Each read is fresh across Flutter/daemon processes. */
internal class NativeOptionsStore(private val context: Context) {
    private val file get() = AtomicFile(File(context.noBackupFilesDir, "flutter_vless_options_v1.json"))
    private fun <T> locked(body: () -> T): T = synchronized(mutex) {
        context.noBackupFilesDir.mkdirs()
        RandomAccessFile(File(context.noBackupFilesDir,"flutter_vless_options_v1.lock"),"rw").use { lock ->
            lock.channel.lock().use { body() }
        }
    }
    private fun snapshotLocked(): QuickAccessSnapshot {
        if (!file.baseFile.exists()) return QuickAccessSnapshot(NativeVlessOptions(), "")
        return runCatching {
            val bytes = file.openRead().use { input -> require(input.channel.size() <= 16384); input.readBytes() }
            decode(bytes)
        }.getOrElse { QuickAccessSnapshot(NativeVlessOptions(diagnostics = NativeVlessOptions.Diagnostics(enabled = false)), "") }
    }
    fun read(): NativeVlessOptions = readSnapshot().options
    fun readSnapshot(): QuickAccessSnapshot = locked { snapshotLocked() }
    /** Linearizes a pending action with cross-process option writes. Do not recursively read this store in body. */
    fun <T> withSnapshot(action: QuickAccessAction, lockedDevice: () -> Boolean, body: (NativeVlessOptions) -> T): T? = locked {
        val snapshot = snapshotLocked()
        if (!action.permits(snapshot, lockedDevice())) null else body(snapshot.options)
    }
    /** Every new control intent revokes older callbacks, including Start/Stop ABA with unchanged preferences. */
    fun beginAction(): QuickAccessSnapshot = locked {
        val current = snapshotLocked()
        if (!current.options.quickAccess.enabled || current.revision.isEmpty()) current else {
            val next = QuickAccessSnapshot(current.options, UUID.randomUUID().toString().replace("-", ""))
            writeLocked(encode(next.options, next.revision)); next
        }
    }
    fun invalidateActions() { beginAction() }
    fun write(options: NativeVlessOptions) = locked {
        writeLocked(encode(options, UUID.randomUUID().toString().replace("-", "")))
    }
    private fun writeLocked(bytes: ByteArray) {
        val output = file.startWrite()
        try { output.write(bytes); file.finishWrite(output) }
        catch (error: Exception) { file.failWrite(output); throw error }
    }
    internal companion object {
        private val mutex = Any()
        // The revision and options share ONE atomic commit; no sidecar/ABA window.
        internal fun encode(options: NativeVlessOptions, revision: String): ByteArray {
            require(revision.matches(Regex("[a-f0-9]{32}")))
            val json = Gson().toJsonTree(options).asJsonObject
            json.addProperty("_quickAccessRevision", revision)
            return Gson().toJson(json).toByteArray(Charsets.UTF_8).also { require(it.size <= 16384) }
        }
        internal fun decode(bytes: ByteArray): QuickAccessSnapshot {
            require(bytes.size <= 16384)
            val raw = Gson().fromJson(bytes.toString(Charsets.UTF_8), Map::class.java)
            val options = NativeVlessOptions.parse(raw)
            // Legacy files remain readable. Their exact committed bytes identify an old action.
            val revision = if (raw.containsKey("_quickAccessRevision")) {
                (raw["_quickAccessRevision"] as? String)?.also { require(it.matches(Regex("[a-f0-9]{32}"))) }
                    ?: error("Invalid options revision")
            } else MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
            return QuickAccessSnapshot(options, revision)
        }
    }
}
