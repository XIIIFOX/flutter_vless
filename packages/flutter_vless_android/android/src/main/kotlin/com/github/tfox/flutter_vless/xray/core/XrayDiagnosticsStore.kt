package com.github.tfox.flutter_vless.xray.core

import android.util.Log
import java.io.File
import java.io.RandomAccessFile
import java.io.FileOutputStream
import com.github.tfox.flutter_vless.xray.service.NativeVlessOptions

/** The same allowlisted, content-free events feed logcat and the cross-process snapshot. */
internal object XrayDiagnosticsStore {
    internal enum class Event {
        SESSION_START, SESSION_STOP, CONFIG_REJECTED, PROFILE_UNAVAILABLE, PROFILE_SAVE_FAILED,
        WORKERS_START, WORKERS_STOP, WORKER_EXIT, WORKER_START_FAILED, PROTECT_FAILED,
        TUN_ESTABLISHED, TUN_FAILED, FD_SENT, FD_FAILED, AUTH_PROBE_FAILED, PATH_PROBE_FAILED,
        CONNECTED, RECOVERING, OUTPUT_DISCARDED, IO_FAILED, NATIVE_VALIDATION_FAILED
    }
    private const val FILE_NAME = "flutter_vless_events_v2.log"
    private const val MAX_BYTES = 128 * 1024
    private var activeGeneration = 0L
    private fun <T> locked(filesDir: File, body: () -> T): T {
        filesDir.mkdirs()
        return RandomAccessFile(File(filesDir,"flutter_vless_diagnostics_policy_v1.lock"),"rw").use { lock ->
            lock.channel.lock().use { body() }
        }
    }
    private fun policy(filesDir: File): NativeVlessOptions.Diagnostics {
        val file = File(filesDir,"flutter_vless_diagnostics_policy_v1.txt")
        if (!file.exists()) return NativeVlessOptions.Diagnostics()
        return runCatching {
            require(file.length() < 128)
            val fields = file.readText().trim().split(':')
            require(fields.size == 3 && fields[0] in listOf("true","false"))
            val bytes = fields[1].toInt(); val lines = fields[2].toInt()
            require(bytes in 4096..MAX_BYTES && lines in 1..300)
            NativeVlessOptions.Diagnostics(fields[0] == "true",bytes,lines)
        }.getOrElse { NativeVlessOptions.Diagnostics(enabled = false) }
    }
    @Synchronized fun configure(filesDir: File, options: NativeVlessOptions.Diagnostics) = locked(filesDir) {
        require(options.maxBytes in 4096..MAX_BYTES && options.maxLines in 1..300)
        val target = File(filesDir,"flutter_vless_diagnostics_policy_v1.txt")
        val temporary = File(filesDir,target.name + ".new")
        FileOutputStream(temporary).use { output ->
            output.write("${options.enabled}:${options.maxBytes}:${options.maxLines}".toByteArray())
            output.fd.sync()
        }
        check(temporary.renameTo(target)) { "Could not save diagnostics policy" }
        val events = File(filesDir,FILE_NAME)
        if (!options.enabled) events.writeText("")
        else if (events.exists()) events.writeText(readTail(events,options.maxBytes,options.maxLines) + "\n")
    }

    /** Called by the service owner after all preceding native writers are stopped. */
    @Synchronized fun reset(filesDir: File): Long = locked(filesDir) {
        activeGeneration++
        migrateLegacy(filesDir)
        filesDir.mkdirs()
        File(filesDir, FILE_NAME).writeText("")
        activeGeneration
    }
    @Synchronized fun migrateLegacy(filesDir: File) {
        listOf("flutter_vless_xray_debug.log", "access.log", "error.log").forEach {
            runCatching { File(filesDir, it).delete() }
        }
    }
    @Synchronized fun currentGeneration() = activeGeneration

    @Synchronized fun event(filesDir: File, event: Event, generation: Long? = null, value: Long? = null) {
        if (generation != null && generation != activeGeneration) return
        runCatching {
            locked(filesDir) {
                val options = policy(filesDir)
                if (options.enabled) {
                    val line = event.name + (value?.let { " value=$it" } ?: "")
                    Log.i("FlutterVlessRuntime", line)
                    val file = File(filesDir, FILE_NAME)
                    file.appendText("$line\n")
                    if (file.length() > options.maxBytes || file.useLines { it.take(options.maxLines + 1).count() } > options.maxLines)
                        file.writeText(readTail(file, options.maxBytes - 1, options.maxLines) + "\n")
                }
            }
        }
    }

    /** Legacy callers cannot smuggle native data through the old append entry point. */
    @Suppress("UNUSED_PARAMETER")
    fun append(filesDir: File, source: String, message: String, generation: Long? = null) {
        event(filesDir, Event.OUTPUT_DISCARDED, generation)
    }

    @Synchronized fun snapshot(filesDir: File): String = locked(filesDir) {
        val options = policy(filesDir)
        if (!options.enabled) "" else readTail(File(filesDir, FILE_NAME), minOf(40 * 1024,options.maxBytes), options.maxLines)
        .lineSequence().filter { line ->
            line.matches(Regex("(?:${Event.values().joinToString("|") { it.name }})(?: value=-?[0-9]+)?"))
        }.joinToString("\n")
    }

    internal fun readTail(file: File, maxBytes: Int, maxLines: Int): String {
        if (!file.isFile || maxBytes <= 0 || maxLines <= 0) return ""
        return runCatching {
            RandomAccessFile(file, "r").use { input ->
                val start = (input.length() - maxBytes).coerceAtLeast(0)
                input.seek(start)
                val bytes = ByteArray((input.length() - start).toInt())
                input.readFully(bytes)
                val text = bytes.toString(Charsets.UTF_8)
                (if (start > 0) text.substringAfter('\n', "") else text)
                    .lineSequence().filter(String::isNotBlank).toList().takeLast(maxLines).joinToString("\n")
            }
        }.getOrDefault("")
    }
}
