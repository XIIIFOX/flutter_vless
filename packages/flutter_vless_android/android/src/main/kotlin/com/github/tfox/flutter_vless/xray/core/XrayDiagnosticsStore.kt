package com.github.tfox.flutter_vless.xray.core

import android.util.Log
import java.io.File
import java.io.RandomAccessFile

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

    /** Called by the service owner after all preceding native writers are stopped. */
    @Synchronized fun reset(filesDir: File): Long {
        activeGeneration++
        migrateLegacy(filesDir)
        filesDir.mkdirs()
        File(filesDir, FILE_NAME).writeText("")
        return activeGeneration
    }
    @Synchronized fun migrateLegacy(filesDir: File) {
        listOf("flutter_vless_xray_debug.log", "access.log", "error.log").forEach {
            runCatching { File(filesDir, it).delete() }
        }
    }
    @Synchronized fun currentGeneration() = activeGeneration

    @Synchronized fun event(filesDir: File, event: Event, generation: Long? = null, value: Long? = null) {
        if (generation != null && generation != activeGeneration) return
        val line = event.name + (value?.let { " value=$it" } ?: "")
        Log.i("FlutterVlessRuntime", line)
        runCatching {
            filesDir.mkdirs()
            val file = File(filesDir, FILE_NAME)
            file.appendText("$line\n")
            if (file.length() > MAX_BYTES) file.writeText(readTail(file, MAX_BYTES / 2, Int.MAX_VALUE) + "\n")
        }
    }

    /** Legacy callers cannot smuggle native data through the old append entry point. */
    @Suppress("UNUSED_PARAMETER")
    fun append(filesDir: File, source: String, message: String, generation: Long? = null) {
        event(filesDir, Event.OUTPUT_DISCARDED, generation)
    }

    fun snapshot(filesDir: File): String = readTail(File(filesDir, FILE_NAME), 40 * 1024, 300)
        .lineSequence().filter { line ->
            line.matches(Regex("(?:${Event.values().joinToString("|") { it.name }})(?: value=-?[0-9]+)?"))
        }.joinToString("\n")

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
