package com.github.tfox.flutter_vless.xray.core

import java.io.File
import java.io.RandomAccessFile
import java.nio.charset.StandardCharsets

/**
 * Cross-process, bounded diagnostics for the most recent Android Xray session.
 *
 * [XrayVPNService] runs in a dedicated Android process, while MethodChannel
 * calls are handled in the application process. An internal file is therefore
 * used instead of an in-memory singleton. There is one writer per session; a
 * concurrent reader may briefly observe an in-progress rotation and can retry;
 * diagnostics deliberately avoid blocking the VPN service with cross-process
 * coordination.
 */
internal object XrayDiagnosticsStore {
    private const val DIAGNOSTICS_FILE = "flutter_vless_xray_debug.log"
    private const val ACCESS_LOG_FILE = "access.log"
    private const val ERROR_LOG_FILE = "error.log"
    private const val MAX_DIAGNOSTICS_BYTES = 128 * 1024
    private const val MAX_DIAGNOSTICS_SNAPSHOT_BYTES = 40 * 1024
    private const val MAX_XRAY_FILE_SNAPSHOT_BYTES = 10 * 1024
    private const val MAX_SNAPSHOT_LINES = 300
    private const val MAX_MESSAGE_BYTES = 16 * 1024
    private var activeGeneration = 0L

    @Synchronized
    fun reset(filesDir: File): Long {
        activeGeneration++
        filesDir.mkdirs()
        listOf(DIAGNOSTICS_FILE, ACCESS_LOG_FILE, ERROR_LOG_FILE).forEach { name ->
            runCatching { File(filesDir, name).writeText("") }
        }
        return activeGeneration
    }

    @Synchronized
    fun currentGeneration(): Long = activeGeneration

    @Synchronized
    fun append(
        filesDir: File,
        source: String,
        message: String,
        generation: Long? = null
    ) {
        if (generation != null && generation != activeGeneration) return
        val normalizedSource = source.replace(Regex("[\\r\\n]+"), " ").trim()
        val normalizedMessage = boundedUtf8Tail(
            message
            .replace("\r\n", "\n")
            .replace('\r', '\n'),
            MAX_MESSAGE_BYTES
        )
        if (normalizedMessage.isBlank()) return

        val target = File(filesDir, DIAGNOSTICS_FILE)
        target.parentFile?.mkdirs()
        val payload = normalizedMessage
            .lineSequence()
            .filter { it.isNotEmpty() }
            .joinToString(separator = "\n", postfix = "\n") { line ->
                "[$normalizedSource] $line"
            }
        runCatching {
            target.appendText(payload, StandardCharsets.UTF_8)
            if (target.length() > MAX_DIAGNOSTICS_BYTES) {
                val tail = readTail(
                    target,
                    maxBytes = MAX_DIAGNOSTICS_BYTES / 2,
                    maxLines = Int.MAX_VALUE
                )
                target.writeText(tail, StandardCharsets.UTF_8)
                if (tail.isNotEmpty() && !tail.endsWith('\n')) {
                    target.appendText("\n", StandardCharsets.UTF_8)
                }
            }
        }
    }

    fun snapshot(filesDir: File): String {
        val sections = mutableListOf<String>()
        addSection(
            sections,
            "Android Xray/tun2socks output",
            File(filesDir, DIAGNOSTICS_FILE),
            MAX_DIAGNOSTICS_SNAPSHOT_BYTES,
            MAX_SNAPSHOT_LINES
        )
        addSection(
            sections,
            "Xray access log",
            File(filesDir, ACCESS_LOG_FILE),
            MAX_XRAY_FILE_SNAPSHOT_BYTES,
            120
        )
        addSection(
            sections,
            "Xray error log",
            File(filesDir, ERROR_LOG_FILE),
            MAX_XRAY_FILE_SNAPSHOT_BYTES,
            120
        )
        return sections.joinToString("\n")
    }

    internal fun readTail(file: File, maxBytes: Int, maxLines: Int): String {
        if (!file.isFile || maxBytes <= 0 || maxLines <= 0) return ""
        return runCatching {
            RandomAccessFile(file, "r").use { input ->
                val length = input.length()
                if (length <= 0) return@use ""
                val start = (length - maxBytes).coerceAtLeast(0)
                input.seek(start)
                val bytes = ByteArray((length - start).toInt())
                input.readFully(bytes)

                var firstByte = 0
                if (start > 0) {
                    val newline = bytes.indexOf('\n'.code.toByte())
                    if (newline < 0) return@use ""
                    firstByte = newline + 1
                }
                val decoded = String(
                    bytes,
                    firstByte,
                    bytes.size - firstByte,
                    StandardCharsets.UTF_8
                )
                decoded
                    .lineSequence()
                    .filter { it.isNotEmpty() }
                    .toList()
                    .takeLast(maxLines)
                    .joinToString("\n")
            }
        }.getOrDefault("")
    }

    private fun boundedUtf8Tail(value: String, maxBytes: Int): String {
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        if (bytes.size <= maxBytes) return value
        var start = bytes.size - maxBytes
        while (start < bytes.size && bytes[start].toInt() and 0xc0 == 0x80) {
            start++
        }
        return String(bytes, start, bytes.size - start, StandardCharsets.UTF_8)
    }

    private fun addSection(
        sections: MutableList<String>,
        title: String,
        file: File,
        maxBytes: Int,
        maxLines: Int
    ) {
        val tail = readTail(file, maxBytes, maxLines)
        if (tail.isNotEmpty()) {
            sections += "--- $title bytes=${file.length()} ---\n$tail"
        }
    }
}
