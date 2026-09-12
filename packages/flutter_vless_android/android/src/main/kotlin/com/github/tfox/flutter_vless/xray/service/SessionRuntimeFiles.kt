package com.github.tfox.flutter_vless.xray.service

import android.os.Process
import android.system.Os
import java.io.File

/** Bounded cleanup of this service's known files, never arbitrary app or standalone-delay files. */
internal object SessionRuntimeFiles {
    private val uuid = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    private val owned = Regex("(?:(?:xray|validate)-$uuid\\.json|tun-$uuid\\.yaml|fd-[0-9a-f]{8}-[0-9a-f]{3})")

    fun removeAbandoned(directory: File) {
        // A cold service may inherit files after process death. Never remove files still referenced
        // by a native process of this UID; the live worker's configuration belongs to that worker.
        val processes = File("/proc").listFiles() ?: return
        val active = mutableSetOf<String>()
        for (entry in processes) {
            if (!entry.name.all(Char::isDigit)) continue
            runCatching {
                if (Os.stat(entry.path).st_uid != Process.myUid()) return@runCatching
                val arguments = File(entry, "cmdline").inputStream().use { input ->
                    val bytes = ByteArray(8192)
                    val count = input.read(bytes)
                    if (count <= 0) emptyList() else bytes.copyOf(count).toString(Charsets.UTF_8).split('\u0000')
                }
                if (arguments.firstOrNull()?.substringAfterLast('/') in setOf("libxray.so", "libtun2socks.so")) active.addAll(arguments)
            }
        }
        cleanup(directory, active)
    }

    internal fun cleanup(directory: File, activePaths: Set<String>) {
        directory.listFiles()?.filter { owned.matches(it.name) && it.absolutePath !in activePaths }
            ?.forEach { runCatching { it.delete() } }
    }
}
