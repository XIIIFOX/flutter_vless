package com.github.tfox.flutter_vless.xray.service

import android.content.Context
import android.util.AtomicFile
import com.google.gson.Gson
import java.io.File
import java.io.RandomAccessFile

/** Non-secret preferences only. Each read is fresh across Flutter/daemon processes. */
internal class NativeOptionsStore(private val context: Context) {
    private val file get() = AtomicFile(File(context.noBackupFilesDir, "flutter_vless_options_v1.json"))
    private fun <T> locked(body: () -> T): T = synchronized(mutex) {
        context.noBackupFilesDir.mkdirs()
        RandomAccessFile(File(context.noBackupFilesDir,"flutter_vless_options_v1.lock"),"rw").use { lock ->
            lock.channel.lock().use { body() }
        }
    }
    fun read(): NativeVlessOptions = locked {
        if (!file.baseFile.exists()) return@locked NativeVlessOptions()
        runCatching {
            val bytes = file.openRead().use { input -> require(input.channel.size() <= 16384); input.readBytes() }
            NativeVlessOptions.parse(Gson().fromJson(bytes.toString(Charsets.UTF_8), Map::class.java))
        }.getOrElse { NativeVlessOptions(diagnostics = NativeVlessOptions.Diagnostics(enabled = false)) }
    }
    fun write(options: NativeVlessOptions) = locked {
        val bytes = Gson().toJson(options).toByteArray(Charsets.UTF_8)
        require(bytes.size <= 16384)
        val output = file.startWrite()
        try { output.write(bytes); file.finishWrite(output) }
        catch (error: Exception) { file.failWrite(output); throw error }
    }
    private companion object { val mutex = Any() }
}
