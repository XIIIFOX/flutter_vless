package com.github.tfox.flutter_vless.xray.core

import org.json.JSONObject
import java.io.File
import java.util.UUID

/** Exact final Core input, shared by native preflight and startup without reserialization. */
internal class NativeRuntimeConfig private constructor(private val frozen: ByteArray) {
    val bytes: ByteArray get() = frozen.clone()
    fun writeTo(file: File) { file.writeBytes(frozen) }
    /** The fixed parser command creates no descendants. Success requires bounded drain/reap. */
    fun preflight(directory: File, launch: (File) -> Process, timeoutMillis: Long = 10_000,
                  nanoTime: () -> Long = System::nanoTime): Boolean {
        val file = File(directory, "validate-${UUID.randomUUID()}.json")
        var process: Process? = null
        return try {
            writeTo(file)
            process = launch(file)
            BoundedCoreCommand.capture(process, timeoutMillis = timeoutMillis, nanoTime = nanoTime) != null
        } catch (_: Exception) { false }
        finally {
            // An un-reaped refusal must not lose its still-referenced input.
            // Cold cleanup already preserves live owned Core command-line paths.
            if (process?.isAlive != true) file.delete()
        }
    }
    override fun toString() = "NativeRuntimeConfig(<private>)"
    companion object {
        fun freeze(json: JSONObject) = NativeRuntimeConfig(json.toString().toByteArray(Charsets.UTF_8))
    }
}
