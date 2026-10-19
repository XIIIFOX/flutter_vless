package com.github.tfox.flutter_vless.xray.core

import com.github.tfox.flutter_vless.xray.service.NativeRoutingEnvelope
import org.json.JSONObject
import java.io.Closeable
import java.io.File
import java.util.UUID

/** Exact final Core input pair, shared by native preflight and startup without reserialization. */
internal class NativeRuntimeConfig private constructor(private val frozen: ByteArray, private val spec: ByteArray? = null) {
    val bytes: ByteArray get() = frozen.clone()
    val hasRouting: Boolean get() = spec != null
    fun writeTo(file: File) { file.writeBytes(frozen) }

    internal class Inputs(val config: File, val spec: File?) : Closeable {
        fun command(executable: String, check: Boolean): List<String> = if (spec == null)
            listOf(executable, "run") + (if (check) listOf("-test") else emptyList()) + listOf("-config", config.absolutePath)
        else listOf(executable, "native-routing", if (check) "check" else "run", "--config", config.absolutePath, "--spec", spec.absolutePath)
        override fun close() {
            var failed=false
            for(file in listOfNotNull(spec,config)) if(!file.delete() && file.exists()) failed=true
            check(!failed) { "Private runtime cleanup failed" }
        }
    }
    fun createInputs(directory: File, prefix: String): Inputs {
        require(prefix in setOf("validate", "xray"))
        val stem="$prefix-${UUID.randomUUID()}"
        val config=File(directory, "$stem.json")
        val metadata=if (spec == null) null else File(directory, "$stem.spec.json")
        val owned=mutableListOf<File>()
        try {
            fun write(file: File, data: ByteArray) {
                check(file.createNewFile()) { "Private runtime input unavailable" }; owned += file
                check(file.setReadable(false, false) && file.setWritable(false, false) && file.setExecutable(false, false) &&
                    file.setReadable(true, true) && file.setWritable(true, true)) { "Private runtime permissions unavailable" }
                file.writeBytes(data)
            }
            write(config, frozen); if (metadata != null) write(metadata, requireNotNull(spec))
            return Inputs(config, metadata)
        } catch (error: Throwable) { owned.forEach { it.delete() }; throw error }
    }
    /** Fixed parser commands create no descendants. Success requires bounded drain/reap and strict routing status. */
    fun preflightInputs(directory: File, launch: (Inputs) -> Process, timeoutMillis: Long = 10_000,
                  nanoTime: () -> Long = System::nanoTime): Boolean {
        var inputs: Inputs? = null; var process: Process? = null
        return try {
            inputs=createInputs(directory, "validate")
            process=launch(inputs)
            val result=BoundedCoreCommand.capture(process, timeoutMillis=timeoutMillis, nanoTime=nanoTime)
            result != null && (!hasRouting || NativeRoutingCommand.checked(result))
        } catch (_: Exception) { false }
        finally {
            // Keep still-referenced inputs when bounded reap refuses to complete.
            if (process?.isAlive != true) inputs?.close()
        }
    }
    fun preflight(directory: File, launch: (File) -> Process, timeoutMillis: Long = 10_000,
                  nanoTime: () -> Long = System::nanoTime): Boolean {
        require(!hasRouting) { "Routing requires its complete private input pair" }
        return preflightInputs(directory, { launch(it.config) }, timeoutMillis, nanoTime)
    }
    override fun toString() = "NativeRuntimeConfig(<private>)"
    companion object {
        fun freeze(json: JSONObject) = NativeRuntimeConfig(json.toString().toByteArray(Charsets.UTF_8))
        fun routing(envelope: NativeRoutingEnvelope) = NativeRuntimeConfig(envelope.configurationData, envelope.metadataData)
    }
}
