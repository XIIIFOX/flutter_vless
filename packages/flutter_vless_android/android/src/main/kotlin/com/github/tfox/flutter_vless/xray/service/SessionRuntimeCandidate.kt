package com.github.tfox.flutter_vless.xray.service

import com.github.tfox.flutter_vless.xray.core.NativeRuntimeConfig
import org.json.JSONObject
import java.io.Closeable

/** Owns a candidate's probe until admission, then until the active worker adopts it. */
internal class SessionRuntimeCandidate<P : Closeable> private constructor(
    val configuration: NativeRuntimeConfig, private var probe: P?
) : Closeable {
    private var admitted = false
    private var consumed = false
    private var closed = false

    fun admit(isCurrent: () -> Boolean, persist: () -> Unit,
              commit: (SessionRuntimeCandidate<P>) -> Boolean): Boolean {
        check(!closed && !admitted && !consumed)
        var primary: Throwable? = null
        try {
            if (!isCurrent()) return false
            persist()
            if (!isCurrent()) return false
            admitted = commit(this)
            return admitted
        } catch (error: Throwable) { primary = error; throw error }
        finally {
            if (!admitted) try { close() }
            catch (cleanup: Throwable) { if (primary != null) primary.addSuppressed(cleanup) else throw cleanup }
        }
    }

    fun takeProbe(): P? {
        check(!closed && !consumed)
        consumed = true
        return probe.also { probe = null }
    }

    override fun close() {
        if (closed) return
        probe?.close()
        probe = null
        closed = true
    }

    companion object {
        fun <P : Closeable> prepare(base: JSONObject, createProbe: () -> P?,
                                   configure: (P, JSONObject) -> JSONObject,
                                   validate: (NativeRuntimeConfig) -> Boolean): SessionRuntimeCandidate<P> {
            var probe: P? = null
            try {
                val working = JSONObject(base.toString())
                probe = createProbe()
                val final = if (probe == null) working else configure(probe, working)
                val frozen = NativeRuntimeConfig.freeze(final)
                require(validate(frozen)) { "Native configuration rejected" }
                return SessionRuntimeCandidate(frozen, probe)
            } catch (error: Throwable) {
                try { probe?.close() } catch (cleanup: Throwable) { error.addSuppressed(cleanup) }
                throw error
            }
        }
    }
}
