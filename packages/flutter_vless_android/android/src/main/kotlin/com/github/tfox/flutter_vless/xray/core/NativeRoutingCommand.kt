package com.github.tfox.flutter_vless.xray.core

import org.json.JSONObject
import org.json.JSONTokener

/** Closed fixed CLI status only. Never accept stock/unknown binaries or an arbitrary caller API. */
internal object NativeRoutingCommand {
    fun capabilities(bytes: ByteArray?) = status(bytes, "capabilities", true)
    fun checked(bytes: ByteArray?) = status(bytes, "check", false)
    private fun status(bytes: ByteArray?, stage: String, capability: Boolean): Boolean = try {
        if (bytes == null || bytes.size > 4096) false else {
            val parser=JSONTokener(bytes.toString(Charsets.UTF_8))
            val json=parser.nextValue() as? JSONObject
            json != null && parser.nextClean() == '\u0000' &&
                json.keys().asSequence().toSet() == (if (capability) setOf("stage", "code", "capability") else setOf("stage", "code")) &&
                json.opt("stage") == stage && json.opt("code") is Int && json.getInt("code") == 0 &&
                (!capability || (json.opt("capability") is Int && json.getInt("capability") == 1))
        }
    } catch (_: Exception) { false }
}
