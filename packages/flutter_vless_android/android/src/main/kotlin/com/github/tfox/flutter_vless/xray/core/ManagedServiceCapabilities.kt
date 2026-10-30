package com.github.tfox.flutter_vless.xray.core

import org.json.JSONObject
import org.json.JSONTokener

/** Fixed CLI reply only; absence, unknown bits and malformed replies deny admission. */
internal object ManagedServiceCapabilities {
    const val GEODATA = 1
    const val XDRIVE_STORAGE = 2
    const val XDRIVE_WORKERS = 4
    const val XDRIVE = 6 // Both owned storage and idle workers are mandatory.
    fun required(json: String): Int = (if (XrayGeodataAssets.hasSchedule(json)) GEODATA else 0) or
        (if (XdriveServicePolicy.requiresLifetime(json)) XDRIVE else 0)
    fun allows(json: String, capabilities: Int): Boolean = required(json).let { (it and capabilities) == it }
    fun parse(bytes: ByteArray?): Int = try {
        if (bytes == null || bytes.size > 4096) 0 else {
            val text = bytes.toString(Charsets.UTF_8)
            val fields = Regex("\"(stage|code|managed_service_lifetimes)\"\\s*:").findAll(text).map { it.groupValues[1] }.toList()
            val parser = JSONTokener(text)
            val value = parser.nextValue() as? JSONObject
            if (value == null || fields.size != 3 || fields.toSet().size != 3 || parser.nextClean() != '\u0000' ||
                value.keys().asSequence().toSet() != setOf("stage", "code", "managed_service_lifetimes") ||
                value.opt("stage") != "capabilities" || value.opt("code") !is Int || value.getInt("code") != 0 ||
                value.opt("managed_service_lifetimes") !is Int) 0
            else value.getInt("managed_service_lifetimes").takeIf { it in 0..7 } ?: 0
        }
    } catch (_: Exception) { 0 }
}
