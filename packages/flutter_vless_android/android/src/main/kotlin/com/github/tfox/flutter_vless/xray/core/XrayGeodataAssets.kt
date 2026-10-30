package com.github.tfox.flutter_vless.xray.core

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.Locale

/** Check the scheduled updater's real write owner without touching caller DATs. */
internal object XrayGeodataAssets {
    private fun field(value: JSONObject, name: String): Any? {
        val keys = value.keys().asSequence().filter {
            it.replace('\u017f', 's').replace('\u212a', 'k').lowercase(Locale.ROOT) == name
        }.toList()
        require(keys.size <= 1) { "Conflicting GeoDAT configuration fields" }
        return keys.singleOrNull()?.let(value::opt)?.takeUnless { it == JSONObject.NULL }
    }

    private fun section(json: String): JSONObject? {
        val value = field(JSONObject(json), "geodata") ?: return null
        return value as? JSONObject ?: throw IllegalArgumentException("Invalid GeoDAT configuration")
    }

    fun hasSchedule(json: String): Boolean {
        val value = section(json) ?: return false
        val cron = field(value, "cron") ?: return false
        require(cron is String) { "Invalid GeoDAT schedule" }
        return cron.isNotEmpty()
    }

    fun validateWritableRoot(json: String, directory: File) {
        if (!hasSchedule(json)) return
        val section = section(json)!!
        val raw = field(section, "assets") ?: return // Reload only, no writes.
        require(raw is JSONArray && raw.length() <= 100) { "Invalid GeoDAT asset list" }
        if (raw.length() == 0) return
        require(directory.isAbsolute && directory.isDirectory) { "GeoDAT updater requires an existing writable asset directory" }
        val parents = linkedSetOf<File>()
        for (index in 0 until raw.length()) {
            val asset = raw.optJSONObject(index) ?: throw IllegalArgumentException("Invalid GeoDAT asset")
            val name = field(asset, "file") as? String ?: throw IllegalArgumentException("Invalid GeoDAT asset file")
            require(!name.startsWith('/') && !name.contains('\u0000') && name.lowercase(Locale.ROOT).endsWith(".dat") &&
                name.split('/').none { it.isEmpty() || it == "." || it == ".." }) { "GeoDAT asset must be a local DAT file" }
            val file = File(directory, name)
            require(file.isFile) { "GeoDAT updater assets must already exist as regular files" }
            parents.add(file.parentFile!!)
        }
        for (parent in parents) probe(parent)
    }

    private fun probe(parent: File) {
        var first: File? = null
        var second: File? = null
        try {
            first = File.createTempFile(".flutter-vless-geodat-check-", ".tmp", parent)
            second = File.createTempFile(".flutter-vless-geodat-check-", ".tmp", parent)
            require(first.renameTo(second)) { "GeoDAT updater requires atomic replacement in its asset directory" }
        } catch (_: Exception) {
            throw IllegalArgumentException("GeoDAT updater requires a writable asset directory with atomic replacement")
        } finally {
            val removedFirst = first == null || !first.exists() || first.delete()
            val removedSecond = second == null || !second.exists() || second.delete()
            check(removedFirst && removedSecond) { "GeoDAT updater write-check cleanup failed" }
        }
    }
}
