package com.github.tfox.flutter_vless.xray.core

import org.json.JSONArray
import org.json.JSONObject

/** Reserve user definitions and references, including otherwise dangling references. */
internal class XrayServiceTags(configuration: Any?) {
    private val used = mutableSetOf<String>()
    private val selectorPrefixes = mutableSetOf<String>()
    /** Empty/wildcard selectors, or an exhausted scalar namespace, remain open. */
    var hasUniversalSelectorBoundary = false
        private set
    private val escapeScalar by lazy { findEscapeScalar() }
    init { collect(configuration); collectSelectorPrefixes(configuration) }

    fun next(preferred: String): String {
        var candidate = unused(preferred)
        // Check the actual suffix candidate too: "private" can be free of a
        // "private-" selector while its first unused suffix is covered.
        if (selectorPrefixes.any { candidate.startsWith(it) }) {
            val leading = escapeScalar
            if (leading != null) candidate = unused(leading + preferred)
            else hasUniversalSelectorBoundary = true // Preserve the old exact allocator; never reject a profile.
        }
        used.add(candidate)
        return candidate
    }

    private fun unused(stem: String): String {
        var candidate = stem
        var suffix = 0
        while (candidate in used) { suffix++; candidate = "$stem-$suffix" }
        return candidate
    }

    private fun findEscapeScalar(): String? {
        val firstScalars = selectorPrefixes.mapTo(mutableSetOf()) { it.codePointAt(0) }
        val friendly = "_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
        val friendlyScalars = friendly.mapTo(mutableSetOf()) { it.code }
        val privateUse = listOf(0xE000..0xF8FF, 0xF0000..0xFFFFD, 0x100000..0x10FFFD)
        val candidates = sequence {
            friendly.forEach { yield(it.code) }
            for (range in privateUse) for (scalar in range) yield(scalar)
            for (scalar in 0..0x10FFFF)
                if (scalar !in 0xD800..0xDFFF && scalar !in friendlyScalars && privateUse.none { scalar in it }) yield(scalar)
        }
        // The sequence contains each valid Unicode scalar once. N+1 attempts
        // suffice unless every scalar is covered; even that search is bounded.
        return candidates.take(minOf(firstScalars.size + 1, 0x110000 - 0x800))
            .firstOrNull { it !in firstScalars }?.let { String(Character.toChars(it)) }
    }

    private fun fold(key: String) = key.replace('\u017f', 's').replace('\u212a', 'k')
        .lowercase(java.util.Locale.ROOT)

    private fun values(value: JSONObject, field: String) =
        value.keys().asSequence().filter { fold(it) == field }.map { value.opt(it) }.toList()

    private fun collectSelectorPrefixes(configuration: Any?) {
        val root = configuration as? JSONObject ?: return
        fun add(value: Any?) {
            if (value == JSONObject.NULL || value == "") hasUniversalSelectorBoundary = true
            else if (value is String) selectorPrefixes.add(value)
        }
        fun selectors(value: Any?, stringList: Boolean) {
            when {
                value is JSONArray -> for (index in 0 until value.length()) add(value.opt(index))
                stringList && value is String -> value.split(',').forEach(::add)
            }
        }
        for (routing in values(root, "routing").filterIsInstance<JSONObject>())
            for (balancers in values(routing, "balancers").filterIsInstance<JSONArray>())
                for (index in 0 until balancers.length()) {
                    val balancer = balancers.optJSONObject(index) ?: continue
                    values(balancer, "selector").forEach { selectors(it, true) }
                }
        for (field in listOf("observatory", "burstobservatory"))
            for (observer in values(root, field).filterIsInstance<JSONObject>())
                values(observer, "subjectselector").forEach { selectors(it, false) }
    }

    private fun collect(value: Any?) {
        when (value) {
            is JSONObject -> value.keys().forEach { key ->
                val child = value.opt(key)
                // Match Go's simple folding, including long S and Kelvin sign.
                val field = fold(key)
                if (field in setOf("tag", "inboundtag", "outboundtag", "balancertag", "dialerproxy", "fallbacktag")) {
                    if (child is String) used.add(child)
                    if (child is JSONArray) for (i in 0 until child.length()) (child.opt(i) as? String)?.let(used::add)
                }
                collect(child)
            }
            is JSONArray -> for (i in 0 until value.length()) collect(value.opt(i))
        }
    }
}
