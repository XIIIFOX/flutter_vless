package com.github.tfox.flutter_vless.xray.core

import org.json.JSONArray
import org.json.JSONObject

/** Reserve user definitions and references, including otherwise dangling references. */
internal class XrayServiceTags(configuration: Any?) {
    private val used = mutableSetOf<String>()
    init { collect(configuration) }

    fun next(preferred: String): String {
        var candidate = preferred
        var suffix = 0
        while (candidate in used) { suffix++; candidate = "$preferred-$suffix" }
        used.add(candidate)
        return candidate
    }

    private fun collect(value: Any?) {
        when (value) {
            is JSONObject -> value.keys().forEach { key ->
                val child = value.opt(key)
                // Match Go's simple folding, including long S and Kelvin sign.
                val field = key.replace('\u017f', 's').replace('\u212a', 'k').lowercase(java.util.Locale.ROOT)
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
