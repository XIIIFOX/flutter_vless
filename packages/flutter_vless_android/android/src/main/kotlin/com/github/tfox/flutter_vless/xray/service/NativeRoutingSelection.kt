package com.github.tfox.flutter_vless.xray.service

import org.json.JSONObject
import org.json.JSONTokener

/** Only native-validated user choices are retained; no runtime identity or capability is persisted. */
internal object NativeRoutingSelection {
    fun encode(raw: Any?, proxyOnly: Boolean): String? {
        if (raw == null) return null
        require(!proxyOnly && raw is Map<*, *>) { "Invalid VPN routing selection" }
        require(raw.keys.all { it == "sourceInboundIndex" || it == "defaultOutboundTag" }) { "Invalid VPN routing selection" }
        val json=JSONObject()
        if (raw.containsKey("sourceInboundIndex")) {
            val index=raw["sourceInboundIndex"]
            require((index is Int || index is Long) && (index as Number).toLong() in 0..Int.MAX_VALUE.toLong()) {
                "Invalid VPN routing selection"
            }
            json.put("sourceInboundIndex", (index as Number).toInt())
        }
        val tag=raw["defaultOutboundTag"]
        require(tag == null || tag === JSONObject.NULL || tag is String) { "Invalid VPN routing selection" }
        if (tag is String && tag.isNotEmpty()) json.put("defaultOutboundTag", tag)
        return json.toString()
    }
    fun decode(snapshot: String?, proxyOnly: Boolean): NativeRoutingIntent? {
        if (snapshot == null) return null
        try {
            val parser=JSONTokener(snapshot)
            val json=parser.nextValue() as? JSONObject ?: error("Invalid selection")
            require(parser.nextClean() == '\u0000')
            val map=json.keys().asSequence().associateWith { json.get(it) }
            val canonical=JSONObject(requireNotNull(encode(map, proxyOnly)))
            return NativeRoutingIntent(if (canonical.has("sourceInboundIndex")) canonical.getInt("sourceInboundIndex") else null,
                canonical.optString("defaultOutboundTag").takeIf { it.isNotEmpty() })
        } catch (_: Exception) { throw IllegalArgumentException("Invalid VPN routing selection") }
    }
}
