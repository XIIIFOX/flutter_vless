package com.github.tfox.flutter_vless.xray.service

import com.github.tfox.flutter_vless.xray.core.NativeRuntimeConfig
import org.json.JSONObject

/** Producer provenance; never reconstructed from private-looking caller rules or tags. */
internal class NativeRoutingPreparation(
    private val intent: NativeRoutingIntent,
    private val managedIndex: Int,
    private val managedTag: String,
    private val sourceInboundFinalIndex: Int?,
    guardRuleIndices: List<Int>
) {
    private val guards=guardRuleIndices.toList()
    fun freeze(final: JSONObject, authUser: String): NativeRuntimeConfig {
        // SessionReadinessProbe.configure prepends its one owned packet-path rule.
        val envelope=requireNotNull(NativeRoutingSpec.freeze(final.toString().toByteArray(Charsets.UTF_8),
            managedIndex, managedTag, authUser, intent, sourceInboundFinalIndex,
            listOf(0)+guards.map { it+1 }))
        return NativeRuntimeConfig.routing(envelope)
    }
    override fun toString()="NativeRoutingPreparation(<private>)"
}
