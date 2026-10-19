package com.github.tfox.flutter_vless.xray.service

import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest

/** Trusted native choices. This index addresses the ORIGINAL caller inbounds. */
internal class NativeRoutingIntent(val sourceInboundIndex: Int? = null, val defaultOutboundTag: String? = null) {
    init {
        if (sourceInboundIndex != null && sourceInboundIndex < 0)
            throw NativeRoutingSpecException(NativeRoutingSpecFailure.INVALID_INTENT)
    }
    override fun toString() = "NativeRoutingIntent(<private>)"
}

/** One exact factory input pair; callers receive independent copies of its bytes. */
internal class NativeRoutingEnvelope internal constructor(configurationData: ByteArray, metadataData: ByteArray,
                                                         val sourceSHA256: String) {
    private val configuration = configurationData.clone()
    private val metadata = metadataData.clone()
    val configurationData: ByteArray get() = configuration.clone()
    val metadataData: ByteArray get() = metadata.clone()
    override fun toString() = "NativeRoutingEnvelope(<private>)"
}

internal enum class NativeRoutingSpecFailure {
    INVALID_INTENT, MALFORMED_CONFIGURATION, INVALID_MANAGED_INBOUND,
    INVALID_SOURCE_INBOUND, INVALID_DEFAULT_OUTBOUND, INVALID_GUARD_RULES
}

/** Fixed categories only: never attach JSON parser errors or private field values. */
internal class NativeRoutingSpecException(val failure: NativeRoutingSpecFailure) :
    IllegalArgumentException("Invalid native routing metadata: " + failure.name)

internal object NativeRoutingSpec {
    /**
     * Metadata only: no normalization, address resolution or Core invocation.
     * The preparer must supply provenance-backed final mapping and guard indices.
     * Go Check remains authoritative for the complete compiled Core shape.
     */
    fun freeze(finalData: ByteArray, managedInboundIndex: Int, managedInboundTag: String, authUser: String,
               intent: NativeRoutingIntent?, sourceInboundFinalIndex: Int? = null,
               guardRuleIndices: List<Int> = emptyList()): NativeRoutingEnvelope? {
        // Caller JSON can never enable this path or select its trusted metadata.
        if (intent == null) return null
        val frozen = finalData.clone()
        val root = parse(frozen)
        val inputs = objects(field(root, "inbounds"), NativeRoutingSpecFailure.MALFORMED_CONFIGURATION)
        if (managedInboundTag.isEmpty() || authUser.isEmpty() || managedInboundIndex !in inputs.indices ||
            !privateInput(inputs[managedInboundIndex], managedInboundTag, authUser) ||
            inputs.count { tag(it) == managedInboundTag } != 1)
            fail(NativeRoutingSpecFailure.INVALID_MANAGED_INBOUND)

        if (intent.sourceInboundIndex != null) {
            if (sourceInboundFinalIndex == null || sourceInboundFinalIndex !in inputs.indices ||
                sourceInboundFinalIndex == managedInboundIndex)
                fail(NativeRoutingSpecFailure.INVALID_SOURCE_INBOUND)
        } else if (sourceInboundFinalIndex != null) {
            fail(NativeRoutingSpecFailure.INVALID_SOURCE_INBOUND)
        }

        val defaultTag = intent.defaultOutboundTag.orEmpty()
        if (defaultTag.isNotEmpty()) {
            val outputs = objects(field(root, "outbounds"), NativeRoutingSpecFailure.INVALID_DEFAULT_OUTBOUND)
            if (outputs.count { tag(it) == defaultTag } != 1) fail(NativeRoutingSpecFailure.INVALID_DEFAULT_OUTBOUND)
        }

        // Snapshot explicitly supplied indices; never discover guards by private-looking tags.
        val guards = guardRuleIndices.toList()
        if (guards.isNotEmpty()) {
            val routing = field(root, "routing") as? JSONObject ?: fail(NativeRoutingSpecFailure.INVALID_GUARD_RULES)
            val rules = objects(field(routing, "rules"), NativeRoutingSpecFailure.INVALID_GUARD_RULES)
            if (guards.distinct().size != guards.size || guards.any { it !in rules.indices || !guardRule(rules[it]) })
                fail(NativeRoutingSpecFailure.INVALID_GUARD_RULES)
        }

        val digest = MessageDigest.getInstance("SHA-256").digest(frozen)
            .joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
        val metadata = JSONObject().put("version", 1).put("source_sha256", digest)
            .put("managed_inbound_index", managedInboundIndex).put("managed_inbound_tag", managedInboundTag)
            .put("auth_user", authUser).put("guard_rule_indices", JSONArray(guards))
        if (sourceInboundFinalIndex != null) metadata.put("source_inbound_index", sourceInboundFinalIndex)
        if (defaultTag.isNotEmpty()) metadata.put("default_outbound_tag", defaultTag)
        return NativeRoutingEnvelope(frozen, metadata.toString().toByteArray(Charsets.UTF_8), digest)
    }

    private fun parse(bytes: ByteArray): JSONObject {
        try {
            val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
            val parser = JSONTokener(text)
            val root = parser.nextValue() as? JSONObject ?: fail(NativeRoutingSpecFailure.MALFORMED_CONFIGURATION)
            if (parser.nextClean() != '\u0000') fail(NativeRoutingSpecFailure.MALFORMED_CONFIGURATION)
            return root
        } catch (error: NativeRoutingSpecException) {
            throw error
        } catch (_: Exception) {
            fail(NativeRoutingSpecFailure.MALFORMED_CONFIGURATION)
        }
    }

    /** Go's ASCII schema matching also includes the long-S and Kelvin simple folds. */
    private fun matches(key: String, expected: String): Boolean = key.length == expected.length && key.indices.all {
        val c = key[it]
        val folded = when (c) { in 'A'..'Z' -> c.lowercaseChar(); '\u017f' -> 's'; '\u212a' -> 'k'; else -> c }
        folded == expected[it]
    }

    private fun field(objectValue: JSONObject, name: String): Any? {
        val keys = objectValue.keys().asSequence().filter { matches(it, name.lowercase(java.util.Locale.ROOT)) }.toList()
        if (keys.size > 1) fail(NativeRoutingSpecFailure.MALFORMED_CONFIGURATION)
        return keys.firstOrNull()?.let { objectValue.opt(it) }
    }

    private fun objects(value: Any?, failure: NativeRoutingSpecFailure): List<JSONObject> {
        val array = value as? JSONArray ?: fail(failure)
        return (0 until array.length()).map { array.opt(it) as? JSONObject ?: fail(failure) }
    }

    private fun tag(value: JSONObject): String = when (val tag = field(value, "tag")) {
        null, JSONObject.NULL -> ""
        is String -> tag
        else -> fail(NativeRoutingSpecFailure.MALFORMED_CONFIGURATION)
    }

    private fun privateInput(input: JSONObject, expectedTag: String, user: String): Boolean {
        if (tag(input) != expectedTag || field(input, "protocol") != "socks" ||
            field(input, "listen") !in listOf("127.0.0.1", "::1")) return false
        val port = (field(input, "port") as? Number)?.toDouble() ?: return false
        if (!port.isFinite() || port < 1 || port > 65535 || port != port.toInt().toDouble()) return false
        val settings = field(input, "settings") as? JSONObject ?: return false
        if (field(settings, "auth") != "password") return false
        val accounts = field(settings, "accounts") as? JSONArray ?: return false
        if (accounts.length() != 1) return false
        val account = accounts.opt(0) as? JSONObject ?: return false
        return field(account, "user") == user && (field(account, "pass") as? String)?.isNotEmpty() == true
    }

    private fun guardRule(rule: JSONObject): Boolean {
        if ((field(rule, "outboundTag") as? String)?.isNotEmpty() != true) return false
        val balancing = field(rule, "balancerTag")
        if (balancing != null && balancing != JSONObject.NULL && balancing != "") return false
        val webhook = field(rule, "webhook")
        if (webhook != null && webhook != JSONObject.NULL) return false
        val tags = when (val value = field(rule, "inboundTag")) {
            is String -> value.split(',')
            is JSONArray -> (0 until value.length()).map { value.opt(it) as? String ?: return false }
            else -> return false
        }
        return tags.isNotEmpty() && tags.all { it.isNotEmpty() }
    }

    private fun fail(failure: NativeRoutingSpecFailure): Nothing = throw NativeRoutingSpecException(failure)
}
