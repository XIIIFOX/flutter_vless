package com.github.tfox.flutter_vless.xray.core

import java.util.Locale
import org.json.JSONObject

/** Derive private-listener reservations and freeze runtime listen env; imported source stays intact. */
internal object XrayPortSpec {
    /** Freeze only inbound Address env syntax before the child adds its private
     * environment. Like Core, expand once, prefer an exact existing empty value,
     * then try the normalized name; a missing address becomes an empty string. */
    fun bindListenEnvironment(value: String, environment: (String) -> String? = System::getenv): String {
        if (!value.startsWith("env:")) return value
        val name = value.substring(4)
        // Go strings.TrimSpace's Unicode White_Space set excludes Java's
        // additional control separators. Go uppercasing is one rune at a time,
        // so, for example, sharp-s must not expand to two ASCII letters.
        val trimmed = trimGoSpace(name)
        val alternate = StringBuilder()
        var index = 0
        while (index < trimmed.length) {
            val codePoint = Character.codePointAt(trimmed, index)
            alternate.appendCodePoint(if (codePoint == '.'.code) '_'.code else Character.toUpperCase(codePoint))
            index += Character.charCount(codePoint)
        }
        val resolved = environment(name) ?: if (alternate.isNotEmpty()) environment(alternate.toString()) ?: "" else ""
        // The original Address decoder expands once. Materializing another
        // env: token would make the child's decoder expand it a second time.
        require(!resolved.startsWith("env:")) { "Nested environment listen address is unavailable" }
        return resolved
    }

    private fun trimGoSpace(value: String) = value.trim { c -> c in '\t'..'\r' || c == ' ' || c == '\u0085' || c == '\u00a0' ||
        c == '\u1680' || c in '\u2000'..'\u200a' || c in '\u2028'..'\u2029' ||
        c == '\u202f' || c == '\u205f' || c == '\u3000' }

    /** Core ParseAddress removes an outer [] pair before trimming whitespace. */
    fun isUnixListen(value: String): Boolean {
        val address = trimGoSpace(if (value.startsWith('[') && value.endsWith(']')) value.substring(1, value.length - 1) else value)
        return java.io.File(address).isAbsolute || address.startsWith('@')
    }

    /** API.listen is another listener: reserve numeric ports without resolving
     * hosts or rejecting Core/OS service-name and Unix-socket syntax. */
    fun apiListenerPorts(configuration: JSONObject): Set<Int> = listenerPorts(configuration, setOf("api"))

    /** Imported metrics.listen also binds TCP independently of inbounds. */
    fun serviceListenerPorts(configuration: JSONObject): Set<Int> = listenerPorts(configuration, setOf("api", "metrics"))

    private fun listenerPorts(configuration: JSONObject, services: Set<String>): Set<Int> {
        fun field(key: String) = key.replace('\u017f', 's').replace('\u212a', 'k').lowercase(Locale.ROOT)
        val ports = mutableSetOf<Int>()
        configuration.keys().forEach { key ->
            if (field(key) !in services) return@forEach
            val service = configuration.optJSONObject(key) ?: return@forEach
            service.keys().forEach listenField@ { name ->
                if (field(name) != "listen") return@listenField
                val listen = service.opt(name) as? String ?: return@listenField
                if (listen.startsWith('/') || listen.startsWith('@') || ':' !in listen) return@listenField
                // Go net.parsePort permits one leading '+' on decimal ports.
                val digits = listen.substringAfterLast(':').removePrefix("+")
                if (digits.isEmpty() || digits.any { it !in '0'..'9' }) return@listenField
                digits.toIntOrNull()?.takeIf { it in 1..65535 }?.let(ports::add)
            }
        }
        return ports
    }

    fun reservedPorts(value: Any, environment: (String) -> String? = System::getenv): Set<Int> {
        fun invalid(): Nothing = throw IllegalArgumentException("Invalid Xray inbound port specification")
        if (value is Int || value is Long || value is Short || value is Byte) {
            val port = (value as Number).toLong()
            if (port !in 0..65535) invalid()
            return if (port == 0L) emptySet() else setOf(port.toInt())
        }
        if (value !is String) invalid()
        val ports = mutableSetOf<Int>()
        for (raw in value.split(',')) {
            var part = raw.trim { it.isWhitespace() || it == '\u0085' }
            if (part.isEmpty()) continue
            val fromEnvironment = part.startsWith("env:")
            if (fromEnvironment) {
                val name = part.substring(4)
                val alternate = name.trim { it.isWhitespace() || it == '\u0085' }.uppercase(Locale.ROOT).replace('.', '_')
                part = environment(name) ?: environment(alternate) ?: invalid()
            }
            val limits = part.split('-')
            if (limits.size !in 1..2) invalid()
            fun number(text: String): Int {
                if (text.isEmpty() || text.any { it !in '0'..'9' } ||
                    (!fromEnvironment && limits.size == 1 && text != "0" && text.startsWith('0'))) invalid()
                return text.toIntOrNull()?.takeIf { it in 0..65535 } ?: invalid()
            }
            val first = number(limits.first()); val last = number(limits.last())
            if (first <= last) ports.addAll((first..last).filter { it != 0 })
        }
        return ports
    }
}
