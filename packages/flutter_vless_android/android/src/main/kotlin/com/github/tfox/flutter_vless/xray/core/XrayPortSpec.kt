package com.github.tfox.flutter_vless.xray.core

import java.util.Locale
import org.json.JSONObject

/** Imported Core syntax stays intact; only the private listener's occupied set is derived. */
internal object XrayPortSpec {
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
