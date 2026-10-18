package com.github.tfox.flutter_vless.xray.core

import java.util.Locale

/** Imported Core syntax stays intact; only the private listener's occupied set is derived. */
internal object XrayPortSpec {
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
