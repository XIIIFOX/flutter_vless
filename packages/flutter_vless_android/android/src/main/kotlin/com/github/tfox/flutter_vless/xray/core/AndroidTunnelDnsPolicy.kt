package com.github.tfox.flutter_vless.xray.core

import org.json.JSONArray
import org.json.JSONObject
import java.net.IDN
import java.net.InetAddress
import java.util.Locale

/** Explicit system-DNS policy. This helper never performs an OS DNS lookup. */
internal object AndroidTunnelDnsPolicy {
    const val VIRTUAL_SERVER = "198.18.0.2"
    const val RELAY_TAG = "flutter-vless-system-dns"
    const val UPSTREAM_TAG = "flutter-vless-dns-upstream"
    const val PROXY_TAG = "flutter-vless-dns-proxy"
    private val reservedTags = setOf(RELAY_TAG, UPSTREAM_TAG, PROXY_TAG)
    private val endpointProtocols = setOf("http", "socks", "vless", "vmess", "trojan", "shadowsocks", "hysteria", "wireguard")

    data class Prepared(
        val configJson: String,
        val systemDnsServers: List<String>,
        val bootstrapHostnames: Set<String> = emptySet(),
        val bootstrapAddresses: Set<String> = emptySet()
    )

    /** Perform preflight without querying DNS or modifying the caller's configuration. */
    fun validate(configJson: String, policy: String = "config", proxyOutboundTag: String? = null,
                 excludedRoutes: List<String> = emptyList()) {
        prepareInternal(configJson, policy, proxyOutboundTag, excludedRoutes, null)
    }

    /** Call before replacing a live session. The resolver must be scoped to a physical Network. */
    fun prepare(configJson: String, policy: String = "config", proxyOutboundTag: String? = null,
                excludedRoutes: List<String> = emptyList(),
                resolveEndpoint: (String) -> List<String> = { emptyList() }): Prepared {
        validate(configJson, policy, proxyOutboundTag, excludedRoutes)
        return prepareInternal(configJson, policy, proxyOutboundTag, excludedRoutes, resolveEndpoint)
    }

    private fun prepareInternal(configJson: String, policy: String, proxyOutboundTag: String?,
                                excludedRoutes: List<String>, resolveEndpoint: ((String) -> List<String>)?): Prepared {
        require(policy == "config" || policy == "proxy") { "Unsupported Android DNS policy" }
        require(proxyOutboundTag == null || policy == "proxy") { "DNS proxy outbound tag requires proxy DNS policy" }
        if (policy == "config") return Prepared(configJson, listOf("8.8.8.8", "1.1.1.1"))
        require(allowsRouteExclusions(excludedRoutes)) { "Excluded route conflicts with virtual system DNS" }

        val config = JSONObject(configJson)
        canonicalize(config, "outbounds", "inbounds", "routing", "dns")
        val outbounds = objects(config, "outbounds", required = true)
        val inbounds = objects(config, "inbounds")
        outbounds.forEach { canonicalize(it, "tag", "protocol", "settings", "streamSettings", "proxySettings") }
        inbounds.forEach { canonicalize(it, "tag") }
        val tags = outbounds.mapNotNull { optionalString(it, "tag")?.takeIf(String::isNotEmpty) }
        require(tags.distinct().size == tags.size) { "Duplicate outbound tag in proxy DNS configuration" }
        require((tags + inbounds.mapNotNull { optionalString(it, "tag") }).none { it in reservedTags }) {
            "Configuration collides with a reserved DNS tag"
        }
        val candidates = outbounds.filter { protocol(it) in endpointProtocols }
        val selected = if (proxyOutboundTag != null) {
            require(proxyOutboundTag.isNotBlank()) { "DNS proxy outbound tag is empty" }
            candidates.singleOrNull { optionalString(it, "tag") == proxyOutboundTag }
                ?: throw IllegalArgumentException("DNS proxy outbound tag must identify a supported proxy")
        } else {
            candidates.singleOrNull { optionalString(it, "tag") == "proxy" }
                ?: candidates.singleOrNull()
                ?: throw IllegalArgumentException("DNS proxy outbound is ambiguous or missing; specify its tag")
        }
        val selectedTag = optionalString(selected, "tag")?.takeIf(String::isNotEmpty) ?: PROXY_TAG.also { selected.put("tag", it) }
        val hosts = JSONObject()
        val names = linkedSetOf<String>()
        val addresses = linkedSetOf<String>()
        fun pinEndpoint(raw: String) {
            require(raw.isNotBlank()) { "Proxy endpoint is empty" }
            val literal = literalAddress(raw)
            if (literal != null) {
                require(!isVirtualAddress(literal)) { "Proxy endpoint conflicts with virtual system DNS" }
                addresses.add(literal.hostAddress!!.substringBefore('%'))
                return
            }
            val name = canonicalHostname(raw)
            if (!names.add(name)) return
            if (resolveEndpoint == null) return // structural preflight cannot issue DNS queries
            val answers = try { resolveEndpoint(name) } catch (_: Exception) {
                throw IllegalArgumentException("Physical-network proxy endpoint bootstrap failed")
            }
            require(answers.isNotEmpty()) { "Physical-network proxy endpoint bootstrap failed" }
            val pinned = answers.map { answer ->
                val address = literalAddress(answer)
                    ?: throw IllegalArgumentException("Proxy endpoint bootstrap returned a non-IP address")
                require(!isVirtualAddress(address)) { "Proxy endpoint resolves to virtual system DNS" }
                address.hostAddress!!.substringBefore('%')
            }.distinct()
            pinned.forEach(addresses::add)
            hosts.put(name, JSONArray(pinned))
        }

        outbounds.filter { protocol(it) in endpointProtocols }.forEach { outbound ->
            val settings = objectValue(outbound, "settings", required = true)!!
            canonicalize(settings, "address", "endpoint", "vnext", "servers", "peers", "port", "id", "encryption", "flow", "level")
            val proto = protocol(outbound)
            val entries = when {
                proto == "wireguard" -> objects(settings, "peers", required = true)
                settings.has("address") -> listOf(settings)
                proto == "vless" || proto == "vmess" -> objects(settings, "vnext", required = true)
                else -> objects(settings, "servers", required = true)
            }
            require(entries.isNotEmpty()) { "Proxy outbound has no endpoints" }
            entries.forEach { entry ->
                canonicalize(entry, "address", "endpoint")
                val address = optionalString(entry, "address") ?: endpointHost(optionalString(entry, "endpoint"))
                require(address != null) { "Proxy outbound has no endpoint address" }
                pinEndpoint(address)
            }
            val stream = objectValue(outbound, "streamSettings") ?: JSONObject()
            prepareStream(stream, ::pinEndpoint)
            outbound.put("streamSettings", stream)
        }
        val routing = objectValue(config, "routing") ?: JSONObject()
        canonicalize(routing, "rules", "domainStrategy", "balancers")
        objects(routing, "balancers").forEach { balancer ->
            canonicalize(balancer, "tag")
            require(optionalString(balancer, "tag") !in reservedTags) { "Routing balancer collides with a reserved DNS tag" }
        }
        val userRules = objects(routing, "rules")
        userRules.forEach { rule ->
            canonicalize(rule, "ip", "inboundTag", "outboundTag", "balancerTag")
            require(optionalString(rule, "outboundTag") !in reservedTags && optionalString(rule, "balancerTag") !in reservedTags) {
                "Routing rule references a reserved DNS tag"
            }
            val inboundTags = rule.optJSONArray("inboundTag")
            if (inboundTags != null) for (i in 0 until inboundTags.length()) {
                require(inboundTags.optString(i) !in reservedTags) { "Routing rule references a reserved DNS tag" }
            }
            val ips = rule.optJSONArray("ip")
            if (ips != null) for (i in 0 until ips.length()) {
                val entry = ips.optString(i)
                require(entry != VIRTUAL_SERVER && entry != "$VIRTUAL_SERVER/32") {
                    "Routing rule explicitly targets the reserved virtual DNS endpoint"
                }
            }
        }
        val serviceRules = JSONArray()
            .put(JSONObject().put("type", "field").put("inboundTag", JSONArray().put(UPSTREAM_TAG)).put("outboundTag", selectedTag))
            .put(JSONObject().put("type", "field").put("ip", JSONArray().put("$VIRTUAL_SERVER/32"))
                .put("port", "53").put("network", "tcp,udp").put("outboundTag", RELAY_TAG))
        userRules.forEach(serviceRules::put)
        routing.put("rules", serviceRules)
        config.put("routing", routing)
        val relay = JSONObject().put("tag", RELAY_TAG).put("protocol", "dns")
            .put("settings", JSONObject().put("rewriteNetwork", "tcp").put("rewriteAddress", "1.1.1.1")
                .put("rewritePort", 53).put("rules", JSONArray().put(JSONObject().put("action", "direct"))))
            .put("streamSettings", JSONObject().put("sockopt", JSONObject().put("dialerProxy", selectedTag)))
        config.put("outbounds", JSONArray(outbounds).put(relay))
        // Explicit proxy policy owns system DNS. No local/+local/OS fallback is retained.
        config.put("dns", JSONObject().put("hosts", hosts).put("servers", JSONArray().put("tcp://1.1.1.1"))
            .put("tag", UPSTREAM_TAG).put("queryStrategy", "UseIP").put("disableFallback", true))
        return Prepared(config.toString(), listOf(VIRTUAL_SERVER), names, addresses)
    }

    private fun prepareStream(stream: JSONObject, pinEndpoint: (String) -> Unit) {
        canonicalize(stream, "sockopt", "address", "network", "xhttpSettings", "splithttpSettings")
        // These two native keys select the same transport object. Reject ambiguous payloads.
        require(!(stream.has("xhttpSettings") && stream.has("splithttpSettings"))) { "Conflicting XHTTP transport aliases" }
        val sockopt = objectValue(stream, "sockopt") ?: JSONObject()
        canonicalize(sockopt, "domainStrategy", "addressPortStrategy", "dialerProxy")
        require((optionalString(sockopt, "addressPortStrategy") ?: "none").equals("none", true)) {
            "SRV/TXT endpoint overrides cannot use the protected system DNS policy"
        }
        sockopt.put("domainStrategy", "ForceIP")
        stream.put("sockopt", sockopt)
        optionalString(stream, "address")?.let(pinEndpoint)
        for (key in listOf("xhttpSettings", "splithttpSettings")) {
            val transport = objectValue(stream, key) ?: continue
            canonicalize(transport, "extra", "downloadSettings")
            val extra = objectValue(transport, "extra")
            if (extra == null) {
                objectValue(transport, "downloadSettings")?.let { prepareStream(it, pinEndpoint) }
            } else {
                // Xray replaces the outer settings with extra; unused endpoints must not bootstrap.
                canonicalize(extra, "downloadSettings")
                objectValue(extra, "downloadSettings")?.let { prepareStream(it, pinEndpoint) }
            }
        }
    }

    /** User bypass routes may never remove the reserved resolver from TUN capture. */
    fun allowsRouteExclusions(routes: List<String>): Boolean = routes.none { route ->
        val parts = route.split('/')
        val address = literalAddress(parts[0])?.address
        if (address?.size != 4 || parts.size > 2) false else {
            val prefix = if (parts.size == 1) 32 else parts[1].toIntOrNull()
            require(prefix != null && prefix in 0..32) { "Invalid excluded route prefix" }
            val number = address.fold(0L) { acc, byte -> (acc shl 8) or (byte.toLong() and 255) }
            val mask = if (prefix == 0) 0L else (0xffffffffL shl (32 - prefix)) and 0xffffffffL
            (number and mask) == (0xc6120002L and mask)
        }
    }

    /** InetAddress is used only after lexical validation prevents any resolver access. */
    private fun literalAddress(raw: String): InetAddress? {
        val value = if (raw.startsWith('[') && raw.endsWith(']')) raw.drop(1).dropLast(1) else raw
        if (value.contains(':')) {
            if (!value.matches(Regex("[0-9a-fA-F:.]+"))) return null
            return runCatching { InetAddress.getByName(value) }.getOrNull()
        }
        val bytes = value.split('.')
        if (bytes.size != 4 || bytes.any { it.isEmpty() || it.any { c -> c !in '0'..'9' } || (it.length > 1 && it[0] == '0') || (it.toIntOrNull() ?: -1) !in 0..255 }) return null
        return InetAddress.getByAddress(bytes.map { it.toInt().toByte() }.toByteArray())
    }

    private fun isVirtualAddress(address: InetAddress): Boolean = address.address.contentEquals(byteArrayOf(198.toByte(), 18, 0, 2))

    internal fun canonicalHostname(raw: String): String {
        require(raw == raw.trim() && !raw.contains(':') && !raw.contains('/') && !raw.contains('%') && !raw.contains('[')) { "Invalid proxy endpoint hostname" }
        val name = IDN.toASCII(raw.removeSuffix("."), IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT)
        require(name.length in 1..253 && name.split('.').all { it.length in 1..63 }) { "Invalid proxy endpoint hostname" }
        require(!name.all { it in '0'..'9' || it == '.' }) { "Invalid proxy endpoint IP literal" }
        return name
    }

    private fun endpointHost(endpoint: String?): String? {
        if (endpoint == null) return null
        val colon = endpoint.lastIndexOf(':')
        require(colon > 0 && endpoint.substring(colon + 1).toIntOrNull() in 1..65535) { "Invalid proxy endpoint port" }
        val host = endpoint.substring(0, colon)
        require(!host.contains(':') || (host.startsWith('[') && host.endsWith(']') && literalAddress(host) != null)) { "IPv6 endpoint must use brackets" }
        return host
    }

    private fun protocol(outbound: JSONObject): String = optionalString(outbound, "protocol")?.lowercase(Locale.ROOT).orEmpty()

    /** Go JSON keys are case insensitive; never inspect one spelling while native consumes another. */
    private fun canonicalize(value: JSONObject, vararg keys: String) {
        for (canonical in keys) {
            val matches = value.keys().asSequence().filter { it.equals(canonical, true) }.toList()
            require(matches.size <= 1) { "Conflicting case-insensitive configuration keys" }
            val actual = matches.singleOrNull() ?: continue
            if (actual != canonical) value.put(canonical, value.remove(actual))
        }
    }

    private fun optionalString(value: JSONObject, key: String): String? {
        if (!value.has(key)) return null
        require(value.get(key) is String) { "Invalid DNS policy configuration field" }
        return value.getString(key)
    }

    private fun objectValue(value: JSONObject, key: String, required: Boolean = false): JSONObject? {
        if (!value.has(key)) {
            require(!required) { "Missing DNS policy configuration object" }
            return null
        }
        return value.optJSONObject(key) ?: throw IllegalArgumentException("Invalid DNS policy configuration object")
    }

    private fun objects(value: JSONObject, key: String, required: Boolean = false): List<JSONObject> {
        if (!value.has(key)) {
            require(!required) { "Missing DNS policy configuration array" }
            return emptyList()
        }
        val array = value.optJSONArray(key) ?: throw IllegalArgumentException("Invalid DNS policy configuration array")
        return (0 until array.length()).map { array.optJSONObject(it) ?: throw IllegalArgumentException("Invalid DNS policy configuration entry") }
    }
}
