package com.github.tfox.flutter_vless.xray.core

import org.json.JSONArray
import org.json.JSONObject
import java.net.IDN
import java.net.InetAddress
import java.util.Locale
import kotlin.math.log2

/** Explicit system-DNS policy. This helper never performs an OS DNS lookup. */
internal object AndroidTunnelDnsPolicy {
    const val VIRTUAL_SERVER = "10.0.85.53"
    const val RELAY_TAG = "flutter-vless-system-dns"
    const val UPSTREAM_TAG = "flutter-vless-dns-upstream"
    const val PROXY_TAG = "flutter-vless-dns-proxy"
    private val endpointProtocols = setOf("http", "socks", "vless", "vmess", "trojan", "shadowsocks", "hysteria", "wireguard", "masque")

    data class Prepared(
        val configJson: String,
        val systemDnsServers: List<String>,
        val bootstrapHostnames: Set<String> = emptySet(),
        val bootstrapAddresses: Set<String> = emptySet(),
        /** Native-only identity shared with the adapter builder, never imported from JSON. */
        val managedInboundTag: String? = null,
        /** Only indices inserted by this preparer, not inferred from caller rules. */
        val guardRuleIndices: List<Int> = emptyList()
    )

    /** Perform preflight without querying DNS or modifying the caller's configuration. */
    fun validate(configJson: String, policy: String = "config", proxyOutboundTag: String? = null,
                 excludedRoutes: List<String> = emptyList(),
                 environment: (String) -> String? = System::getenv) {
        prepareInternal(configJson, policy, proxyOutboundTag, excludedRoutes, null, snapshotEnvironment(environment), null)
    }

    /** Call before replacing a live session. The resolver must be scoped to a physical Network. */
    fun prepare(configJson: String, policy: String = "config", proxyOutboundTag: String? = null,
                excludedRoutes: List<String> = emptyList(),
                environment: (String) -> String? = System::getenv,
                changes: PreparationChanges? = null,
                resolveEndpoint: (String) -> List<String> = { emptyList() }): Prepared {
        val snapshot = snapshotEnvironment(environment)
        prepareInternal(configJson, policy, proxyOutboundTag, excludedRoutes, null, snapshot, changes)
        return prepareInternal(configJson, policy, proxyOutboundTag, excludedRoutes, resolveEndpoint, snapshot, changes)
    }

    /** Missing and empty are distinct, and both passes must use the same value. */
    private fun snapshotEnvironment(environment: (String) -> String?): (String) -> String? {
        val values = mutableMapOf<String, String?>()
        return { name ->
            if (values.containsKey(name)) values[name]
            else environment(name).also { values[name] = it }
        }
    }

    private fun prepareInternal(configJson: String, policy: String, proxyOutboundTag: String?,
                                excludedRoutes: List<String>, resolveEndpoint: ((String) -> List<String>)?,
                                environment: (String) -> String?, changes: PreparationChanges?): Prepared {
        require(policy == "config" || policy == "proxy") { "Unsupported Android DNS policy" }
        require(proxyOutboundTag == null || policy == "proxy") { "DNS proxy outbound tag requires proxy DNS policy" }
        if (policy == "config") return prepareCallerRoot(configJson, excludedRoutes, environment, changes)
        require(allowsRouteExclusions(excludedRoutes)) { "Excluded route conflicts with virtual system DNS" }

        val config = JSONObject(configJson)
        bindLogicalAddresses(config, environment, changes)
        XdriveServicePolicy.validate(config)
        // The explicit policy replaces caller DNS, but a separately configured
        // FakeDNS engine must still leave the adapter's reserved addresses free.
        fakeDnsActive(config, inspectServers = false)
        canonicalize(config, "outbounds", "inbounds", "routing", "dns")
        val outbounds = objects(config, "outbounds", required = true)
        val inbounds = objects(config, "inbounds")
        outbounds.forEach { canonicalize(it, "tag", "protocol", "settings", "streamSettings", "proxySettings") }
        inbounds.forEach { canonicalize(it, "tag") }
        val tags = outbounds.mapNotNull { optionalString(it, "tag")?.takeIf(String::isNotEmpty) }
        require(tags.distinct().size == tags.size) { "Duplicate outbound tag in proxy DNS configuration" }
        val serviceTags = XrayServiceTags(config)
        val managedInboundTag = serviceTags.next("flutter-vless-tun")
        val relayTag = serviceTags.next(RELAY_TAG)
        val upstreamTag = serviceTags.next(UPSTREAM_TAG)
        val proxyTag = serviceTags.next(PROXY_TAG)
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
        val selectedTag = optionalString(selected, "tag")?.takeIf(String::isNotEmpty) ?: proxyTag.also { selected.put("tag", it) }
        val hosts = JSONObject()
        val names = linkedSetOf<String>()
        val addresses = linkedSetOf<String>()
        fun pinEndpoint(raw: String, typedAddress: Boolean) {
            // Keep raw JSON intact, but bootstrap the same Address Core parsed.
            // Brackets have already had their single chance to be removed.
            val value = if (typedAddress) XrayPortSpec.coreAddressText(raw) else raw
            require(value.isNotBlank()) { "Proxy endpoint is empty" }
            val literal = literalAddress(value, allowBrackets = !typedAddress)
            if (literal != null) {
                require(!isVirtualAddress(literal)) { "Proxy endpoint conflicts with virtual system DNS" }
                addresses.add(literal.hostAddress!!.substringBefore('%'))
                return
            }
            val name = canonicalHostname(value)
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
            val stream = objectValue(outbound, "streamSettings") ?: JSONObject()
            // internet.DialSystem redirects a chained destination to its next
            // handler. It remains a logical address, not a physical DNS target.
            // WireGuard separately performs LookupIP for its peer endpoints.
            val chained = proto != "wireguard" && streamIsChained(stream)
            val entries = when {
                proto == "wireguard" -> objects(settings, "peers", required = true)
                settings.has("address") && !settings.isNull("address") -> listOf(settings)
                proto == "vless" || proto == "vmess" -> objects(settings, "vnext", required = true)
                else -> objects(settings, "servers", required = true)
            }
            require(entries.isNotEmpty()) { "Proxy outbound has no endpoints" }
            entries.forEach { entry ->
                canonicalize(entry, "address", "endpoint")
                val address = optionalString(entry, "address")?.let { raw ->
                    // WireGuard endpoint is a plain String, unlike these typed
                    // protocol Address fields. Never expand arbitrary strings.
                    if (proto == "wireguard") raw else XrayPortSpec.bindAddressEnvironment(raw, environment) { changes?.record(PreparationChange.ADDRESS_ENVIRONMENT_BOUND) }
                        .also { entry.put("address", it) }
                } ?: endpointHost(optionalString(entry, "endpoint"))
                require(address != null) { "Proxy outbound has no endpoint address" }
                if (!chained && !XdriveServicePolicy.active(stream)) pinEndpoint(address, typedAddress = proto != "wireguard")
            }
            prepareStream(stream, { pinEndpoint(it, typedAddress = true) }, effectiveChain = chained,
                environment = environment, changes = changes)
            outbound.put("streamSettings", stream)
        }
        // A cloud-backed inbound also opens outbound service sockets.
        for (stream in XdriveServicePolicy.streams(config)) {
            if (outbounds.none { it.optJSONObject("streamSettings") === stream })
                prepareStream(stream, { pinEndpoint(it, typedAddress = true) }, environment = environment, changes = changes)
        }
        val routing = objectValue(config, "routing") ?: JSONObject()
        canonicalize(routing, "rules", "domainStrategy", "balancers")
        val userRules = objects(routing, "rules")
        userRules.forEach { rule ->
            canonicalize(rule, "ip", "inboundTag", "outboundTag", "balancerTag")
            val ips = rule.optJSONArray("ip")
            if (ips != null) for (i in 0 until ips.length()) {
                val entry = ips.optString(i)
                require(entry != VIRTUAL_SERVER && entry != "$VIRTUAL_SERVER/32") {
                    "Routing rule explicitly targets the reserved virtual DNS endpoint"
                }
            }
        }
        val serviceRules = JSONArray()
            .put(JSONObject().put("type", "field").put("inboundTag", JSONArray().put(upstreamTag)).put("outboundTag", selectedTag))
            .put(JSONObject().put("type", "field").put("inboundTag", JSONArray().put(managedInboundTag))
                .put("ip", JSONArray().put("$VIRTUAL_SERVER/32"))
                .put("port", "53").put("network", "tcp,udp").put("outboundTag", relayTag))
        userRules.forEach(serviceRules::put)
        routing.put("rules", serviceRules)
        config.put("routing", routing)
        val relay = JSONObject().put("tag", relayTag).put("protocol", "dns")
            .put("settings", JSONObject().put("rewriteNetwork", "tcp").put("rewriteAddress", "1.1.1.1")
                // This explicit override carries both address families through
                // the selected proxy; it never uses a physical DNS fallback.
                .put("rewritePort", 53).put("rules", JSONArray()
                    .put(JSONObject().put("action", "direct"))))
            .put("streamSettings", JSONObject().put("sockopt", JSONObject().put("dialerProxy", selectedTag)))
        config.put("outbounds", JSONArray(outbounds).put(relay))
        // Explicit proxy policy owns system DNS. No local/+local/OS fallback is retained.
        config.put("dns", JSONObject().put("hosts", hosts).put("servers", JSONArray().put("tcp://1.1.1.1"))
            .put("tag", upstreamTag).put("queryStrategy", "UseIP").put("disableFallback", true))
        changes?.record(PreparationChange.SYSTEM_DNS_GUARD_ADDED)
        return Prepared(config.toString(), listOf(VIRTUAL_SERVER), names, addresses, managedInboundTag, listOf(0, 1))
    }

    /**
     * Keep the imported root DNS client semantics, freezing typed env Addresses
     * in the copied document. The private TUN input sends only
     * its virtual resolver traffic here; imported inputs and DNS routing tags
     * retain their original meaning. Missing/empty/localhost DNS uses the
     * official protected Core resolver's D broker on an Android physical Network.
     * This does not pin transport endpoints into caller hosts or select a proxy.
     */
    private fun prepareCallerRoot(configJson: String, excludedRoutes: List<String>, environment: (String) -> String?, changes: PreparationChanges?): Prepared {
        require(allowsRouteExclusions(excludedRoutes)) { "Excluded route conflicts with virtual system DNS" }
        val config = JSONObject(configJson)
        bindLogicalAddresses(config, environment, changes)
        XdriveServicePolicy.validate(config)
        bindRootDnsAddresses(config, environment, changes)
        fakeDnsActive(config)
        canonicalize(config, "outbounds", "inbounds", "routing")
        val outbounds = objects(config, "outbounds", required = true)
        val serviceTags = XrayServiceTags(config)
        val managedInboundTag = serviceTags.next("flutter-vless-tun")
        val relayTag = serviceTags.next(RELAY_TAG)
        val routing = objectValue(config, "routing") ?: JSONObject()
        canonicalize(routing, "rules")
        val userRules = objects(routing, "rules")
        for (rule in userRules) {
            val inspected = JSONObject(rule.toString())
            canonicalize(inspected, "ip")
            val ips = inspected.optJSONArray("ip") ?: continue
            for (i in 0 until ips.length()) require(ips.optString(i) !in setOf(VIRTUAL_SERVER, "$VIRTUAL_SERVER/32")) {
                "Routing rule explicitly targets the reserved virtual DNS endpoint"
            }
        }
        val rules = JSONArray().put(JSONObject().put("type", "field")
            .put("inboundTag", JSONArray().put(managedInboundTag))
            .put("ip", JSONArray().put("$VIRTUAL_SERVER/32")).put("port", "53")
            .put("network", "tcp,udp").put("outboundTag", relayTag))
        userRules.forEach(rules::put)
        routing.put("rules", rules)
        config.put("routing", routing)
        // Both address families are answered by Core's unchanged root client,
        // which applies caller queryStrategy (including UseIPv4) itself. Other
        // record types are REFUSED, never forwarded to the virtual address.
        val dnsRules = JSONArray()
            .put(JSONObject().put("action", "hijack").put("qType", "28"))
            .put(JSONObject().put("action", "hijack").put("qType", "1"))
            .put(JSONObject().put("action", "return").put("rCode", 5))
        config.put("outbounds", JSONArray(outbounds).put(JSONObject().put("tag", relayTag)
            .put("protocol", "dns").put("settings", JSONObject().put("rules", dnsRules))))
        changes?.record(PreparationChange.SYSTEM_DNS_GUARD_ADDED)
        return Prepared(config.toString(), listOf(VIRTUAL_SERVER), managedInboundTag = managedInboundTag, guardRuleIndices = listOf(0))
    }

    private fun schemaFold(value: String) = value.replace('\u017f', 's').replace('\u212a', 'k').lowercase(Locale.ROOT)

    private fun schemaKey(value: JSONObject, name: String): String? {
        val keys = value.keys().asSequence().filter { schemaFold(it) == name }.toList()
        require(keys.size <= 1) { "Conflicting case-insensitive configuration keys" }
        return keys.singleOrNull()
    }

    private fun schemaField(value: JSONObject, name: String): Any? = schemaKey(value, name)?.let(value::opt)

    /** These typed Addresses describe a logical dispatch destination, not a
     * physical transport endpoint. Match Core's non-null primary precedence
     * without resolving it or changing its dormant compatibility alias. */
    private fun bindLogicalAddresses(config: JSONObject, environment: (String) -> String?, changes: PreparationChanges?) {
        fun bind(collection: String, protocols: Set<String>) {
            val entries = schemaField(config, collection) as? JSONArray ?: return
            for (index in 0 until entries.length()) {
                val entry = entries.opt(index) as? JSONObject ?: continue
                val protocol = (schemaField(entry, "protocol") as? String)?.lowercase(Locale.ROOT)
                if (protocol !in protocols) continue
                val settings = schemaField(entry, "settings") as? JSONObject ?: continue
                val primary = schemaKey(settings, "address")
                val selected = if (primary != null && !settings.isNull(primary)) primary
                    else schemaKey(settings, "rewriteaddress") ?: continue
                // Invalid non-null primary values stay invalid for Core's
                // preflight, rather than falling back to a different target.
                val raw = settings.opt(selected) as? String ?: continue
                settings.put(selected, XrayPortSpec.bindAddressEnvironment(raw, environment) { changes?.record(PreparationChange.ADDRESS_ENVIRONMENT_BOUND) })
            }
        }
        bind("outbounds", setOf("dns"))
        bind("inbounds", setOf("dokodemo-door", "tunnel"))
    }

    /** Address values only: hosts dictionary keys, tags, URLs containing env:
     * and arbitrary nested caller objects never become environment references. */
    private fun bindRootDnsAddresses(config: JSONObject, environment: (String) -> String?, changes: PreparationChanges?) {
        val dns = schemaField(config, "dns") as? JSONObject ?: return
        fun bindField(owner: JSONObject, name: String) {
            val key = schemaKey(owner, name) ?: return
            val raw = owner.opt(key) as? String ?: return
            owner.put(key, XrayPortSpec.bindAddressEnvironment(raw, environment) { changes?.record(PreparationChange.ADDRESS_ENVIRONMENT_BOUND) })
        }
        bindField(dns, "clientip")
        (schemaField(dns, "servers") as? JSONArray)?.let { servers ->
            for (index in 0 until servers.length()) {
                when (val server = servers.opt(index)) {
                    is String -> servers.put(index, XrayPortSpec.bindAddressEnvironment(server, environment) { changes?.record(PreparationChange.ADDRESS_ENVIRONMENT_BOUND) })
                    is JSONObject -> {
                        bindField(server, "address")
                        bindField(server, "clientip")
                    }
                }
            }
        }
        val hosts = schemaField(dns, "hosts") as? JSONObject ?: return
        for (key in hosts.keys().asSequence().toList()) {
            when (val value = hosts.opt(key)) {
                is String -> hosts.put(key, XrayPortSpec.bindAddressEnvironment(value, environment) { changes?.record(PreparationChange.ADDRESS_ENVIRONMENT_BOUND) })
                is JSONArray -> for (index in 0 until value.length()) {
                    val raw = value.opt(index) as? String ?: continue
                    value.put(index, XrayPortSpec.bindAddressEnvironment(raw, environment) { changes?.record(PreparationChange.ADDRESS_ENVIRONMENT_BOUND) })
                }
            }
        }
    }

    /** Validate only the Core engine/server schema; never rewrite caller pools. */
    internal fun fakeDnsActive(config: JSONObject, inspectServers: Boolean = true): Boolean {
        val engine = schemaField(config, "fakedns")
        val explicit = engine != null && engine != JSONObject.NULL
        val pools = when (engine) {
            null, JSONObject.NULL -> emptyList()
            is JSONObject -> listOf(engine)
            is JSONArray -> (0 until engine.length()).map {
                engine.opt(it) as? JSONObject ?: throw IllegalArgumentException("Invalid FakeDNS pool")
            }
            else -> throw IllegalArgumentException("Invalid FakeDNS engine")
        }
        val reserved = listOf("10.0.85.0/24", "26.26.26.0/30", "fd26:26:26::/126", "fd00:198:18::/64",
            "::ffff:10.0.85.0/120", "::ffff:26.26.26.0/126").map(::fakePoolNetwork)
        for (pool in pools) {
            val cidr = schemaField(pool, "ippool") as? String
                ?: throw IllegalArgumentException("Invalid FakeDNS pool CIDR")
            val range = fakePoolNetwork(cidr)
            val size = when (val value = schemaField(pool, "poolsize")) {
                is Byte, is Short, is Int, is Long -> (value as Number).toLong()
                is java.math.BigInteger -> try { value.longValueExact() } catch (_: ArithmeticException) {
                    throw IllegalArgumentException("Invalid FakeDNS pool size")
                }
                else -> throw IllegalArgumentException("Invalid FakeDNS pool size")
            }
            require(size > 0 && log2(size.toDouble()) < range.address.size * 8 - range.prefix) {
                "FakeDNS pool size exceeds its address capacity"
            }
            require(reserved.none(range::overlaps)) { "FakeDNS pool overlaps a reserved adapter range" }
        }
        if (explicit || !inspectServers) return explicit
        val dns = schemaField(config, "dns") as? JSONObject ?: return false
        val servers = schemaField(dns, "servers") as? JSONArray ?: return false
        for (index in 0 until servers.length()) {
            val server = servers.opt(index)
            val address = if (server is JSONObject) schemaField(server, "address") else server
            if (address is String && schemaFold(XrayPortSpec.coreAddressText(address)) == "fakedns") return true
        }
        return false
    }

    private data class FakePoolNetwork(val address: ByteArray, val prefix: Int) {
        fun overlaps(other: FakePoolNetwork): Boolean {
            if (address.size != other.address.size) return false
            for (bit in 0 until minOf(prefix, other.prefix)) {
                val mask = 1 shl (7 - bit % 8)
                if ((address[bit / 8].toInt() and mask) != (other.address[bit / 8].toInt() and mask)) return false
            }
            return true
        }
    }

    private fun fakePoolNetwork(cidr: String): FakePoolNetwork {
        val parts = cidr.split('/')
        require(parts.size == 2 && parts[1].matches(Regex("[0-9]+"))) { "Invalid FakeDNS pool CIDR" }
        if (parts[0].contains(':') && parts[0].contains('.'))
            require(literalAddress(parts[0].substringAfterLast(':'), allowBrackets = false)?.address?.size == 4) {
                "Invalid FakeDNS pool CIDR"
            }
        // ParseCIDR accepts plain numeric addresses, not scopes, brackets or
        // whitespace. Lexical validation in literalAddress prevents DNS lookup.
        val parsed = literalAddress(parts[0], allowBrackets = false)?.address
            ?: throw IllegalArgumentException("Invalid FakeDNS pool CIDR")
        // Java collapses IPv4-mapped IPv6 to four bytes; preserve its CIDR family.
        val address = if (parts[0].contains(':') && parsed.size == 4)
            ByteArray(10) + byteArrayOf(0xff.toByte(), 0xff.toByte()) + parsed else parsed
        val prefix = parts[1].toIntOrNull() ?: throw IllegalArgumentException("Invalid FakeDNS pool CIDR")
        require(prefix in 0..address.size * 8) { "Invalid FakeDNS pool CIDR" }
        return FakePoolNetwork(address, prefix)
    }

    private fun streamIsChained(stream: JSONObject): Boolean {
        canonicalize(stream, "sockopt")
        if (stream.isNull("sockopt")) return false
        val options = objectValue(stream, "sockopt") ?: return false
        canonicalize(options, "dialerProxy")
        return !options.isNull("dialerProxy") && !optionalString(options, "dialerProxy").isNullOrEmpty()
    }

    private fun prepareStream(stream: JSONObject, pinEndpoint: (String) -> Unit, independentDownload: Boolean = false,
                              inheritedSocketPolicy: Boolean = false, effectiveChain: Boolean? = null,
                              environment: (String) -> String?, changes: PreparationChanges?) {
        canonicalize(stream, "sockopt", "address", "network", "method", "xhttpSettings", "splithttpSettings")
        val chained = effectiveChain ?: streamIsChained(stream)
        // Core treats an absent or null SocketSettings as nil. The independent
        // download keeps its own policy; only Core's explicit penetrate flag
        // makes it inherit the parent at dial time.
        val penetrating = if (inheritedSocketPolicy) false else {
            val sockopt = if (stream.isNull("sockopt")) JSONObject() else objectValue(stream, "sockopt") ?: JSONObject()
            canonicalize(sockopt, "domainStrategy", "addressPortStrategy", "dialerProxy", "penetrate")
            val addressPortStrategy = if (sockopt.isNull("addressPortStrategy")) null else optionalString(sockopt, "addressPortStrategy")
            require(addressPortStrategy.isNullOrEmpty() || addressPortStrategy.equals("none", true)) {
                "SRV/TXT endpoint overrides cannot use the protected system DNS policy"
            }
            sockopt.put("domainStrategy", if (chained) "AsIs" else "ForceIP")
            stream.put("sockopt", sockopt)
            sockopt.opt("penetrate") == true
        }
        // Core method overrides network; JSON null retains the fallback/default.
        val method = if (stream.isNull("method")) null else optionalString(stream, "method")
        val network = method ?: if (stream.isNull("network")) "tcp" else optionalString(stream, "network")
        val xhttp = network?.lowercase(Locale.ROOT) in setOf("xhttp", "splithttp")
        if (network.equals("xdrive", ignoreCase = true)) {
            optionalString(stream, "address")?.let { raw ->
                stream.put("address", XrayPortSpec.bindAddressEnvironment(raw, environment) { changes?.record(PreparationChange.ADDRESS_ENVIRONMENT_BOUND) })
            }
            val targets = XdriveServicePolicy.targets(stream)
            if (!chained) targets.forEach { pinEndpoint(it.host) }
            return
        }
        // Core consumes the immediate download as an XHTTP Config, regardless
        // of whether its socket policy is independent or inherited.
        require(!independentDownload || xhttp) { "XHTTP download transport must be xhttp or splithttp" }
        // Primary TCP/WS/gRPC/XHTTP use the protocol's server address. Only
        // XDRIVE uses the primary MemoryStreamConfig destination; an independent
        // XHTTP download always has its own destination, regardless of method.
        if (independentDownload)
            optionalString(stream, "address")?.let { raw ->
                val address = XrayPortSpec.bindAddressEnvironment(raw, environment) { changes?.record(PreparationChange.ADDRESS_ENVIRONMENT_BOUND) }
                stream.put("address", address)
                if (!chained) pinEndpoint(address)
            }
        // getHTTPClient consumes the immediate download's own address and TLS,
        // with either its own or inherited socket policy. It never recursively
        // dials another nested XHTTP download.
        if (independentDownload) return
        if (!xhttp) return
        fun nullableObject(value: JSONObject, key: String) =
            if (value.isNull(key)) null else objectValue(value, key)
        // These are separate Core aliases with defined precedence, not ambiguous
        // duplicate keys. Do not rewrite or bootstrap the inactive object.
        val transport = nullableObject(stream, "xhttpSettings") ?: nullableObject(stream, "splithttpSettings") ?: return
        canonicalize(transport, "extra", "downloadSettings")
        if (transport.has("extra")) {
            // Even explicit extra:null replaces outer advanced settings in Core.
            val extra = nullableObject(transport, "extra") ?: return
            canonicalize(extra, "downloadSettings")
            nullableObject(extra, "downloadSettings")?.let {
                prepareStream(it, pinEndpoint, independentDownload = true, inheritedSocketPolicy = penetrating,
                    effectiveChain = if (penetrating) chained else null, environment = environment, changes = changes)
            }
        } else nullableObject(transport, "downloadSettings")?.let {
            prepareStream(it, pinEndpoint, independentDownload = true, inheritedSocketPolicy = penetrating,
                    effectiveChain = if (penetrating) chained else null, environment = environment, changes = changes)
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
            val virtual = VIRTUAL_SERVER.split('.').fold(0L) { acc, byte -> (acc shl 8) or byte.toLong() }
            (number and mask) == (virtual and mask)
        }
    }

    /** InetAddress is used only after lexical validation prevents any resolver access. */
    private fun literalAddress(raw: String, allowBrackets: Boolean = true): InetAddress? {
        val value = if (allowBrackets && raw.startsWith('[') && raw.endsWith(']')) raw.drop(1).dropLast(1) else raw
        if (value.contains(':')) {
            if (!value.matches(Regex("[0-9a-fA-F:.]+"))) return null
            return runCatching { InetAddress.getByName(value) }.getOrNull()
        }
        val bytes = value.split('.')
        if (bytes.size != 4 || bytes.any { it.isEmpty() || it.any { c -> c !in '0'..'9' } || (it.length > 1 && it[0] == '0') || (it.toIntOrNull() ?: -1) !in 0..255 }) return null
        return InetAddress.getByAddress(bytes.map { it.toInt().toByte() }.toByteArray())
    }

    private fun isVirtualAddress(address: InetAddress): Boolean = address.address.contentEquals(literalAddress(VIRTUAL_SERVER)!!.address)

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
