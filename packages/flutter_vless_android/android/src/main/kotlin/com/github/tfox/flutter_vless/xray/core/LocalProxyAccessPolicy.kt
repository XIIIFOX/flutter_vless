package com.github.tfox.flutter_vless.xray.core

import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom

/** Native session secret: deliberately not Serializable and never stored in the public DTO. */
internal class LocalProxyCredentials(val username: String, val password: String) {
    init {
        require(username.toByteArray(Charsets.UTF_8).size in 1..255) { "Invalid local username" }
        require(password.toByteArray(Charsets.UTF_8).size in 1..255) { "Invalid local password" }
    }
    override fun toString() = "LocalProxyCredentials(<redacted>)"
    companion object {
        fun generate(): LocalProxyCredentials {
            val random = SecureRandom()
            fun token(): String = ByteArray(32).also(random::nextBytes)
                .joinToString("") { "%02x".format(it.toInt() and 255) }
            return LocalProxyCredentials(token(), token())
        }
    }
}

internal object LocalProxyAccessPolicy {
    private fun canonicalize(value: JSONObject, fields: Set<String>) {
        val seen = mutableSetOf<String>()
        for (key in value.keys().asSequence().toList()) {
            val canonical = fields.firstOrNull { it.equals(key, ignoreCase = true) } ?: continue
            // Go also folds a few non-ASCII characters (for example long-s). Reject ambiguous spellings.
            require(key.all { it.code < 128 }) { "Unsupported native configuration field spelling" }
            require(seen.add(canonical)) { "Duplicate native configuration field" }
            if (key != canonical) {
                val child = value.get(key)
                value.remove(key)
                value.put(canonical, child)
            }
        }
    }
    fun normalizeConfigInputs(json: JSONObject) {
        // Go's decoder treats struct keys case-insensitively. Validate the same representation.
        canonicalize(json, setOf("inbounds", "outbounds", "log", "api", "stats", "policy", "routing", "dns"))
        json.optJSONArray("inbounds")?.let { inbounds ->
            for (i in 0 until inbounds.length()) normalizeInput(inbounds.getJSONObject(i))
        }
    }
    private fun normalizeInput(input: JSONObject) {
        canonicalize(input, setOf("tag", "protocol", "listen", "port", "settings"))
        input.optJSONObject("settings")?.let { settings ->
            canonicalize(settings, setOf("auth", "accounts", "users", "udp"))
            for (name in listOf("accounts", "users")) settings.optJSONArray(name)?.let { accounts ->
                for (i in 0 until accounts.length()) canonicalize(accounts.getJSONObject(i), setOf("user", "pass"))
            }
        }
    }
    fun credentialsForProxyOnly(json: JSONObject, port: Int): LocalProxyCredentials? {
        val inputs = json.getJSONArray("inbounds")
        for (i in 0 until inputs.length()) {
            val input = inputs.getJSONObject(i)
            if (input.optString("protocol").lowercase() == "socks") {
                require((input.optJSONObject("settings")?.optString("auth", "noauth") ?: "noauth") in setOf("", "noauth", "password")) {
                    "Unsupported explicit SOCKS auth mode"
                }
            }
        }
        for (i in 0 until inputs.length()) {
            val input = inputs.getJSONObject(i)
            val listen = input.optString("listen")
            if (XrayPortSpec.isUnixListen(listen)) continue
            if (input.optString("protocol").lowercase() != "socks" || input.optInt("port") != port) continue
            val settings = input.optJSONObject("settings") ?: JSONObject()
            val auth = settings.optString("auth", "noauth")
            if (auth != "password") return null
            val accounts = settings.optJSONArray("accounts") ?: settings.optJSONArray("users")
                ?: error("Proxy-only credentials are unavailable")
            require(accounts.length() > 0) { "Proxy-only credentials are unavailable" }
            // Native accounts is a map: the last occurrence of a username wins.
            val account = accounts.getJSONObject(accounts.length() - 1)
            return LocalProxyCredentials(account.getString("user"), account.getString("pass"))
        }
        error("Proxy-only SOCKS input is unavailable")
    }

    /** Authenticate only the private listener inserted by the VPN adapter.
     * Imported listeners and their explicit authentication belong to the caller. */
    fun apply(inbounds: JSONArray, credentials: LocalProxyCredentials, managedPort: Int) {
        val matches = (0 until inbounds.length()).map(inbounds::getJSONObject).filter {
            it.optString("protocol") == "socks" && it.optInt("port") == managedPort && it.optString("listen") == "127.0.0.1"
        }
        require(matches.size == 1 && matches[0].optString("listen") == "127.0.0.1") {
            "Private VPN SOCKS listener is unavailable"
        }
        val inbound = matches.single()
        val settings = inbound.optJSONObject("settings") ?: JSONObject()
        settings.put("accounts", JSONArray().put(JSONObject().put("user", credentials.username).put("pass", credentials.password)))
        settings.put("auth", "password")
        settings.put("udp", true)
        settings.put("ip", "127.0.0.1")
        inbound.put("settings", settings)
    }
}
