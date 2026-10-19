package com.github.tfox.flutter_vless.xray.core

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.Locale

/** Bind only files Core loads, keeping reload paths independent of process env. */
internal object XrayCertificateAssets {
    fun validateDirectory(requested: String?): File? = requested?.let {
        File(it).also { directory ->
            require(directory.isAbsolute && directory.isDirectory) {
                "Certificate asset directory must be an existing absolute directory"
            }
        }
    }

    fun prepare(configJson: String, requested: String?): JSONObject {
        val directory = validateDirectory(requested)
        val config = JSONObject(configJson)
        if (directory == null) return config

        fun key(owner: JSONObject, name: String): String? {
            val matches = owner.keys().asSequence().filter {
                it.replace('\u017f', 's').replace('\u212a', 'k').lowercase(Locale.ROOT) == name
            }.toList()
            require(matches.size <= 1) { "Conflicting certificate configuration keys" }
            return matches.singleOrNull()
        }
        fun field(owner: JSONObject, name: String): Any? = key(owner, name)?.let(owner::opt)
        fun objectField(owner: JSONObject, name: String): JSONObject? {
            val value = field(owner, name)
            if (value == null || value == JSONObject.NULL) return null
            return value as? JSONObject ?: throw IllegalArgumentException("Invalid certificate configuration object")
        }
        fun bindFile(certificate: JSONObject, name: String) {
            val spelling = key(certificate, name) ?: return
            val file = certificate.opt(spelling) as? String ?: return
            if (file.isNotEmpty() && !File(file).isAbsolute)
                certificate.put(spelling, directory.resolve(file).normalize().absolutePath)
        }
        fun tlsFiles(tls: JSONObject) {
            val certificates = field(tls, "certificates") as? JSONArray ?: return
            for (index in 0 until certificates.length()) {
                val certificate = certificates.optJSONObject(index) ?: continue
                bindFile(certificate, "certificatefile")
                bindFile(certificate, "keyfile")
            }
        }
        fun stream(value: JSONObject) {
            // Inactive TLS dictionaries are not built by Core. In particular,
            // their file-like values must not become portable file references.
            if ((field(value, "security") as? String).equals("tls", ignoreCase = true)) {
                objectField(value, "tlssettings")?.let(::tlsFiles)
            }
            // These UDP mask settings build their own TLSConfig independently
            // of the stream security/network. Other mask metadata stays opaque.
            val masks = objectField(value, "finalmask")?.let { field(it, "udp") } as? JSONArray
            if (masks != null) for (index in 0 until masks.length()) {
                val mask = masks.optJSONObject(index) ?: continue
                when ((field(mask, "type") as? String)?.lowercase(Locale.ROOT)) {
                    "realm" -> objectField(mask, "settings")?.let { objectField(it, "tlsconfig") }?.let(::tlsFiles)
                    "xdns" -> {
                        val resolvers = objectField(mask, "settings")?.let { field(it, "resolvers") } as? JSONArray ?: continue
                        for (resolver in 0 until resolvers.length()) {
                            val entry = resolvers.optJSONObject(resolver) ?: continue
                            objectField(entry, "tlsconfig")?.let(::tlsFiles)
                        }
                    }
                }
            }
            // StreamConfig.Build compiles the effective XHTTP settings even
            // when the parent selected another network. These are Build/file
            // semantics, unlike physical endpoint bootstrap selection.
            val transport = objectField(value, "xhttpsettings") ?: objectField(value, "splithttpsettings") ?: return
            val extra = key(transport, "extra")
            val effective = if (extra == null) transport else {
                if (transport.isNull(extra)) return
                transport.opt(extra) as? JSONObject
                    ?: throw IllegalArgumentException("Invalid certificate transport configuration")
            }
            objectField(effective, "downloadsettings")?.let(::stream)
        }
        for (collection in listOf("inbounds", "outbounds")) {
            val entries = field(config, collection) as? JSONArray ?: continue
            for (index in 0 until entries.length()) {
                val entry = entries.optJSONObject(index) ?: continue
                objectField(entry, "streamsettings")?.let(::stream)
            }
        }
        return config
    }
}
