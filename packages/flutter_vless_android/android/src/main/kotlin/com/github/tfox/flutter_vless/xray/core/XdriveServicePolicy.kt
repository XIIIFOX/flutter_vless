package com.github.tfox.flutter_vless.xray.core

import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.util.Locale

/** Only the pinned Core's S3/Google Drive clients have finite, qualified origins.
 * Folder IDs/object prefixes and secrets are opaque remote data, never files. */
internal object XdriveServicePolicy {
    data class Target(val host: String, val port: Int)

    private fun field(objectValue: JSONObject, name: String): Any? {
        val keys = objectValue.keys().asSequence().filter {
            it.replace('ſ', 's').replace('K', 'k').lowercase(Locale.ROOT) == name.lowercase(Locale.ROOT)
        }.toList()
        require(keys.size <= 1) { "Conflicting XDRIVE field aliases" }
        return keys.singleOrNull()?.let(objectValue::opt)?.takeUnless { it === JSONObject.NULL }
    }
    fun active(stream: JSONObject): Boolean {
        val method = field(stream, "method")
        val network = method ?: field(stream, "network") ?: "tcp"
        require(network is String) { "Invalid stream transport" }
        return network.equals("xdrive", true)
    }
    private fun string(value: Any?): String? {
        require(value == null || value is String) { "Invalid XDRIVE string field" }
        return value as? String
    }
    private fun validName(value: String): Boolean = value.isNotEmpty() &&
        value.none { it < ' ' || it == '\u007f' || it == '\\' } &&
        value.split('/').all { it.isNotEmpty() && it != "." && it != ".." }

    fun targets(stream: JSONObject): List<Target> {
        val settings = field(stream, "xdriveSettings") as? JSONObject
            ?: throw IllegalArgumentException("XDRIVE settings must be an object")
        val service = string(field(settings, "service"))
        val folder = string(field(settings, "remoteFolder"))
        require(!folder.isNullOrEmpty()) { "XDRIVE remote folder is required" }
        val secrets = field(settings, "secrets") as? JSONArray
            ?: throw IllegalArgumentException("XDRIVE secrets must be an array")
        for (index in 0 until secrets.length())
            require(secrets.opt(index) is String && secrets.getString(index).isNotEmpty()) { "Invalid XDRIVE secret" }
        val logical = when (service) {
            "google-drive", "Google Drive" -> {
                require(secrets.length() == 3) { "Google Drive requires three secrets" }
                listOf(Target("oauth2.googleapis.com", 443), Target("www.googleapis.com", 443))
            }
            "s3" -> {
                require(secrets.length() in 2..3 && validName(folder.removeSuffix("/"))) { "Invalid S3 credentials or prefix" }
                val s3 = field(settings, "s3") as? JSONObject
                    ?: throw IllegalArgumentException("S3 settings are required")
                val raw = string(field(s3, "endpoint")) ?: throw IllegalArgumentException("S3 endpoint is required")
                val uri = runCatching { URI(raw) }.getOrElse { throw IllegalArgumentException("Invalid S3 endpoint URL") }
                val scheme = uri.scheme?.lowercase(Locale.ROOT)
                require(scheme in setOf("http", "https") && !uri.isOpaque && uri.rawUserInfo == null &&
                    uri.rawQuery == null && uri.rawFragment == null && !uri.host.isNullOrEmpty()) { "Invalid S3 endpoint URL" }
                val bucket = string(field(s3, "bucket")) ?: throw IllegalArgumentException("S3 bucket is required")
                require(validName(bucket) && '/' !in bucket) { "Invalid S3 bucket" }
                val pathStyle = field(s3, "pathStyle")
                require(pathStyle == null || pathStyle is Boolean) { "Invalid S3 addressing mode" }
                var host = uri.host.removePrefix("[").removeSuffix("]")
                if (pathStyle == false) {
                    require(host.any { it !in "0123456789." } && ':' !in host &&
                        bucket.all { it in "abcdefghijklmnopqrstuvwxyz0123456789-." } &&
                        !bucket.startsWith('.') && !bucket.endsWith('.') && ".." !in bucket) { "S3 virtual addressing requires DNS names" }
                    host = "$bucket.$host"
                }
                val port = if (uri.port == -1) if (scheme == "https") 443 else 80 else uri.port
                require(port in 1..65535) { "Invalid S3 endpoint port" }
                listOf(Target(host, port))
            }
            else -> throw IllegalArgumentException("XDRIVE service is not qualified for native VPN")
        }
        val front = string(field(stream, "address"))
        val rawPort = field(stream, "port")
        require(rawPort == null || rawPort is Int && rawPort in 0..65535) { "Invalid XDRIVE fronting port" }
        if (front == null) return logical
        require(front.isNotEmpty()) { "Empty XDRIVE fronting address" }
        return logical.map { Target(front, (rawPort as? Int)?.takeIf { it != 0 } ?: it.port) }.distinct()
    }

    /** Detect only active socket transports; dormant loopback/freedom metadata is not a service. */
    fun streams(config: JSONObject): List<JSONObject> {
        val result = mutableListOf<JSONObject>()
        for (collection in listOf("inbounds", "outbounds")) {
            val entries = field(config, collection) as? JSONArray ?: continue
            for (index in 0 until entries.length()) {
                val entry = entries.opt(index) as? JSONObject ?: continue
                if (collection == "outbounds" && string(field(entry, "protocol"))?.lowercase(Locale.ROOT) in
                    setOf("loopback", "freedom", "blackhole", "dns", "wireguard")) continue
                val stream = field(entry, "streamSettings") as? JSONObject ?: continue
                if (active(stream)) result.add(stream)
            }
        }
        return result
    }
    fun requiresLifetime(configJson: String): Boolean {
        val streams = streams(JSONObject(configJson))
        streams.forEach(::targets)
        return streams.isNotEmpty()
    }
    fun validate(config: JSONObject) { streams(config).forEach(::targets) }
}
