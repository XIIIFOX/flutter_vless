package com.github.tfox.flutter_vless.xray.core

import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** File-only producer/export contract. Neither the default tests nor export start Core. */
class AndroidXhttpTlsExportTest {
    private val modes = listOf("independent", "wrong_ca", "wrong_sni")
    private val credentials = LocalProxyCredentials("session-user", "session-password")
    private val directoryPermissions = PosixFilePermissions.fromString("rwx------")
    private val filePermissions = PosixFilePermissions.fromString("rw-------")

    @Test fun exportExactPreparedXhttpTlsBatchRuntime() {
        val external = System.getenv("FLVLESS_EXPORT_XHTTP_TLS_BATCH")
        if (external != null) {
            assertEquals(modes, exportBatch(Paths.get(external)).map { it.getString("mode") })
        } else withFixture { _, manifest ->
            val result = exportBatch(manifest)
            assertEquals(modes, result.map { it.getString("mode") })
            val entries = readJson(manifest).getJSONArray("entries")
            for (index in modes.indices) {
                val entry = entries.getJSONObject(index)
                val directory = Paths.get(entry.getString("outputDirectory"))
                val bytes = Files.readAllBytes(directory.resolve("config.json"))
                val metadata = readJson(directory.resolve("metadata.json"))
                assertEquals(sha256(bytes), metadata.getString("configSHA256"))
                assertEquals(credentials.username, metadata.getString("username"))
                assertEquals(credentials.password, metadata.getString("password"))
                assertEquals(directoryPermissions, Files.getPosixFilePermissions(directory))
                for (name in listOf("config.json", "metadata.json")) {
                    assertEquals(filePermissions, Files.getPosixFilePermissions(directory.resolve(name)))
                }
            }
        }
    }

    @Test fun rejectsMissingDuplicateOrUnorderedModesBeforeAnyOutput() = withFixture { _, manifest ->
        val original = readJson(manifest)
        val entries = original.getJSONArray("entries")
        for (bad in listOf(
            JSONArray().put(entries.getJSONObject(0)).put(entries.getJSONObject(1)),
            JSONArray().put(entries.getJSONObject(0)).put(entries.getJSONObject(0)).put(entries.getJSONObject(2)),
            JSONArray().put(entries.getJSONObject(1)).put(entries.getJSONObject(0)).put(entries.getJSONObject(2)))) {
            replaceJson(manifest, JSONObject().put("version", 1).put("entries", bad))
            refused { exportBatch(manifest) }
            assertNoOutputs(original)
        }
    }

    @Test fun rejectsSourceAndCAHashChangesBeforeAnyOutput() = withFixture { _, manifest ->
        val original = readJson(manifest)
        for (field in listOf("sourceSHA256", "caSHA256")) {
            val bad = JSONObject(original.toString())
            val entry = bad.getJSONArray("entries").getJSONObject(2)
            if (field == "sourceSHA256") entry.put(field, "0".repeat(64))
            else entry.getJSONArray("caFiles").getJSONObject(1).put("sha256", "0".repeat(64))
            replaceJson(manifest, bad)
            refused { exportBatch(manifest) }
            assertNoOutputs(original)
        }
    }

    @Test fun rejectsMissingCAAndCAOutsideOwnedAssets() = withFixture { directory, manifest ->
        val original = readJson(manifest)
        val missing = JSONObject(original.toString())
        missing.getJSONArray("entries").getJSONObject(2).getJSONArray("caFiles").getJSONObject(1)
            .put("path", directory.resolve("missing.pem").toString())
        replaceJson(manifest, missing)
        refused { exportBatch(manifest) }
        assertNoOutputs(original)
        val outside = directory.resolve("outside.pem")
        writePrivate(outside, "SYNTHETIC-NON-CERTIFICATE".toByteArray())
        val escaped = JSONObject(original.toString())
        escaped.getJSONArray("entries").getJSONObject(0).getJSONArray("caFiles").getJSONObject(0)
            .put("path", outside.toString()).put("sha256", sha256(Files.readAllBytes(outside)))
        replaceJson(manifest, escaped)
        refused { exportBatch(manifest) }
        assertNoOutputs(original)
    }

    @Test fun refusesStaleOutputIncludingEmptyDirectory() = withFixture { _, manifest ->
        val original = readJson(manifest)
        val output = Paths.get(original.getJSONArray("entries").getJSONObject(2).getString("outputDirectory"))
        Files.createDirectory(output, PosixFilePermissions.asFileAttribute(directoryPermissions))
        refused { exportBatch(manifest) }
        assertEquals(0, Files.list(output).use { it.count() }.toInt())
        for (index in 0..1) assertFalse(Files.exists(Paths.get(original.getJSONArray("entries")
            .getJSONObject(index).getString("outputDirectory")), NOFOLLOW_LINKS))
    }

    @Test fun rejectsRepeatedOutputAndPortsBeforeAnyOutput() = withFixture { _, manifest ->
        val original = readJson(manifest)
        for (field in listOf("outputDirectory", "privatePort", "uploadPort", "downloadPort")) {
            val bad = JSONObject(original.toString())
            val entries = bad.getJSONArray("entries")
            entries.getJSONObject(2).put(field, entries.getJSONObject(0).get(field))
            replaceJson(manifest, bad)
            refused { exportBatch(manifest) }
            assertNoOutputs(original)
        }
    }

    @Test fun rejectsMalformedSchemaAndRelativeManifest() = withFixture { _, manifest ->
        val original = readJson(manifest)
        for (bad in listOf(JSONObject(original.toString()).put("version", 2),
            JSONObject(original.toString()).put("version", "1"),
            JSONObject(original.toString()).put("unexpected", true))) {
            replaceJson(manifest, bad)
            refused { exportBatch(manifest) }
            assertNoOutputs(original)
        }
        refused { exportBatch(Paths.get("relative-manifest.json")) }
    }

    private data class InputFile(val path: Path, val sha256: String)
    private data class Entry(val mode: String, val source: InputFile, val output: Path,
        val privatePort: Int, val uploadPort: Int, val downloadPort: Int,
        val assets: Path, val caFiles: List<InputFile>)

    private fun exportBatch(manifest: Path): List<JSONObject> {
        val input = checkedFile(manifest, null)
        val batch = readJson(input.path)
        require(keys(batch) == setOf("version", "entries") && integer(batch, "version") == 1)
        val rawEntries = batch.getJSONArray("entries")
        require(rawEntries.length() == modes.size)
        val entries = modes.indices.map { index ->
            val raw = rawEntries.getJSONObject(index)
            require(keys(raw) == setOf("mode", "sourcePath", "sourceSHA256", "outputDirectory",
                "privatePort", "uploadPort", "downloadPort", "certificateAssetsDirectory", "caFiles"))
            require(raw.getString("mode") == modes[index])
            val source = checkedFile(Paths.get(raw.getString("sourcePath")), raw.getString("sourceSHA256"))
            val assets = checkedDirectory(Paths.get(raw.getString("certificateAssetsDirectory")))
            val ca = raw.getJSONArray("caFiles")
            require(ca.length() == 2)
            val caFiles = listOf("upload-ca.pem", "download-ca.pem").mapIndexed { caIndex, name ->
                val record = ca.getJSONObject(caIndex)
                require(keys(record) == setOf("path", "sha256"))
                checkedFile(Paths.get(record.getString("path")), record.getString("sha256")).also {
                    require(it.path.parent == assets && it.path.fileName.toString() == name)
                }
            }
            val output = Paths.get(raw.getString("outputDirectory"))
            require(output.isAbsolute && output == output.normalize())
            checkedDirectory(output.parent)
            require(!Files.exists(output, NOFOLLOW_LINKS))
            val ports = listOf("privatePort", "uploadPort", "downloadPort").map { integer(raw, it) }
            require(ports.all { it in 1..65535 } && ports.distinct().size == 3)
            Entry(modes[index], source, output, ports[0], ports[1], ports[2], assets, caFiles)
        }
        require(entries.map { it.source.path }.distinct().size == modes.size)
        require(entries.map { it.output }.distinct().size == modes.size)
        val allPorts = entries.flatMap { listOf(it.privatePort, it.uploadPort, it.downloadPort) }
        require(allPorts.distinct().size == allPorts.size)
        val allInputs = listOf(input) + entries.flatMap { listOf(it.source) + it.caFiles }
        for (entry in entries) {
            require(allInputs.none { it.path.startsWith(entry.output) })
            require(entries.none { it !== entry && it.output.startsWith(entry.output) })
        }
        // Validate and prepare the whole batch before creating even its first output directory.
        val products = entries.map { entry -> prepare(entry) }
        allInputs.forEach(::unchanged)
        entries.forEach { require(!Files.exists(it.output, NOFOLLOW_LINKS)) }
        for ((index, entry) in entries.withIndex()) {
            Files.createDirectory(entry.output, PosixFilePermissions.asFileAttribute(directoryPermissions))
            writePrivate(entry.output.resolve("config.json"), products[index].first)
            writePrivate(entry.output.resolve("metadata.json"), products[index].second.toString().toByteArray(Charsets.UTF_8))
        }
        allInputs.forEach(::unchanged)
        return products.map { it.second }
    }

    private fun prepare(entry: Entry): Pair<ByteArray, JSONObject> {
        val raw = Files.readAllBytes(entry.source.path)
        val text = String(raw, Charsets.UTF_8)
        require(text.toByteArray(Charsets.UTF_8).contentEquals(raw))
        val source = JSONObject(text)
        require(source.has("api") && source.isNull("api") && source.getJSONArray("inbounds").length() == 0)
        val primary = source.getJSONArray("outbounds").getJSONObject(0)
        require(primary.getString("tag") == "proxy" && primary.getString("protocol") == "vless")
        require(primary.getJSONObject("settings").getString("address") == "endpoint.invalid")
        require(integer(primary.getJSONObject("settings"), "port") == entry.uploadPort)
        val stream = primary.getJSONObject("streamSettings")
        val transport = stream.getJSONObject("xhttpSettings")
        val download = transport.getJSONObject("downloadSettings")
        require(stream.getString("network") == "xhttp" && stream.getString("security") == "tls")
        require(stream.getJSONObject("sockopt").get("penetrate") == false)
        require(!stream.getJSONObject("sockopt").has("dialerProxy"))
        require(download.getString("network") == "xhttp" && download.getString("security") == "tls")
        require(download.getString("address") == "endpoint.invalid" && integer(download, "port") == entry.downloadPort)
        require(!download.getJSONObject("sockopt").has("dialerProxy"))
        require(transport.getString("mode") == "packet-up" && transport.getString("host") == "upload.invalid")
        require(download.getJSONObject("xhttpSettings").getString("host") == "download.invalid")
        fun checkTLS(tls: JSONObject, expectedName: String, file: InputFile) {
            require(tls.getString("serverName") == expectedName && tls.getString("masterKeyLog") == "")
            require(tls.get("disableSystemRoot") == true && sameJson(tls.getJSONArray("alpn"), JSONArray().put("h2")))
            val certificates = tls.getJSONArray("certificates")
            require(certificates.length() == 1 && certificates.getJSONObject(0).getString("usage") == "verify")
            require(certificates.getJSONObject(0).getString("certificateFile") == file.path.toString())
        }
        checkTLS(stream.getJSONObject("tlsSettings"), "upload-tls.invalid", entry.caFiles[0])
        checkTLS(download.getJSONObject("tlsSettings"),
            if (entry.mode == "wrong_sni") "wrong-download.invalid" else "download-tls.invalid", entry.caFiles[1])
        val calls = mutableListOf<String>()
        val prepared = AndroidTunnelDnsPolicy.prepare(text, policy = "proxy", proxyOutboundTag = "proxy",
            environment = { error("Endpoint environment lookup is forbidden") }) { host ->
            require(host == "endpoint.invalid")
            calls += host
            listOf("127.0.0.1")
        }
        assertEquals(listOf("endpoint.invalid"), calls)
        assertEquals(setOf("endpoint.invalid"), prepared.bootstrapHostnames)
        assertEquals(setOf("127.0.0.1"), prepared.bootstrapAddresses)
        val candidate = XrayConfig(V2RAY_FULL_JSON_CONFIG = prepared.configJson,
            ANDROID_DNS_POLICY = "proxy", LOCAL_SOCKS5_PORT = entry.privatePort,
            CERTIFICATE_ASSETS_DIRECTORY = entry.assets.toString())
        val availability = mutableListOf<Int>()
        val runtime = XrayCoreManager.buildRuntimeConfigJson(candidate, entry.assets.toFile(), credentials, prepared,
            tcpAvailable = { availability += it; require(it == entry.privatePort); true },
            environment = { error("Listener environment lookup is forbidden") })
        assertEquals(listOf(entry.privatePort), availability)
        assertEquals(entry.privatePort, candidate.LOCAL_SOCKS5_PORT)
        assertEquals(0, candidate.LOCAL_API_PORT)
        assertEquals(prepared.configJson, candidate.V2RAY_FULL_JSON_CONFIG)
        assertTrue(runtime.has("api") && runtime.isNull("api"))
        val actualStream = runtime.getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")
        val actualTransport = actualStream.getJSONObject("xhttpSettings")
        val actualDownload = actualTransport.getJSONObject("downloadSettings")
        // Compare complete TLS maps, including blank key-log, trust/name, ALPN and file references.
        assertTrue(sameJson(stream.getJSONObject("tlsSettings"), actualStream.getJSONObject("tlsSettings")))
        assertTrue(sameJson(download.getJSONObject("tlsSettings"), actualDownload.getJSONObject("tlsSettings")))
        assertEquals("tls", actualStream.getString("security"))
        assertEquals("tls", actualDownload.getString("security"))
        assertEquals("endpoint.invalid", actualDownload.getString("address"))
        assertEquals(entry.downloadPort, actualDownload.getInt("port"))
        val expectedTransport = JSONObject(transport.toString()).apply { remove("downloadSettings") }
        val effectiveTransport = JSONObject(actualTransport.toString()).apply { remove("downloadSettings") }
        assertTrue(sameJson(expectedTransport, effectiveTransport))
        assertTrue(sameJson(download.getJSONObject("xhttpSettings"), actualDownload.getJSONObject("xhttpSettings")))
        assertEquals(false, actualStream.getJSONObject("sockopt").get("penetrate"))
        assertEquals(7, actualDownload.getJSONObject("sockopt").getInt("tcpKeepAliveIdle"))
        assertEquals("ForceIP", actualStream.getJSONObject("sockopt").getString("domainStrategy"))
        assertEquals("ForceIP", actualDownload.getJSONObject("sockopt").getString("domainStrategy"))
        val managed = runtime.getJSONArray("inbounds").getJSONObject(0)
        assertEquals(prepared.managedInboundTag, managed.getString("tag"))
        assertEquals(entry.privatePort, managed.getInt("port"))
        assertEquals("127.0.0.1", managed.getString("listen"))
        val local = managed.getJSONObject("settings")
        assertEquals("password", local.getString("auth"))
        assertEquals(credentials.username, local.getJSONArray("accounts").getJSONObject(0).getString("user"))
        assertEquals(credentials.password, local.getJSONArray("accounts").getJSONObject(0).getString("pass"))
        assertTrue(raw.contentEquals(Files.readAllBytes(entry.source.path)))
        entry.caFiles.forEach(::unchanged)
        val bytes = runtime.toString().toByteArray(Charsets.UTF_8)
        val ca = JSONArray()
        entry.caFiles.forEach { ca.put(JSONObject().put("path", it.path.toString()).put("sha256", it.sha256)) }
        val metadata = JSONObject().put("version", 1).put("mode", entry.mode)
            .put("sourceSHA256", entry.source.sha256)
            .put("preparedSHA256", sha256(prepared.configJson.toByteArray(Charsets.UTF_8)))
            .put("configSHA256", sha256(bytes)).put("privatePort", entry.privatePort)
            .put("uploadPort", entry.uploadPort).put("downloadPort", entry.downloadPort)
            .put("certificateAssetsDirectory", entry.assets.toString()).put("caFiles", ca)
            .put("managedInboundTag", prepared.managedInboundTag)
            .put("username", credentials.username).put("password", credentials.password)
        // Explicit proxy policy intentionally owns system DNS; caller-DNS preservation is not asserted.
        return bytes to metadata
    }

    private fun integer(value: JSONObject, key: String): Int {
        val number = value.get(key)
        require(number is Int || number is Long)
        val wide = (number as Number).toLong()
        require(wide in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong())
        return wide.toInt()
    }

    private fun keys(value: JSONObject): Set<String> = value.keys().asSequence().toSet()

    private fun sameJson(left: Any?, right: Any?): Boolean = when {
        left is JSONObject && right is JSONObject -> keys(left) == keys(right) &&
            keys(left).all { sameJson(left.get(it), right.get(it)) }
        left is JSONArray && right is JSONArray -> left.length() == right.length() &&
            (0 until left.length()).all { sameJson(left.get(it), right.get(it)) }
        else -> left == right
    }

    private fun checkedFile(path: Path, expected: String?): InputFile {
        require(path.isAbsolute && path == path.normalize() && Files.isRegularFile(path, NOFOLLOW_LINKS))
        require(path.toRealPath() == path && Files.getPosixFilePermissions(path) == filePermissions)
        require(Files.size(path) in 1..(1024 * 1024))
        val actual = sha256(Files.readAllBytes(path))
        if (expected != null) require(expected.matches(Regex("[0-9a-f]{64}")) && actual == expected)
        return InputFile(path, actual)
    }

    private fun checkedDirectory(path: Path): Path {
        require(path.isAbsolute && path == path.normalize() && Files.isDirectory(path, NOFOLLOW_LINKS))
        require(path.toRealPath() == path && Files.getPosixFilePermissions(path) == directoryPermissions)
        return path
    }

    private fun unchanged(input: InputFile) {
        require(checkedFile(input.path, input.sha256).sha256 == input.sha256)
    }

    private fun refused(action: () -> Unit) {
        try { action(); fail("Invalid batch was admitted") }
        catch (_: IllegalArgumentException) { /* Expected fixed input refusal. */ }
        catch (_: java.io.IOException) { /* Missing/stale owned file. */ }
    }

    private fun assertNoOutputs(manifest: JSONObject) {
        val entries = manifest.getJSONArray("entries")
        for (index in 0 until entries.length()) {
            assertFalse(Files.exists(Paths.get(entries.getJSONObject(index).getString("outputDirectory")), NOFOLLOW_LINKS))
        }
    }

    private fun withFixture(action: (Path, Path) -> Unit) {
        val directory = Files.createTempDirectory("android-xhttp-tls-").toRealPath()
        Files.setPosixFilePermissions(directory, directoryPermissions)
        try {
            val entries = JSONArray()
            for ((index, mode) in modes.withIndex()) {
                val case = Files.createDirectory(directory.resolve(mode), PosixFilePermissions.asFileAttribute(directoryPermissions))
                val assets = Files.createDirectory(case.resolve("assets"), PosixFilePermissions.asFileAttribute(directoryPermissions))
                val uploadCA = assets.resolve("upload-ca.pem")
                val downloadCA = assets.resolve("download-ca.pem")
                // Native preparation binds files; it does not parse certificates or execute TLS here.
                writePrivate(uploadCA, "FILE-ONLY-UPLOAD-CA".toByteArray())
                writePrivate(downloadCA, "FILE-ONLY-$mode-DOWNLOAD-CA".toByteArray())
                val port = 18100 + index * 10
                val source = case.resolve("source.json")
                writePrivate(source, syntheticSource(mode, port + 1, port + 2, uploadCA, downloadCA)
                    .toString().toByteArray(Charsets.UTF_8))
                entries.put(JSONObject().put("mode", mode).put("sourcePath", source.toString())
                    .put("sourceSHA256", sha256(Files.readAllBytes(source)))
                    .put("outputDirectory", case.resolve("export").toString()).put("privatePort", port)
                    .put("uploadPort", port + 1).put("downloadPort", port + 2)
                    .put("certificateAssetsDirectory", assets.toString())
                    .put("caFiles", JSONArray().put(fileRecord(uploadCA)).put(fileRecord(downloadCA))))
            }
            val manifest = directory.resolve("batch.json")
            writePrivate(manifest, JSONObject().put("version", 1).put("entries", entries).toString().toByteArray(Charsets.UTF_8))
            action(directory, manifest)
        } finally {
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private fun syntheticSource(mode: String, uploadPort: Int, downloadPort: Int, uploadCA: Path, downloadCA: Path): JSONObject {
        fun tls(name: String, ca: Path) = JSONObject().put("serverName", name).put("alpn", JSONArray().put("h2"))
            .put("disableSystemRoot", true).put("masterKeyLog", "")
            .put("certificates", JSONArray().put(JSONObject().put("usage", "verify").put("certificateFile", ca.toString())))
        val headers = JSONObject().put("X-Fixture-Nonce", "fixed-inert-nonce")
            .put("X-Data", JSONArray().put("first").put("second"))
        val download = JSONObject().put("address", "endpoint.invalid").put("port", downloadPort)
            .put("network", "xhttp").put("security", "tls")
            .put("tlsSettings", tls(if (mode == "wrong_sni") "wrong-download.invalid" else "download-tls.invalid", downloadCA))
            .put("sockopt", JSONObject().put("tcpKeepAliveIdle", 7))
            .put("xhttpSettings", JSONObject().put("path", "/download").put("host", "download.invalid").put("headers", headers))
        val stream = JSONObject().put("network", "xhttp").put("security", "tls")
            .put("tlsSettings", tls("upload-tls.invalid", uploadCA)).put("sockopt", JSONObject().put("penetrate", false))
            .put("xhttpSettings", JSONObject().put("path", "/upload").put("host", "upload.invalid")
                .put("mode", "packet-up").put("headers", headers).put("downloadSettings", download))
        return JSONObject().put("inbounds", JSONArray()).put("api", JSONObject.NULL)
            .put("outbounds", JSONArray().put(JSONObject().put("tag", "proxy").put("protocol", "vless")
                .put("settings", JSONObject().put("address", "endpoint.invalid").put("port", uploadPort)
                    .put("id", "00000000-0000-0000-0000-000000000001").put("encryption", "none"))
                .put("streamSettings", stream)).put(JSONObject().put("tag", "direct").put("protocol", "freedom"))
                .put(JSONObject().put("tag", "block").put("protocol", "blackhole")))
            .put("dns", JSONObject().put("hosts", JSONObject().put("endpoint.invalid", "127.0.0.2"))
                .put("servers", JSONArray().put("tcp://9.9.9.9")).put("queryStrategy", "UseIPv4"))
    }

    private fun fileRecord(path: Path) = JSONObject().put("path", path.toString()).put("sha256", sha256(Files.readAllBytes(path)))
    private fun readJson(path: Path) = JSONObject(String(Files.readAllBytes(path), Charsets.UTF_8))
    private fun replaceJson(path: Path, value: JSONObject) { Files.write(path, value.toString().toByteArray(Charsets.UTF_8)) }
    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun writePrivate(path: Path, bytes: ByteArray) {
        Files.newByteChannel(path, setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
            PosixFilePermissions.asFileAttribute(filePermissions)).use { channel ->
            val buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) channel.write(buffer)
        }
    }
}
