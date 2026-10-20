package com.github.tfox.flutter_vless.xray.core

import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import java.io.File
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Actual native producers with inert callbacks; optional CI export never starts Core. */
class AndroidLogicalChainExportTest {
    @Test fun exportExactPreparedLogicalChainRuntime() {
        fun port(name: String, fallback: Int): Int = System.getenv(name)?.let {
            requireNotNull(it.toIntOrNull()).also { value -> require(value in 1..65535) }
        } ?: fallback
        val outerPort = port("FLVLESS_CHAIN_OUTER_PORT", 19090)
        val privatePort = port("FLVLESS_CHAIN_PRIVATE_PORT", 10807)
        require(outerPort != privatePort)
        val source = JSONObject("""{
            "inbounds":[],"api":null,
            "dns":{"servers":["tcp://192.0.2.53"],"queryStrategy":"UseIPv4"},
            "outbounds":[{"tag":"proxy","protocol":"socks",
                "settings":{"servers":[{"address":"inside-only.invalid","port":1080}]},
                "streamSettings":{"sockopt":{"dialerProxy":"outer","domainStrategy":"AsIs"}}},
              {"tag":"outer","protocol":"socks",
                "settings":{"servers":[{"address":"127.0.0.1","port":$outerPort}]}},
              {"tag":"direct","protocol":"freedom"}],"routing":{"rules":[]}}
        """)
        val before = source.toString()
        val prepared = AndroidTunnelDnsPolicy.prepare(before, "proxy",
            environment = { error("No endpoint environment lookup expected") }) {
            error("Chained logical destination reached physical bootstrap")
        }
        assertTrue(prepared.bootstrapHostnames.isEmpty())
        assertEquals(setOf("127.0.0.1"), prepared.bootstrapAddresses)
        val credentials = LocalProxyCredentials("android-chain", "synthetic-chain-token")
        val candidate = XrayConfig(V2RAY_FULL_JSON_CONFIG = prepared.configJson,
            ANDROID_DNS_POLICY = "proxy", LOCAL_SOCKS5_PORT = privatePort)
        val availability = mutableListOf<Int>()
        val runtime = XrayCoreManager.buildRuntimeConfigJson(candidate, File("."), credentials, prepared,
            tcpAvailable = { availability += it; true }, environment = { error("No listener environment expected") })
        assertEquals(listOf(privatePort), availability)
        assertEquals(privatePort, candidate.LOCAL_SOCKS5_PORT)
        assertEquals(0, candidate.LOCAL_API_PORT)
        assertEquals(prepared.configJson, candidate.V2RAY_FULL_JSON_CONFIG)
        val proxy = runtime.getJSONArray("outbounds").getJSONObject(0)
        assertEquals("inside-only.invalid", proxy.getJSONObject("settings").getJSONArray("servers").getJSONObject(0).getString("address"))
        assertEquals("AsIs", proxy.getJSONObject("streamSettings").getJSONObject("sockopt").getString("domainStrategy"))
        assertEquals("ForceIP", runtime.getJSONArray("outbounds").getJSONObject(1).getJSONObject("streamSettings")
            .getJSONObject("sockopt").getString("domainStrategy"))
        val managed = runtime.getJSONArray("inbounds").getJSONObject(0)
        assertEquals(prepared.managedInboundTag, managed.getString("tag"))
        assertEquals(privatePort, managed.getInt("port"))
        assertEquals("127.0.0.1", managed.getString("listen"))
        assertEquals("password", managed.getJSONObject("settings").getString("auth"))
        assertEquals(credentials.username, managed.getJSONObject("settings").getJSONArray("accounts").getJSONObject(0).getString("user"))
        assertEquals(before, source.toString())
        val bytes = runtime.toString().toByteArray(Charsets.UTF_8)
        System.getenv("FLVLESS_EXPORT_LOGICAL_CHAIN_DIR")?.let { location ->
            val directory = Paths.get(location)
            require(directory.isAbsolute)
            Files.createDirectories(directory, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val metadata = JSONObject().put("version", 1).put("configSHA256", sha256(bytes))
                .put("sourceSHA256", sha256(before.toByteArray(Charsets.UTF_8)))
                .put("preparedSHA256", sha256(prepared.configJson.toByteArray(Charsets.UTF_8)))
                .put("privatePort", privatePort).put("outerPort", outerPort)
                .put("username", credentials.username).put("password", credentials.password)
                .put("managedInboundTag", prepared.managedInboundTag)
                .put("expectedLogicalHost", "inside-only.invalid").put("expectedLogicalPort", 1080)
                .put("expectedTargetHost", "nonce.invalid").put("expectedTargetPort", 18083)
            writePrivate(directory.resolve("config.json"), bytes)
            writePrivate(directory.resolve("metadata.json"), metadata.toString().toByteArray(Charsets.UTF_8))
        }
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it.toInt() and 255) }

    private fun writePrivate(path: Path, bytes: ByteArray) {
        Files.newByteChannel(path, setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use { channel ->
            val buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) channel.write(buffer)
        }
    }
}
