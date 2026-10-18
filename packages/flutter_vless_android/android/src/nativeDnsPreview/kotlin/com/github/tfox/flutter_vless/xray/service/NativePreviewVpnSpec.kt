package com.github.tfox.flutter_vless.xray.service

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Network
import android.os.Process
import android.system.Os
import com.github.tfox.flutter_vless.xray.core.LocalProxyCredentials
import java.io.Closeable
import java.io.File
import java.net.InetAddress
import java.net.ServerSocket
import java.security.MessageDigest
import java.util.UUID
import org.json.JSONObject

/** Present only in explicitly opted-in debug builds. Imported JSON cannot grant this policy. */
internal class NativePreviewVpnInput private constructor(
    val source: ByteArray,
    val sourceDigest: String,
    val core: File,
    val forwarder: File,
    val resolver: String,
    val egressIndex: Int,
    val includeBrowser: Boolean,
) {
    companion object {
        const val CAPABILITY = "native-instance-preview-1"
        const val CORE_COMMIT = "92ccc939aaf4f8965f369cf0b142e005aeaa11d5"
        const val VIRTUAL_DNS = "198.18.0.53"
        private const val MAX_SOURCE = 512 * 1024

        fun digest(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 255) }

        fun fromIntent(context: Context, intent: Intent): NativePreviewVpnInput {
            require(context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
            val source = requireNotNull(intent.getByteArrayExtra("source")).copyOf()
            require(source.size in 1..MAX_SOURCE)
            val sourceDigest = digest(source)
            require(sourceDigest == intent.getStringExtra("sourceSha256"))
            val testPackage = requireNotNull(intent.getStringExtra("testPackage"))
            // Library instrumentation is self-targeting; application tests use
            // a separate .test package. Resolve actual registered provenance.
            require(testPackage in setOf(context.packageName, context.packageName + ".test"))
            @Suppress("DEPRECATION")
            val instrumentation = context.packageManager.getInstrumentationInfo(
                ComponentName(testPackage, "androidx.test.runner.AndroidJUnitRunner"), 0)
            require(instrumentation.targetPackage == context.packageName)
            require(context.packageManager.checkSignatures(context.packageName, testPackage) == PackageManager.SIGNATURE_MATCH)
            @Suppress("DEPRECATION")
            val libraryDirectory = File(context.packageManager.getApplicationInfo(testPackage, 0).nativeLibraryDir).canonicalFile
            fun binary(name: String, hashKey: String): File {
                val expected = requireNotNull(intent.getStringExtra(hashKey))
                require(expected.matches(Regex("[a-f0-9]{64}")))
                val file = File(libraryDirectory, name)
                require(file.canonicalFile.parentFile == libraryDirectory && file.isFile && file.canExecute() && !file.canWrite())
                require(digest(file.readBytes()) == expected)
                return file.canonicalFile
            }
            val resolver = requireNotNull(intent.getStringExtra("resolver"))
            // V1 accepts only a literal IPv4 TCP resolver. No OS DNS lookup.
            require(resolver.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}:[0-9]{1,5}")))
            val address = resolver.substringBefore(':').split('.').map(String::toInt)
            require(address.all { it in 0..255 } && address.any { it != 0 } && address[0] !in 224..255)
            require(resolver.substringAfter(':').toInt() in 1..65535)
            val index = intent.getIntExtra("egressIndex", -1)
            require(index >= 0)
            return NativePreviewVpnInput(source, sourceDigest,
                binary("libxray_dns_preview.so", "previewSha256"),
                binary("libtun2socks_preview.so", "forwarderSha256"), resolver, index,
                intent.getBooleanExtra("includeBrowser", false))
        }
    }
}

/** Owns only one candidate's reservation and private files; source bytes are never rewritten. */
internal class NativePreviewVpnSpec private constructor(
    val input: NativePreviewVpnInput,
    val network: Network,
    val generation: NativePreviewNetworkGeneration,
    val epoch: String,
    val credentials: LocalProxyCredentials,
    val reservation: ServerSocket,
    val directory: File,
    val document: File,
    val policy: File,
    val forwarderConfig: File,
    val fdSocket: File,
) : Closeable {
    val socksPort = reservation.localPort
    private var sourceValidated = false

    fun arguments(command: String) = listOf(input.core.absolutePath, command,
        "--config", document.absolutePath, "--resolver", input.resolver,
        "--egress-index", input.egressIndex.toString(), "--capability", NativePreviewVpnInput.CAPABILITY,
        "--timeout-ms", "4000", "--private-policy", policy.absolutePath, "--policy-epoch", epoch)

    override fun close() {
        generation.revoke()
        var primary: Throwable? = null
        fun cleanup(action: () -> Unit) {
            try { action() } catch (error: Throwable) {
                if (primary == null) primary = error else primary!!.addSuppressed(error)
            }
        }
        cleanup { reservation.close() }
        cleanup {
            if (!sourceValidated) {
                check(document.readBytes().contentEquals(input.source)) { "Preview source bytes changed" }
                sourceValidated = true
            }
        }
        directory.listFiles().orEmpty().forEach { file -> cleanup { check(!file.exists() || file.delete()) { "Preview owned file cleanup failed" } } }
        cleanup { check(!directory.exists() || directory.delete()) { "Preview owned directory cleanup failed" } }
        primary?.let { throw it }
    }

    companion object {
        fun create(context: Context, input: NativePreviewVpnInput, network: Network): NativePreviewVpnSpec {
            val epoch = UUID.randomUUID().toString().replace("-", "")
            val directory = File(context.noBackupFilesDir, "native-vpn-${epoch.take(12)}")
            val fdSocket = File(directory, "tun-fd")
            require(fdSocket.absolutePath.toByteArray(Charsets.UTF_8).size <= 100) { "Preview socket path too long" }
            var reservation: ServerSocket? = null
            var created = false
            try {
                Os.mkdir(directory.absolutePath, 448) // 0700, created only by this owner.
                created = true
                fun privateFile(name: String, bytes: ByteArray): File {
                    val temporary = File(directory, "$name.partial")
                    check(temporary.createNewFile()); Os.chmod(temporary.absolutePath, 384)
                    temporary.outputStream().use { output -> output.write(bytes); output.fd.sync() }
                    check(Os.stat(temporary.absolutePath).st_uid == Process.myUid())
                    val file = File(directory, name)
                    Os.rename(temporary.absolutePath, file.absolutePath)
                    return file
                }
                val secret = LocalProxyCredentials.generate()
                reservation = ServerSocket(0, 1, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)))
                val document = privateFile("source.json", input.source)
                val policyBytes = JSONObject().put("schema", 1).put("capability", NativePreviewVpnInput.CAPABILITY)
                    .put("source_digest", input.sourceDigest).put("epoch", epoch)
                    .put("virtual_ipv4", NativePreviewVpnInput.VIRTUAL_DNS)
                    .put("listen", "127.0.0.1:${reservation.localPort}")
                    .put("username", secret.username).put("password", secret.password)
                    .toString().toByteArray(Charsets.UTF_8)
                val policy = privateFile("policy.json", policyBytes)
                val yaml = "proxy: 'socks5://${secret.username}:${secret.password}@127.0.0.1:${reservation.localPort}'\nmtu: 1500\nloglevel: error\n"
                val forwarder = privateFile("forwarder.yaml", yaml.toByteArray(Charsets.UTF_8))
                return NativePreviewVpnSpec(input, network, NativePreviewNetworkGeneration(), epoch, secret,
                    reservation, directory, document, policy, forwarder, fdSocket)
            } catch (error: Throwable) {
                runCatching { reservation?.close() }
                if (created) {
                    directory.listFiles().orEmpty().forEach { runCatching { it.delete() } }
                    runCatching { directory.delete() }
                }
                throw error
            }
        }
    }
}
