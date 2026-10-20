package com.github.tfox.flutter_vless.xray.service

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.google.gson.Gson
import java.io.File
import java.io.RandomAccessFile
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Only an explicitly accepted START arms restart. STOP removes the encrypted authorization. */
internal class AuthorizedProfileStore(context: Context, private val kind: Kind = Kind.AUTHORIZED) {
    enum class Kind(val fileName: String, val alias: String) {
        AUTHORIZED("flutter_vless_authorized_v1.bin", "flutter_vless.authorized-profile.v1"),
        QUICK_ACCESS("flutter_vless_quick_access_v1.bin", "flutter_vless.quick-access-profile.v1")
    }
    private val file = AtomicFile(File(context.noBackupFilesDir, kind.fileName))
    private val lockFile = File(context.noBackupFilesDir, kind.fileName + ".lock")
    private fun <T> locked(body: () -> T): T = synchronized(storageLock) {
        lockFile.parentFile?.mkdirs()
        RandomAccessFile(lockFile,"rw").use { lock -> lock.channel.lock().use { body() } }
    }
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(kind.alias, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(kind.alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true).build())
        }.generateKey()
    }
    fun save(config: XrayConfig) = locked {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(kind.alias.toByteArray())
        val plaintext = Gson().toJson(config).toByteArray(Charsets.UTF_8)
        require(plaintext.size <= MAX_ENCRYPTED_BYTES - 30) { "Authorized profile is too large" }
        val data = byteArrayOf(1, cipher.iv.size.toByte()) + cipher.iv + cipher.doFinal(plaintext)
        val output = file.startWrite()
        try { output.write(data); file.finishWrite(output) }
        catch (error: Exception) { file.failWrite(output); throw error }
    }
    fun revision(): String? = locked {
        if (!file.baseFile.isFile) null else digest(readEncrypted())
    }
    fun load(): XrayConfig = loadVersioned().first
    fun loadVersioned(): Pair<XrayConfig, String> = locked {
        val data = readEncrypted()
        decode(data) to digest(data)
    }
    private fun readEncrypted(): ByteArray {

        val data = file.openRead().use { input ->
            require(input.channel.size() in 30..MAX_ENCRYPTED_BYTES.toLong()) { "Authorized profile unavailable" }
            input.readBytes()
        }
        return data
    }
    private fun decode(data: ByteArray): XrayConfig {
        require(data.size in 30..MAX_ENCRYPTED_BYTES && data[0].toInt() == 1 && data[1].toInt() == 12) { "Authorized profile unavailable" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, data.copyOfRange(2, 14)))
        cipher.updateAAD(kind.alias.toByteArray())
        return Gson().fromJson(cipher.doFinal(data.copyOfRange(14, data.size)).toString(Charsets.UTF_8), XrayConfig::class.java)
            ?: error("Authorized profile unavailable")
    }
    private fun digest(data: ByteArray) = MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }
    fun disarm() = locked { file.delete() }
    fun exists(): Boolean = locked { file.baseFile.isFile }
    private companion object {
        val storageLock = Any()
        const val MAX_ENCRYPTED_BYTES = 4 * 1024 * 1024
    }
}
