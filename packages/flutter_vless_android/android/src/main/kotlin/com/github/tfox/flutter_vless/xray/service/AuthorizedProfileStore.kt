package com.github.tfox.flutter_vless.xray.service

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.google.gson.Gson
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Only an explicitly accepted START arms restart. STOP removes the encrypted authorization. */
internal class AuthorizedProfileStore(context: Context) {
    private val file = AtomicFile(File(context.noBackupFilesDir, "flutter_vless_authorized_v1.bin"))
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true).build())
        }.generateKey()
    }
    fun save(config: XrayConfig) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(ALIAS.toByteArray())
        val plaintext = Gson().toJson(config).toByteArray(Charsets.UTF_8)
        require(plaintext.size <= MAX_ENCRYPTED_BYTES - 30) { "Authorized profile is too large" }
        val data = byteArrayOf(1, cipher.iv.size.toByte()) + cipher.iv + cipher.doFinal(plaintext)
        val output = file.startWrite()
        try { output.write(data); file.finishWrite(output) }
        catch (error: Exception) { file.failWrite(output); throw error }
    }
    fun load(): XrayConfig {
        val data = file.openRead().use { input ->
            require(input.channel.size() in 30..MAX_ENCRYPTED_BYTES.toLong()) { "Authorized profile unavailable" }
            input.readBytes()
        }
        require(data.size in 30..MAX_ENCRYPTED_BYTES && data[0].toInt() == 1 && data[1].toInt() == 12) { "Authorized profile unavailable" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, data.copyOfRange(2, 14)))
        cipher.updateAAD(ALIAS.toByteArray())
        return Gson().fromJson(cipher.doFinal(data.copyOfRange(14, data.size)).toString(Charsets.UTF_8), XrayConfig::class.java)
            ?: error("Authorized profile unavailable")
    }
    fun disarm() = file.delete()
    private companion object {
        const val ALIAS = "flutter_vless.authorized-profile.v1"
        const val MAX_ENCRYPTED_BYTES = 4 * 1024 * 1024
    }
}
