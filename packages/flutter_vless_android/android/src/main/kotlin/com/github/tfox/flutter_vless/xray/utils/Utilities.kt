package com.github.tfox.flutter_vless.xray.utils

import android.content.Context
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

object Utilities {

    internal fun configureXrayAssets(environment: MutableMap<String, String>, defaultDirectory: File,
        requestedDirectory: String?, copyBundled: () -> Unit): File {
        val selected = validateAssetsDirectory(requestedDirectory) ?: defaultDirectory
        if (requestedDirectory == null) {
            if (!selected.exists()) selected.mkdirs()
            copyBundled()
        }
        // Core checks the exact dotted name before its uppercase alias.
        // Keep both bound to this child, without touching certificate roots.
        environment["xray.location.asset"] = selected.absolutePath
        environment["XRAY_LOCATION_ASSET"] = selected.absolutePath
        return selected
    }

    internal fun validateAssetsDirectory(requestedDirectory: String?): File? = requestedDirectory?.let {
        File(it).also { directory ->
            require(directory.isAbsolute && directory.isDirectory) { "Geo asset directory must be an existing absolute directory" }
        }
    }

    internal fun configureXrayAssets(context: Context, environment: MutableMap<String, String>, requestedDirectory: String?) =
        configureXrayAssets(environment, context.filesDir, requestedDirectory) { copyAssets(context) }

    fun getUserAssetsPath(context: Context): String {
        val dir = context.filesDir
        if (!dir.exists()) {
            dir.mkdirs()
        }
        return dir.absolutePath
    }

    fun copyAssets(context: Context) {
        val assets = context.assets
        val files = assets.list("") ?: return
        for (filename in files) {
            if (filename == "geoip.dat" || filename == "geosite.dat") {
                var `in`: InputStream? = null
                var out: OutputStream? = null
                try {
                    `in` = assets.open(filename)
                    val outFile = File(getUserAssetsPath(context), filename)
                    out = FileOutputStream(outFile)
                    copyFile(`in`, out)
                } catch (e: IOException) {
                    e.printStackTrace()
                } finally {
                    if (`in` != null) {
                        try {
                            `in`.close()
                        } catch (e: IOException) {
                            e.printStackTrace()
                        }
                    }
                    if (out != null) {
                        try {
                            out.close()
                        } catch (e: IOException) {
                            e.printStackTrace()
                        }
                    }
                }
            }
        }
    }

    @Throws(IOException::class)
    private fun copyFile(`in`: InputStream, out: OutputStream) {
        val buffer = ByteArray(1024)
        var read: Int
        while (`in`.read(buffer).also { read = it } != -1) {
            out.write(buffer, 0, read)
        }
    }
}
