package com.github.tfox.flutter_vless.xray.utils

import android.content.Context
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

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

    /** Seed missing bundled data once. Scheduled/caller updates always win.
     *
     * Android's app sandbox forbids hard links. Publish a create-only symlink
     * to a complete private backing file instead: readers never observe a
     * partial copy, and a concurrently installed caller/Core DAT is retained.
     * The backing file remains owned application data after publication. Core
     * reads it normally and its atomic updater replaces the symlink itself.
     */
    @Throws(IOException::class)
    fun copyAssets(context: Context) {
        val assets = context.assets
        val files = assets.list("") ?: return
        for (filename in files) {
            if (filename != "geoip.dat" && filename != "geosite.dat") continue
            val target = File(getUserAssetsPath(context), filename)
            if (target.exists()) continue
            val staged = File.createTempFile(".flutter-vless-geodat-bundle-", ".dat", target.parentFile)
            var published = false
            try {
                assets.open(filename).use { input ->
                    FileOutputStream(staged).use { output ->
                        input.copyTo(output)
                        output.fd.sync()
                    }
                }
                try {
                    // Both paths are in the same app-private directory. A
                    // relative symlink also survives relocation of app data.
                    // symlink() is atomic/create-only; rename() could replace
                    // data committed concurrently by Core's scheduler.
                    android.system.Os.symlink(staged.name, target.absolutePath)
                    published = true
                } catch (error: android.system.ErrnoException) {
                    if (error.errno != android.system.OsConstants.EEXIST) {
                        throw IOException("Cannot publish bundled GeoDAT asset")
                    }
                }
            } catch (_: IOException) {
                throw IOException("Cannot prepare bundled GeoDAT asset")
            } finally {
                if (!published && staged.exists() && !staged.delete()) {
                    throw IOException("Cannot clean bundled GeoDAT staging file")
                }
            }
        }
    }
}
