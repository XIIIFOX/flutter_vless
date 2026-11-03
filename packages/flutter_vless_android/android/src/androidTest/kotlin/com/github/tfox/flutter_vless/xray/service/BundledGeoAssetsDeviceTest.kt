package com.github.tfox.flutter_vless.xray.service

import android.content.Context
import android.content.ContextWrapper
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.github.tfox.flutter_vless.xray.utils.Utilities
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Uses the actual app sandbox and APK assets, never shell/run-as permissions. */
@RunWith(AndroidJUnit4::class)
class BundledGeoAssetsDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val names = listOf("geoip.dat", "geosite.dat")

    private fun digest(input: InputStream): ByteArray = input.use {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(8192)
        while (true) {
            val count = it.read(buffer)
            if (count < 0) break
            digest.update(buffer, 0, count)
        }
        digest.digest()
    }

    private fun inFreshDirectory(test: (Context, File) -> Unit) {
        val domain = File("/proc/self/attr/current").readText()
        assertTrue("Must execute in the application sandbox, not run-as: $domain", domain.contains(":untrusted_app"))
        val directory = File(context.cacheDir, "bundled-geodata-${System.nanoTime()}")
        assertTrue(directory.mkdir())
        try {
            test(object : ContextWrapper(context) {
                override fun getFilesDir(): File = directory
            }, directory)
        } finally {
            assertTrue("Remove only this test's private files", directory.deleteRecursively())
        }
    }

    @Test fun freshInstallSeedsCompleteReadableAssetsInTheActualAppSandbox() = inFreshDirectory { wrapped, directory ->
        val bundled = context.assets.list("")!!.toSet()
        assertTrue(bundled.containsAll(names))
        Utilities.copyAssets(wrapped)
        for (name in names) {
            val target = File(directory, name)
            assertTrue("Fresh bundled asset is readable: $name", target.isFile && target.canRead())
            assertTrue("Publish without forbidden hard links", java.nio.file.Files.isSymbolicLink(target.toPath()))
            assertArrayEquals("Complete APK asset bytes: $name", digest(context.assets.open(name)), digest(target.inputStream()))
        }
        val files = directory.list()!!.toSet()
        Utilities.copyAssets(wrapped)
        assertEquals("Repeated preparation does not create more backing files", files, directory.list()!!.toSet())
    }

    @Test fun callerUpdatedAssetsRemainAuthoritativeInTheActualAppSandbox() = inFreshDirectory { wrapped, directory ->
        val caller = "caller-owned-asset".toByteArray()
        for (name in names) File(directory, name).writeBytes(caller)
        Utilities.copyAssets(wrapped)
        assertEquals(names.toSet(), directory.list()!!.toSet())
        for (name in names) assertArrayEquals(caller, File(directory, name).readBytes())
    }
}
