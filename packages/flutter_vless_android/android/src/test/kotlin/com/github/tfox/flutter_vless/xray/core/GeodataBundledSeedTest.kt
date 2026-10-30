package com.github.tfox.flutter_vless.xray.core

import android.content.Context
import android.content.res.AssetManager
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import com.github.tfox.flutter_vless.xray.utils.Utilities
import org.junit.Assert.*
import org.junit.Test
import org.mockito.Mockito.*
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.Paths

class GeodataBundledSeedTest {
    private fun context(root: java.io.File, source: () -> InputStream): Context {
        val assets=mock(AssetManager::class.java)
        `when`(assets.list("")).thenReturn(arrayOf("geoip.dat"))
        `when`(assets.open("geoip.dat")).thenAnswer { source() }
        val context=mock(Context::class.java)
        `when`(context.assets).thenReturn(assets)
        `when`(context.filesDir).thenReturn(root)
        return context
    }
    // Resource access is synthetic; publication uses the real host hard-link
    // syscall, matching Android Os.link create-only/EEXIST semantics.
    private fun withLink(body: () -> Unit) {
        mockStatic(Os::class.java).use { mocked ->
            mocked.`when`<Unit> { Os.link(anyString(),anyString()) }.thenAnswer { call ->
                try { Files.createLink(Paths.get(call.getArgument<String>(1)),Paths.get(call.getArgument<String>(0))) }
                catch (_: FileAlreadyExistsException) { throw ErrnoException("link",OsConstants.EEXIST) }
                null
            }
            body()
        }
    }
    @Test fun recoveryCannotOverwriteAnUpdatedFullDat() {
        val root=Files.createTempDirectory("geodat-seed-").toFile()
        try {
            val file=root.resolve("geoip.dat").apply { writeText("updated-full-data") }
            Utilities.copyAssets(context(root) { throw AssertionError("Existing data must not reopen the bundle") })
            assertEquals("updated-full-data",file.readText())
        } finally { root.deleteRecursively() }
    }
    @Test fun partialReadFailureLeavesNeitherFinalFileNorOwnedStage() = withLink {
        val root=Files.createTempDirectory("geodat-seed-").toFile()
        try {
            val stream=object: InputStream() {
                var first=true
                override fun read(): Int = throw IOException("synthetic")
                override fun read(bytes: ByteArray,offset: Int,count: Int): Int {
                    if (first) { first=false;bytes[offset]=1;return 1 }
                    throw IOException("synthetic")
                }
            }
            assertThrows(IOException::class.java) { Utilities.copyAssets(context(root) { stream }) }
            assertTrue(root.list()!!.isEmpty())
        } finally { root.deleteRecursively() }
    }
    @Test fun finalFileBecomesVisibleOnlyAfterCompleteCopy() = withLink {
        val root=Files.createTempDirectory("geodat-seed-").toFile()
        try {
            val target=root.resolve("geoip.dat")
            val bytes="complete-bundle".toByteArray()
            val stream=object: ByteArrayInputStream(bytes) {
                override fun read(buffer: ByteArray,offset: Int,count: Int): Int {
                    assertFalse(target.exists())
                    return super.read(buffer,offset,count)
                }
            }
            Utilities.copyAssets(context(root) { stream })
            assertArrayEquals(bytes,target.readBytes())
            assertEquals(listOf("geoip.dat"),root.list()!!.toList())
        } finally { root.deleteRecursively() }
    }
}
