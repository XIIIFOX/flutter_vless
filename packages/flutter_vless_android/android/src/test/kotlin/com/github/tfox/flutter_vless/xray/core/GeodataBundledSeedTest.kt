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
    // The mockable Android jar may zero both constants and constructor fields.
    // Set errno explicitly and choose a fatal value distinct from EEXIST so
    // publication denial cannot accidentally exercise the harmless race case.
    private val deniedErrno: Int
        get() = if (OsConstants.EACCES != OsConstants.EEXIST) OsConstants.EACCES else -1

    private fun errnoFailure(operation: String, errno: Int): ErrnoException =
        ErrnoException(operation, errno).also {
            ErrnoException::class.java.getDeclaredField("errno").setInt(it, errno)
        }

    private fun context(root: java.io.File, source: () -> InputStream): Context {
        val assets=mock(AssetManager::class.java)
        `when`(assets.list("")).thenReturn(arrayOf("geoip.dat"))
        `when`(assets.open("geoip.dat")).thenAnswer { source() }
        val context=mock(Context::class.java)
        `when`(context.assets).thenReturn(assets)
        `when`(context.filesDir).thenReturn(root)
        return context
    }
    // Resource access is synthetic; publication uses real host symlinks.
    // Hard links deliberately fail as they do in Android's app SELinux domain.
    // A run-as/shell UID alone does not reproduce that domain restriction.
    private fun withSymlink(body: () -> Unit) {
        mockStatic(Os::class.java).use { mocked ->
            mocked.`when`<Unit> { Os.link(anyString(),anyString()) }.thenThrow(errnoFailure("link",deniedErrno))
            mocked.`when`<Unit> { Os.symlink(anyString(),anyString()) }.thenAnswer { call ->
                try { Files.createSymbolicLink(Paths.get(call.getArgument<String>(1)),Paths.get(call.getArgument<String>(0))) }
                catch (_: FileAlreadyExistsException) { throw errnoFailure("symlink",OsConstants.EEXIST) }
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
    @Test fun partialReadFailureLeavesNeitherFinalFileNorOwnedStage() = withSymlink {
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
    @Test fun finalFileBecomesVisibleOnlyAfterCompleteCopyWithHardLinksDenied() = withSymlink {
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
            assertTrue(Files.isSymbolicLink(target.toPath()))
            val backing=Files.readSymbolicLink(target.toPath())
            assertFalse(backing.isAbsolute)
            assertArrayEquals(bytes,root.resolve(backing.toString()).readBytes())
            assertEquals(2,root.list()!!.size)
        } finally { root.deleteRecursively() }
    }

    @Test fun updatePublishedDuringCopyWinsAndUnusedBackingIsRemoved() = withSymlink {
        val root=Files.createTempDirectory("geodat-seed-").toFile()
        try {
            val target=root.resolve("geoip.dat")
            val stream=object: ByteArrayInputStream("bundle".toByteArray()) {
                override fun close() {
                    target.writeText("concurrently-updated-data")
                    super.close()
                }
            }
            Utilities.copyAssets(context(root) { stream })
            assertEquals("concurrently-updated-data",target.readText())
            assertFalse(Files.isSymbolicLink(target.toPath()))
            assertEquals(listOf("geoip.dat"),root.list()!!.toList())
        } finally { root.deleteRecursively() }
    }

    @Test fun atomicCoreReplacementAndRollbackKeepCompleteData() = withSymlink {
        val root=Files.createTempDirectory("geodat-seed-").toFile()
        try {
            val target=root.resolve("geoip.dat")
            Utilities.copyAssets(context(root) { ByteArrayInputStream("bundle".toByteArray()) })
            val backup=root.resolve("update.bak")
            assertTrue(target.renameTo(backup))
            val update=root.resolve("update.tmp").apply { writeText("updated-data") }
            assertTrue(update.renameTo(target))
            Utilities.copyAssets(context(root) { throw AssertionError("Updated data must not reopen bundle") })
            assertEquals("updated-data",target.readText())
            assertTrue(target.delete())
            assertTrue(backup.renameTo(target))
            assertTrue(Files.isSymbolicLink(target.toPath()))
            assertEquals("bundle",target.readText())
        } finally { root.deleteRecursively() }
    }

    @Test fun failedPublicationLeavesNoTargetOrBackingFile() {
        val root=Files.createTempDirectory("geodat-seed-").toFile()
        try {
            mockStatic(Os::class.java).use { mocked ->
                val failure=errnoFailure("symlink",deniedErrno)
                assertNotEquals(OsConstants.EEXIST,failure.errno)
                mocked.`when`<Unit> { Os.symlink(anyString(),anyString()) }.thenThrow(failure)
                assertThrows(IOException::class.java) {
                    Utilities.copyAssets(context(root) { ByteArrayInputStream("bundle".toByteArray()) })
                }
            }
            assertTrue(root.list()!!.isEmpty())
        } finally { root.deleteRecursively() }
    }
}
