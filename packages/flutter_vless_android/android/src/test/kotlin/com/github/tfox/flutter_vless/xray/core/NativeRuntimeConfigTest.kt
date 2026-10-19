package com.github.tfox.flutter_vless.xray.core

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.util.concurrent.TimeUnit

/** Inert Process objects only; the launcher callback never invokes a child. */
class NativeRuntimeConfigTest {
    private class Child(val code: Int = 0, val hang: Boolean = false, val refusesKill: Boolean = false) : Process() {
        var now = 0L
        var alive = hang
        var forced = false
        val input = ByteArrayInputStream(byteArrayOf())
        val output = ByteArrayOutputStream()
        override fun getInputStream() = input
        override fun getOutputStream() = output
        override fun getErrorStream() = ByteArrayInputStream(byteArrayOf())
        override fun isAlive() = alive
        override fun waitFor(): Int = throw AssertionError("Unbounded wait forbidden")
        override fun waitFor(timeout: Long, unit: TimeUnit): Boolean { now += unit.toNanos(timeout); return !alive }
        override fun exitValue(): Int { check(!alive); return code }
        override fun destroy() { forced = true; if (!refusesKill) alive = false }
        override fun destroyForcibly(): Process { destroy(); return this }
    }

    @Test fun parserAndStartupFilesReceiveTheSameImmutableFinalBytes() {
        val directory = Files.createTempDirectory("native-preflight-exact").toFile()
        val json = JSONObject("""{"outbounds":[{"protocol":"freedom"}],"remarks":"frozen"}""")
        val snapshot = NativeRuntimeConfig.freeze(json); val expected = snapshot.bytes; var checked = byteArrayOf()
        try {
            assertTrue(snapshot.preflight(directory, launch = { file -> checked = file.readBytes(); Child() }))
            assertEquals(0, directory.listFiles()!!.size)
            json.put("remarks", "mutated"); snapshot.bytes[0] = 0
            val started = directory.resolve("runtime.json"); snapshot.writeTo(started)
            assertArrayEquals(expected, checked); assertArrayEquals(checked, started.readBytes())
        } finally { directory.deleteRecursively() }
    }

    @Test fun nativeParserRejectionAndLaunchFailureRemoveOnlyTheirOwnInputs() {
        val directory = Files.createTempDirectory("native-preflight-refusal").toFile()
        val unknown = directory.resolve("caller-file").apply { writeText("untouched") }
        try {
            val snapshot = NativeRuntimeConfig.freeze(JSONObject())
            assertFalse(snapshot.preflight(directory, launch = { Child(code = 3) }))
            assertFalse(snapshot.preflight(directory, launch = { throw IllegalStateException("Synthetic launch failure") }))
            assertEquals(listOf(unknown.name), directory.listFiles()!!.map { it.name })
        } finally { directory.deleteRecursively() }
    }

    @Test fun hungParserIsKilledAndReapedBeforeItsInputIsDeleted() {
        val directory = Files.createTempDirectory("native-preflight-hang").toFile(); val child = Child(hang = true)
        try {
            assertFalse(NativeRuntimeConfig.freeze(JSONObject()).preflight(directory, { child }, 100, { child.now }))
            assertTrue(child.forced); assertFalse(child.alive); assertEquals(0, directory.listFiles()!!.size)
            assertTrue(child.now <= TimeUnit.MILLISECONDS.toNanos(101))
        } finally { directory.deleteRecursively() }
    }

    @Test fun unreapedParserRefusesSuccessAndRetainsItsStillReferencedInput() {
        val directory = Files.createTempDirectory("native-preflight-unreaped").toFile(); val child = Child(hang = true, refusesKill = true)
        try {
            assertFalse(NativeRuntimeConfig.freeze(JSONObject()).preflight(directory, { child }, 100, { child.now }))
            assertTrue(child.forced); assertTrue(child.alive); assertEquals(1, directory.listFiles()!!.size)
            assertTrue(child.now <= TimeUnit.MILLISECONDS.toNanos(600))
        } finally { directory.deleteRecursively() }
    }
}
