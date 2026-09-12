package com.github.tfox.flutter_vless.xray.core

import java.io.File
import java.nio.file.Files
import org.junit.Assert.*
import org.junit.Test

class XrayDiagnosticsStoreTest {
    @Test fun untrustedNativeOutputNeverEntersSnapshotOrFileAndLegacyFilesAreRemoved() = withDirectory { directory ->
        val secret = "password=canary-secret socks5://user:password@198.51.100.3 secret.example https://subscription.example/token\u001b\r\n"
        listOf("flutter_vless_xray_debug.log", "access.log", "error.log").forEach { File(directory, it).writeText(secret) }
        val other = File(directory, "user-document.txt").apply { writeText(secret) }
        assertEquals("", XrayDiagnosticsStore.snapshot(directory))
        val generation = XrayDiagnosticsStore.reset(directory)
        XrayDiagnosticsStore.append(directory, secret, secret, generation)
        XrayDiagnosticsStore.event(directory, XrayDiagnosticsStore.Event.RECOVERING, generation, 3)
        val snapshot = XrayDiagnosticsStore.snapshot(directory)
        assertEquals("OUTPUT_DISCARDED\nRECOVERING value=3", snapshot)
        assertTrue(other.exists())
        for (file in directory.listFiles()!!.filter { it != other }) assertFalse(file.readText().contains("canary-secret"))
        assertFalse(File(directory, "flutter_vless_xray_debug.log").exists())
    }
    @Test fun boundedEventsRejectStaleWritersAndRetainUsefulFailureNumbers() = withDirectory { directory ->
        val old = XrayDiagnosticsStore.reset(directory)
        val current = XrayDiagnosticsStore.reset(directory)
        XrayDiagnosticsStore.event(directory, XrayDiagnosticsStore.Event.SESSION_START, old)
        repeat(12000) { XrayDiagnosticsStore.event(directory, XrayDiagnosticsStore.Event.RECOVERING, current, it.toLong()) }
        val snapshot = XrayDiagnosticsStore.snapshot(directory)
        assertFalse(snapshot.contains("SESSION_START"))
        assertTrue(snapshot.endsWith("RECOVERING value=11999"))
        assertTrue(snapshot.toByteArray().size < 40 * 1024)
        assertTrue(File(directory, "flutter_vless_events_v2.log").length() <= 128 * 1024)
    }
    @Test fun readTailDiscardsPartialFirstLineAndBoundsLineCount() = withDirectory { directory ->
        val file = File(directory, "tail.log").apply { writeText("first-line\nsecond-line\nthird-line\n") }
        assertEquals("third-line", XrayDiagnosticsStore.readTail(file, 25, 1))
    }
    private fun withDirectory(block: (File) -> Unit) {
        val directory = Files.createTempDirectory("flutter-vless-events").toFile()
        try { block(directory) } finally { directory.deleteRecursively() }
    }
}
