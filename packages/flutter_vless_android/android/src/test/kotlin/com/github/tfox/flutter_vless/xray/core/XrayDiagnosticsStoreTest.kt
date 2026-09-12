package com.github.tfox.flutter_vless.xray.core

import java.io.File
import java.nio.file.Files
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class XrayDiagnosticsStoreTest {
    @Test
    fun snapshot_combinesCrossProcessOutputAndXrayFileLogs() {
        withTempDirectory { directory ->
            XrayDiagnosticsStore.reset(directory)
            XrayDiagnosticsStore.append(directory, "xray", "core started\ntransport ready")
            XrayDiagnosticsStore.append(directory, "tun2socks", "TUN fd received")
            File(directory, "access.log").writeText("accepted tcp:example.com:443")
            File(directory, "error.log").writeText("warning: retrying")

            val snapshot = XrayDiagnosticsStore.snapshot(directory)

            assertTrue(snapshot.contains("[xray] core started"))
            assertTrue(snapshot.contains("[tun2socks] TUN fd received"))
            assertTrue(snapshot.contains("accepted tcp:example.com:443"))
            assertTrue(snapshot.contains("warning: retrying"))
        }
    }

    @Test
    fun append_rotatesDiagnosticsAndKeepsNewestMessages() {
        withTempDirectory { directory ->
            XrayDiagnosticsStore.reset(directory)
            repeat(80) { index ->
                XrayDiagnosticsStore.append(
                    directory,
                    "xray",
                    "message-$index ${"x".repeat(4096)}"
                )
            }
            File(directory, "access.log").writeText(
                List(2000) { index -> "access-$index ${"a".repeat(40)}" }.joinToString("\n")
            )
            File(directory, "error.log").writeText(
                List(2000) { index -> "error-$index ${"e".repeat(40)}" }.joinToString("\n")
            )

            val snapshot = XrayDiagnosticsStore.snapshot(directory)

            assertTrue(snapshot.contains("message-79"))
            assertFalse(snapshot.contains("message-0 "))
            assertTrue(snapshot.contains("access-1999"))
            assertTrue(snapshot.contains("error-1999"))
            assertTrue(snapshot.toByteArray().size < 64 * 1024)
        }
    }

    @Test
    fun readTail_discardsPartialFirstLineAndBoundsLineCount() {
        withTempDirectory { directory ->
            val file = File(directory, "tail.log")
            file.writeText("first-line\nsecond-line\nthird-line\n")

            val tail = XrayDiagnosticsStore.readTail(
                file,
                maxBytes = 25,
                maxLines = 1
            )

            assertTrue(tail == "third-line")
        }
    }

    @Test
    fun append_rejectsStaleGenerationAfterFastRestart() {
        withTempDirectory { directory ->
            val firstGeneration = XrayDiagnosticsStore.reset(directory)
            XrayDiagnosticsStore.append(directory, "xray", "first session", firstGeneration)
            val secondGeneration = XrayDiagnosticsStore.reset(directory)
            XrayDiagnosticsStore.append(directory, "xray", "second session", secondGeneration)
            XrayDiagnosticsStore.append(directory, "xray", "stale output", firstGeneration)

            val snapshot = XrayDiagnosticsStore.snapshot(directory)

            assertTrue(snapshot.contains("second session"))
            assertFalse(snapshot.contains("first session"))
            assertFalse(snapshot.contains("stale output"))
        }
    }

    @Test
    fun append_boundsLongUnicodeWithoutReplacementCharacters() {
        withTempDirectory { directory ->
            val generation = XrayDiagnosticsStore.reset(directory)
            XrayDiagnosticsStore.append(
                directory,
                "xray",
                "🛰️".repeat(40_000),
                generation
            )

            val snapshot = XrayDiagnosticsStore.snapshot(directory)

            assertTrue(snapshot.toByteArray().size < 64 * 1024)
            assertFalse(snapshot.contains("�"))
        }
    }

    private fun withTempDirectory(block: (File) -> Unit) {
        val directory = Files.createTempDirectory("flutter-vless-logs-").toFile()
        try {
            block(directory)
        } finally {
            directory.deleteRecursively()
        }
    }
}
