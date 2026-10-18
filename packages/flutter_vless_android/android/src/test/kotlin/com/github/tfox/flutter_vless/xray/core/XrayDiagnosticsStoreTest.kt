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
    @Test fun delayStagesAndExitCodesRemainContentFreeAndRespectDisabledCollection() = withDirectory { directory ->
        val events = listOf(XrayDiagnosticsStore.Event.DELAY_ALLOCATING_PORTS,
            XrayDiagnosticsStore.Event.DELAY_PORTS_RESERVED, XrayDiagnosticsStore.Event.DELAY_CONFIG_READY,
            XrayDiagnosticsStore.Event.DELAY_CORE_STARTED, XrayDiagnosticsStore.Event.DELAY_MEASURING,
            XrayDiagnosticsStore.Event.DELAY_PROBE_FAILED, XrayDiagnosticsStore.Event.DELAY_CORE_EXIT,
            XrayDiagnosticsStore.Event.DELAY_COMPLETE, XrayDiagnosticsStore.Event.DELAY_FAILED,
            XrayDiagnosticsStore.Event.DELAY_CLEANUP_FAILED)
        XrayDiagnosticsStore.reset(directory)
        for (event in events) XrayDiagnosticsStore.event(directory, event, value = -7)
        val canary = "socks5://private-user:private-password@secret.example/config"
        XrayDiagnosticsStore.append(directory, canary, canary)
        File(directory, "flutter_vless_events_v2.log").appendText("DELAY_FAILED $canary\n")
        val snapshot = XrayDiagnosticsStore.snapshot(directory)
        assertEquals(events.map { "${it.name} value=-7" } + "OUTPUT_DISCARDED", snapshot.lines())
        assertFalse(snapshot.contains("private-password"))
        XrayDiagnosticsStore.configure(directory, com.github.tfox.flutter_vless.xray.service.NativeVlessOptions.Diagnostics(enabled = false))
        XrayDiagnosticsStore.event(directory, XrayDiagnosticsStore.Event.DELAY_CORE_EXIT, value = 9)
        assertEquals("", XrayDiagnosticsStore.snapshot(directory))
    }
    @Test fun readTailDiscardsPartialFirstLineAndBoundsLineCount() = withDirectory { directory ->
        val file = File(directory, "tail.log").apply { writeText("first-line\nsecond-line\nthird-line\n") }
        assertEquals("third-line", XrayDiagnosticsStore.readTail(file, 25, 1))
    }
    @Test fun optionsDisableEraseAndBoundCollectionWithoutEnablingRawOutput() = withDirectory { directory ->
        val small = com.github.tfox.flutter_vless.xray.service.NativeVlessOptions.Diagnostics(true,4096,3)
        XrayDiagnosticsStore.configure(directory,small)
        repeat(1000) { XrayDiagnosticsStore.event(directory,XrayDiagnosticsStore.Event.RECOVERING,value=it.toLong()) }
        assertEquals(3,XrayDiagnosticsStore.snapshot(directory).lines().size)
        assertTrue(File(directory,"flutter_vless_events_v2.log").length()<=4096)
        XrayDiagnosticsStore.configure(directory,small.copy(enabled=false))
        XrayDiagnosticsStore.event(directory,XrayDiagnosticsStore.Event.CONNECTED)
        assertEquals("",XrayDiagnosticsStore.snapshot(directory))
        assertEquals(0L,File(directory,"flutter_vless_events_v2.log").length())
        XrayDiagnosticsStore.configure(directory,small)
        assertEquals("",XrayDiagnosticsStore.snapshot(directory))
        File(directory,"flutter_vless_diagnostics_policy_v1.txt").writeText("corrupt")
        XrayDiagnosticsStore.event(directory,XrayDiagnosticsStore.Event.CONNECTED)
        assertEquals("",XrayDiagnosticsStore.snapshot(directory))
    }
    private fun withDirectory(block: (File) -> Unit) {
        val directory = Files.createTempDirectory("flutter-vless-events").toFile()
        try { block(directory) } finally { directory.deleteRecursively() }
    }
}
