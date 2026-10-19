package com.github.tfox.flutter_vless.xray.service

import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.nio.file.Files

class SessionRuntimeFilesTest {
    @Test fun cleanupRemovesOnlyKnownAbandonedServiceFilesAndPreservesLiveAndDelayFiles() {
        val root = Files.createTempDirectory("flutter-vless-runtime-files").toFile()
        try {
            val id = "11111111-2222-4333-8444-555555555555"
            val abandoned = File(root, "xray-$id.json").apply { writeText("secret-canary") }
            val abandonedValidation = File(root, "validate-$id.json").apply { writeText("validation-canary") }
            val liveValidation = File(root, "validate-22222222-2222-4333-8444-555555555555.json").apply { writeText("live-validation") }
            val live = File(root, "tun-$id.yaml").apply { writeText("live-canary") }
            val delay = File(root, "delay-$id.json").apply { writeText("standalone-client") }
            val user = File(root, "user-profile.json").apply { writeText("user-data") }
            SessionRuntimeFiles.cleanup(root, setOf(live.absolutePath, liveValidation.absolutePath))
            assertFalse(abandoned.exists()); assertTrue(live.exists()); assertTrue(delay.exists()); assertTrue(user.exists())
            assertFalse(abandonedValidation.exists()); assertTrue(liveValidation.exists())
            SessionRuntimeFiles.cleanup(root, emptySet())
            assertFalse(live.exists()); assertTrue(delay.exists()); assertTrue(user.exists())
            assertFalse(liveValidation.exists())
        } finally { root.deleteRecursively() }
    }
    @Test fun routingSidecarsAreRemovedOnlyAfterTheirOwnedChildPathsAreNoLongerActive() {
        val root=Files.createTempDirectory("routing-sidecar-cleanup").toFile()
        try {
            val id="11111111-2222-4333-8444-555555555555"
            val config=root.resolve("xray-$id.json").apply { writeText("private") }
            val spec=root.resolve("xray-$id.spec.json").apply { writeText("private") }
            val caller=root.resolve("caller.spec.json").apply { writeText("caller") }
            SessionRuntimeFiles.cleanup(root,setOf(config.absolutePath,spec.absolutePath))
            assertTrue(config.exists()); assertTrue(spec.exists()); assertTrue(caller.exists())
            SessionRuntimeFiles.cleanup(root,emptySet())
            assertFalse(config.exists()); assertFalse(spec.exists()); assertTrue(caller.exists())
        } finally { root.deleteRecursively() }
    }
}
