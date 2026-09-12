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
}
