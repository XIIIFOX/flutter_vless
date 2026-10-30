package com.github.tfox.flutter_vless.xray.core

import org.junit.Assert.*
import org.junit.Assume.assumeFalse
import org.junit.Test
import java.io.File
import java.nio.file.Files

class XrayGeodataAssetsTest {
    private val active = """{"geodata":{"cron":"@daily","assets":[{"url":"https://example.test/custom.dat","file":"nested/custom.DAT"}]}}"""

    @Test fun existingCustomDatasetAndOnlyCallerFilesSurviveWriteProbe() {
        val root=Files.createTempDirectory("geodat-custom-").toFile()
        try {
            val file=root.resolve("nested/custom.DAT").apply { parentFile!!.mkdir(); writeText("caller-full-data") }
            assertTrue(XrayGeodataAssets.hasSchedule(active))
            XrayGeodataAssets.validateWritableRoot(active,root)
            assertEquals("caller-full-data",file.readText())
            assertEquals(listOf("custom.DAT"),file.parentFile!!.list()!!.toList())
            assertFalse(root.resolve("geoip.dat").exists())
            assertFalse(root.resolve("geosite.dat").exists())
        } finally { root.deleteRecursively() }
    }

    @Test fun disabledAndReloadOnlySchedulesNeedNoWritableDirectory() {
        for (config in listOf("{}","""{"geodata":null}""","""{"geodata":{"cron":""}}""","""{"geodata":{"cron":"@daily"}}""")) {
            XrayGeodataAssets.validateWritableRoot(config,File("not-an-existing-directory"))
        }
        assertTrue(XrayGeodataAssets.hasSchedule("""{"geodata":{"cron":"@daily"}}"""))
        assertFalse(XrayGeodataAssets.hasSchedule("""{"geodata":{"cron":null}}"""))
    }

    @Test fun invalidOrMissingFileNeverCreatesAPlaceholderOrEscapesRoot() {
        val root=Files.createTempDirectory("geodat-files-").toFile()
        try {
            for (name in listOf("missing.dat","../outside.dat","/absolute.dat","nested//asset.dat","script.lua")) {
                val config="""{"geodata":{"cron":"@daily","assets":[{"file":"$name"}]}}"""
                assertThrows(IllegalArgumentException::class.java) { XrayGeodataAssets.validateWritableRoot(config,root) }
                assertEquals(0,root.list()!!.size)
            }
        } finally { root.deleteRecursively() }
    }

    @Test fun readOnlyAssetParentFailsWithoutChangingCallerBytesOrLeavingProbeFiles() {
        val root=Files.createTempDirectory("geodat-readonly-").toFile()
        val nested=root.resolve("nested").apply { mkdir() }
        try {
            val file=nested.resolve("custom.DAT").apply { writeText("original") }
            nested.setWritable(false,false)
            assumeFalse("Privileged test runner bypasses filesystem permission bits",nested.canWrite())
            assertThrows(IllegalArgumentException::class.java) { XrayGeodataAssets.validateWritableRoot(active,root) }
            assertEquals("original",file.readText())
            assertEquals(listOf("custom.DAT"),nested.list()!!.toList())
        } finally { nested.setWritable(true,true);root.deleteRecursively() }
    }

    @Test fun goFieldAliasesAreReadWithoutRewritingAndConflictsFail() {
        val alias="""{"GEODATA":{"Cron":"@daily","Aſſets":[]}}"""
        assertTrue(XrayGeodataAssets.hasSchedule(alias))
        XrayGeodataAssets.validateWritableRoot(alias,File("unused"))
        assertThrows(IllegalArgumentException::class.java) { XrayGeodataAssets.hasSchedule("""{"geodata":{"cron":"","Cron":"@daily"}}""") }
    }
}
