package com.github.tfox.flutter_vless.xray.core

import com.github.tfox.flutter_vless.xray.utils.Utilities
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.google.gson.Gson
import org.junit.Assert.*
import org.junit.Test
import java.nio.file.Files

class XrayAssetsLocationTest {
    @Test fun emptyExplicitDirectoryNeedsNoStandardAssetsAndSurvivesRecoverySnapshots() {
        val directory = Files.createTempDirectory("xray-assets-snapshot-test").toFile()
        try {
            val source = """{"inbounds":[],"outbounds":[{"protocol":"freedom"}]}"""
            val config = XrayConfig(V2RAY_FULL_JSON_CONFIG = source, GEO_ASSETS_DIRECTORY = directory.absolutePath, PROXY_ONLY = true)
            XrayCoreManager.validateConfiguration(config)
            assertEquals(directory.absolutePath, config.copy().GEO_ASSETS_DIRECTORY)
            // AuthorizedProfileStore and quick-access snapshots use this Gson DTO.
            val restored = Gson().fromJson(Gson().toJson(config), XrayConfig::class.java)
            assertEquals(directory.absolutePath, restored.GEO_ASSETS_DIRECTORY)
            assertEquals(source, restored.V2RAY_FULL_JSON_CONFIG)
            assertEquals(source, config.V2RAY_FULL_JSON_CONFIG)
            assertEquals(0, directory.listFiles()!!.size)
            assertNull(Gson().fromJson("{}", XrayConfig::class.java).GEO_ASSETS_DIRECTORY)
        } finally { directory.deleteRecursively() }
    }

    @Test fun preliminaryConfigurationValidationRejectsUnavailableAssetRoots() {
        val directory = Files.createTempDirectory("xray-assets-preflight-test").toFile()
        try {
            val source = """{"inbounds":[],"outbounds":[{"protocol":"freedom"}]}"""
            for (requested in listOf("", "relative/assets", directory.resolve("missing").absolutePath)) {
                val config = XrayConfig(V2RAY_FULL_JSON_CONFIG = source, GEO_ASSETS_DIRECTORY = requested, PROXY_ONLY = true)
                assertThrows(IllegalArgumentException::class.java) { XrayCoreManager.validateConfiguration(config) }
                assertEquals(source, config.V2RAY_FULL_JSON_CONFIG)
            }
        } finally { directory.deleteRecursively() }
    }

    @Test fun explicitRootWinsBothInheritedAliasesWithoutCopyingOrChangingCertificateRoots() {
        val directory = Files.createTempDirectory("xray-assets-test").toFile()
        try {
            val fallback = directory.resolve("default").apply { mkdir() }
            val selected = directory.resolve("external").apply { mkdir() }
            val custom = selected.resolve("caller-geosite.dat").apply { writeBytes(byteArrayOf(1, 2, 3)) }
            val before = custom.readBytes()
            val env = mutableMapOf("xray.location.asset" to "inherited-exact", "XRAY_LOCATION_ASSET" to "inherited-alias",
                "xray.location.cert" to "caller-cert-root", "XRAY_LOCATION_CERT" to "caller-cert-alias")
            var copied = 0
            assertEquals(selected, Utilities.configureXrayAssets(env, fallback, selected.absolutePath) { copied++ })
            assertEquals(selected.absolutePath, env["xray.location.asset"])
            assertEquals(selected.absolutePath, env["XRAY_LOCATION_ASSET"])
            assertEquals("caller-cert-root", env["xray.location.cert"])
            assertEquals("caller-cert-alias", env["XRAY_LOCATION_CERT"])
            assertEquals(0, copied)
            assertArrayEquals(before, custom.readBytes())
            assertEquals(listOf("caller-geosite.dat"), selected.listFiles()!!.map { it.name })
        } finally { directory.deleteRecursively() }
    }

    @Test fun invalidExplicitRootsFailBeforeEnvironmentMutationOrBundledCopy() {
        val directory = Files.createTempDirectory("xray-assets-invalid-test").toFile()
        try {
            val regular = directory.resolve("file").apply { writeText("fixture") }
            for (requested in listOf("", "relative/assets", directory.resolve("missing").absolutePath, regular.absolutePath)) {
                val env = mutableMapOf("XRAY_LOCATION_ASSET" to "unchanged")
                var copied = 0
                assertThrows(IllegalArgumentException::class.java) {
                    Utilities.configureXrayAssets(env, directory, requested) { copied++ }
                }
                assertEquals(mapOf("XRAY_LOCATION_ASSET" to "unchanged"), env)
                assertEquals(0, copied)
            }
        } finally { directory.deleteRecursively() }
    }

    @Test fun nullRootKeepsLegacyDirectoryAndBundledCopyButRefreshesBothAliases() {
        val directory = Files.createTempDirectory("xray-assets-default-test").toFile()
        try {
            val env = mutableMapOf("xray.location.asset" to "stale")
            var copied = 0
            assertEquals(directory, Utilities.configureXrayAssets(env, directory, null) { copied++ })
            assertEquals(1, copied)
            assertEquals(directory.absolutePath, env["xray.location.asset"])
            assertEquals(directory.absolutePath, env["XRAY_LOCATION_ASSET"])
            assertFalse(env.containsKey("xray.location.cert"))
            assertFalse(env.containsKey("XRAY_LOCATION_CERT"))
        } finally { directory.deleteRecursively() }
    }
}
