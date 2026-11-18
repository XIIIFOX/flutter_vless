package com.github.tfox.flutter_vless.xray.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class AndroidCoreInspectionTest {
    @get:Rule val temporary = TemporaryFolder()
    private val help = completed(0, "usage: libxray.so convert pb [-outpbfile file] [json file] ...")

    @Test fun `candidate uses its own file and preserves authored listeners and opaque fields`() {
        val runningProfile = temporary.newFile("session.json").apply { writeText("running-profile") }
        val config = """{"LoG":{"access":"private-path"},"outbounds":[{"protocol":"freedom","tag":"private-tag"}],
            "inbounds":[{"protocol":"socks","listen":"127.0.0.1","port":10808}],
            "future":{"nested":null}}"""
        val result = validate(config) { input, assets, _, needsGeoData ->
            assertEquals(temporary.root, input.parentFile?.parentFile)
            assertTrue(input.parentFile?.name?.startsWith("inspect-profile-") == true)
            assertFalse(input == runningProfile)
            assertNull(assets)
            assertFalse(needsGeoData)
            val prepared = JSONObject(input.readText())
            assertFalse(prepared.has("LoG"))
            assertEquals("none", prepared.getJSONObject("log").getString("access"))
            assertEquals("private-tag", prepared.getJSONArray("outbounds").getJSONObject(0).getString("tag"))
            assertEquals(10808, prepared.getJSONArray("inbounds").getJSONObject(0).getInt("port"))
            assertTrue(prepared.getJSONObject("future").isNull("nested"))
            completed(0, "private internal output")
        }
        assertEquals(mapOf("status" to "valid"), result)
        assertEquals("running-profile", runningProfile.readText())
        assertEquals(listOf(runningProfile), temporary.root.listFiles()!!.toList())
    }

    @Test fun `distinguishes invalid native input from missing parser and infrastructure failure`() {
        val refused = validate("{}") { _, _, _, _ -> completed(1, "failed to load config: private-data") }
        assertEquals(mapOf("status" to "invalid", "stage" to "coreCheck"), refused)
        val unavailable = validate("{}") { _, _, _, _ -> completed(1, "failed to create proto file: private-data") }
        assertEquals(mapOf("status" to "unavailable"), unavailable)
        assertEquals(mapOf("status" to "unavailable"), validate("{}") { _, _, _, _ -> null })
        assertEquals(mapOf("status" to "unavailable"), validate("{}", parser = null))
        assertEquals(mapOf("status" to "unsupported"), validate("{}", parser = completed(2, "unknown command")))
        assertEquals(mapOf("status" to "unavailable"), validate("{}", parser = completed(2, "panic: private-data")))
        assertTrue(temporary.root.listFiles()!!.isEmpty())
    }

    @Test fun `invalid preparation and unsafe Env never query or execute Core`() {
        fun attempt(config: String, geo: String? = null, certificate: String? = null) =
            AndroidCoreInspection.validate(config, geo, certificate, temporary.root,
                availability = { error("Core was queried") }, serviceCapabilities = { error("Service capability was queried") },
                check = { _, _, _, _ -> error("Core was started") })
        val invalid = mapOf("status" to "invalid", "stage" to "prepare")
        assertEquals(invalid, attempt("{} {}"))
        assertEquals(invalid, attempt("""{"env":"secret"}"""))
        assertEquals(invalid, attempt("""{"Env":{},"env":{}}"""))
        assertEquals(invalid, attempt("""{"env":{"XRAY_CUSTOM":1}}"""))
        assertEquals(invalid, attempt("""{"env":{"XRAY_CUSTOM":["secret"]}}"""))
        assertEquals(invalid, attempt("{}", geo = "relative-geo"))
        assertEquals(invalid, attempt("{}", certificate = "relative-certificate"))
        assertEquals(mapOf("status" to "unsupported"), attempt("""{"ENV":{"XRAY_LOCATION_ASSET":"private-path"}}"""))
        assertEquals(mapOf("status" to "unsupported"), attempt("""{"Env":{"XRAY_CUSTOM":null}}"""))
    }

    @Test fun `requiring native services checks the actual lifecycle bits before preflight`() {
        val config = """{"geodata":{"cron":"*/5 * * * *"},"outbounds":[{"protocol":"vless",
            "streamSettings":{"network":"xdrive","xdriveSettings":{"service":"google-drive",
            "remoteFolder":"fixture-folder","secrets":["one","two","three"]}}}]}"""
        assertEquals(mapOf("status" to "unsupported"), validate(config, bits = 3))
        val result = validate(config, bits = 7) { _, _, _, needsGeoData ->
            assertTrue(needsGeoData)
            completed(0, "")
        }
        assertEquals(mapOf("status" to "valid"), result)
    }

    private fun validate(config: String, parser: BoundedCoreCommand.Completion? = help, bits: Int = 0,
        check: (File, File?, String, Boolean) -> BoundedCoreCommand.Completion? = { _, _, _, _ -> error("unexpected Core build") }
    ) = AndroidCoreInspection.validate(config, null, null, temporary.root, { parser }, { bits }, check)

    private fun completed(code: Int, output: String) = BoundedCoreCommand.Completion(code, output.toByteArray(Charsets.UTF_8))
}
