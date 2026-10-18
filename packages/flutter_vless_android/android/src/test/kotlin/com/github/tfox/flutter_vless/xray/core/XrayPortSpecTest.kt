package com.github.tfox.flutter_vless.xray.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class XrayPortSpecTest {
    @Test fun sharedPinnedCorePortCorpus() {
        val cases = JSONArray(requireNotNull(javaClass.getResource("/ports.json")).readText())
        for (index in 0 until cases.length()) {
            val c = cases.getJSONObject(index)
            val environment = c.optJSONObject("environment") ?: JSONObject()
            val result = runCatching { XrayPortSpec.reservedPorts(c.get("value")) { environment.opt(it) as? String } }
            if (c.optBoolean("invalid")) assertTrue(c.getString("name"), result.isFailure)
            else {
                val ports = c.getJSONArray("ports")
                assertEquals(c.getString("name"), (0 until ports.length()).map { ports.getInt(it) }.toSet(), result.getOrThrow())
            }
        }
    }
}
