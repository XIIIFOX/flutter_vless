package com.github.tfox.flutter_vless.xray.service

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.security.MessageDigest
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions

class NativeRoutingSpecTest {
    private val tag = "managed-private-canary"
    private val user = "session-user-canary"
    private fun document() = JSONObject("""{
      "inbounds":[
        {"tag":"$tag","listen":"127.0.0.1","port":19891,"protocol":"socks",
         "settings":{"auth":"password","accounts":[{"user":"$user","pass":"password-canary"}]}},
        {"tag":"caller","listen":"127.0.0.1","port":19892,"protocol":"socks","settings":{"auth":"noauth"}},
        {"tag":null,"listen":"127.0.0.1","port":19893,"protocol":"socks","settings":{"auth":"noauth"}}
      ],"outbounds":[{"tag":"blocked","protocol":"blackhole"},{"tag":"selected","protocol":"freedom"}],
      "routing":{"rules":[
        {"type":"field","inboundTag":["$tag"],"ip":["198.18.0.2/32"],"outboundTag":"selected"},
        {"type":"field","inboundTag":["$tag"],"outboundTag":"blocked","callerMarker":"private-name-lookalike"},
        {"type":"field","inboundTag":"private-bootstrap,private-dns","outboundTag":"blocked"}
      ]},"dns":{"hosts":{"unchanged.invalid":"192.0.2.1"},"servers":["tcp://1.1.1.1"]},
      "api":{"tag":"synthetic-caller-api","services":["StatsService"]},"remarks":"Точный UTF-8 🦊"
    }""")
    private fun bytes(document: JSONObject = document()) = (document.toString(2) + " \n").toByteArray(Charsets.UTF_8)
    private fun freeze(data: ByteArray = bytes(), intent: NativeRoutingIntent? = NativeRoutingIntent(0, "selected"),
                       mapped: Int? = 1, managed: Int = 0, guards: List<Int> = listOf(0, 2),
                       expectedTag: String = tag, expectedUser: String = user) =
        NativeRoutingSpec.freeze(data, managed, expectedTag, expectedUser, intent, mapped, guards)
    private fun rejected(expected: NativeRoutingSpecFailure, block: () -> Unit) {
        try { block(); fail("Invalid native routing metadata accepted") }
        catch (error: NativeRoutingSpecException) {
            assertEquals(expected, error.failure)
            assertFalse(error.toString().contains("canary"))
            assertNull(error.cause)
        }
    }
    private fun inbound(document: JSONObject) = document.getJSONArray("inbounds").getJSONObject(0)
    private fun rule(document: JSONObject) = document.getJSONObject("routing").getJSONArray("rules").getJSONObject(0)

    @Test fun bindsExactFinalBytesAndExplicitGuardOrderWithoutRebuildingCallerJson() {
        val data = bytes(); val original = data.clone()
        val intent = NativeRoutingIntent(0, "selected")
        val result = requireNotNull(freeze(data, intent))
        val metadata = JSONObject(String(result.metadataData, Charsets.UTF_8))
        val digest = MessageDigest.getInstance("SHA-256").digest(original).joinToString("") { "%02x".format(it) }
        assertArrayEquals(original, result.configurationData); assertArrayEquals(original, data)
        assertEquals(digest, result.sourceSHA256); assertEquals(digest, metadata.getString("source_sha256"))
        assertEquals(1, metadata.getInt("version")); assertEquals(0, metadata.getInt("managed_inbound_index"))
        assertEquals(tag, metadata.getString("managed_inbound_tag")); assertEquals(user, metadata.getString("auth_user"))
        assertEquals(1, metadata.getInt("source_inbound_index")); assertEquals("selected", metadata.getString("default_outbound_tag"))
        assertEquals("[0,2]", metadata.getJSONArray("guard_rule_indices").toString())
        assertEquals(setOf("version", "source_sha256", "managed_inbound_index", "managed_inbound_tag", "auth_user",
            "source_inbound_index", "default_outbound_tag", "guard_rule_indices"), metadata.keys().asSequence().toSet())
        assertEquals(0, intent.sourceInboundIndex)
        assertNotEquals(result.sourceSHA256, requireNotNull(freeze(data + byteArrayOf(32))).sourceSHA256)
        System.getenv("FLVLESS_EXPORT_ROUTING_PAIR")?.let { directory ->
            val root = Paths.get(directory)
            Files.createDirectories(root)
            for ((name, content) in listOf("config.json" to result.configurationData, "spec.json" to result.metadataData)) {
                val path = root.resolve(name)
                Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
                Files.write(path, content, StandardOpenOption.TRUNCATE_EXISTING)
            }
        }
    }

    @Test fun snapshotsInputAndReturnedBytesAndKeepsDescriptionsPrivate() {
        val data = bytes(); val original = data.clone(); val intent = NativeRoutingIntent(0, "selected")
        val result = requireNotNull(freeze(data, intent)); val metadata = result.metadataData
        data[0] = 0; result.configurationData[0] = 0; result.metadataData[0] = 0
        assertArrayEquals(original, result.configurationData); assertArrayEquals(metadata, result.metadataData)
        assertEquals("NativeRoutingIntent(<private>)", intent.toString())
        assertEquals("NativeRoutingEnvelope(<private>)", result.toString())
        assertFalse(result.toString().contains(user)); assertFalse(intent.toString().contains("selected"))
    }

    @Test fun callerJsonCannotEnableOrOverrideTrustedIntentAndNilDoesNotParse() {
        val input = document().put("nativeRoutingSpec", JSONObject().put("source_inbound_index", 2))
            .put("source_inbound_index", 2)
        assertNull(freeze(bytes(input), intent = null, mapped = null))
        assertNull(freeze("not-json".toByteArray(), intent = null, mapped = 999))
        val result = requireNotNull(freeze(bytes(input)))
        assertEquals(1, JSONObject(String(result.metadataData)).getInt("source_inbound_index"))
    }

    @Test fun emptyIntentOmitsSourceAndDefaultAndDoesNotInventPrivateGuards() {
        for (default in listOf(null, "")) {
            val result = requireNotNull(freeze(intent = NativeRoutingIntent(defaultOutboundTag = default), mapped = null, guards = emptyList()))
            val fields = JSONObject(String(result.metadataData))
            assertFalse(fields.has("source_inbound_index")); assertFalse(fields.has("default_outbound_tag"))
            assertEquals(0, fields.getJSONArray("guard_rule_indices").length())
        }
        val result = requireNotNull(freeze(guards = listOf(2, 0)))
        assertEquals("[2,0]", JSONObject(String(result.metadataData)).getJSONArray("guard_rule_indices").toString())
        assertEquals("private-name-lookalike", JSONObject(String(result.configurationData)).getJSONObject("routing")
            .getJSONArray("rules").getJSONObject(1).getString("callerMarker"))
    }

    @Test fun originalIndexRequiresSeparateExplicitMappingAndDoesNotUseTagLookup() {
        rejected(NativeRoutingSpecFailure.INVALID_INTENT) { NativeRoutingIntent(-1) }
        for (mapped in listOf(null, -1, 0, 3, Int.MAX_VALUE))
            rejected(NativeRoutingSpecFailure.INVALID_SOURCE_INBOUND) { freeze(mapped = mapped) }
        rejected(NativeRoutingSpecFailure.INVALID_SOURCE_INBOUND) { freeze(intent = NativeRoutingIntent(), mapped = 1) }
        // Only the preparer knows original bounds/provenance; the encoder never adds an offset.
        val mapped = requireNotNull(freeze(intent = NativeRoutingIntent(99), mapped = 2))
        assertEquals(2, JSONObject(String(mapped.metadataData)).getInt("source_inbound_index"))
        assertTrue(JSONObject(String(mapped.configurationData)).getJSONArray("inbounds").getJSONObject(2).isNull("tag"))
    }

    @Test fun managedInputRequiresExactUniqueIdentityAndAuthenticatedLoopback() {
        for (index in listOf(-1, 3, Int.MAX_VALUE))
            rejected(NativeRoutingSpecFailure.INVALID_MANAGED_INBOUND) { freeze(managed = index) }
        for (value in listOf("", "foreign-canary")) {
            rejected(NativeRoutingSpecFailure.INVALID_MANAGED_INBOUND) { freeze(expectedTag = value) }
            rejected(NativeRoutingSpecFailure.INVALID_MANAGED_INBOUND) { freeze(expectedUser = value) }
        }
        val mutations: List<(JSONObject) -> Unit> = listOf(
            { it.put("protocol", "http") }, { it.put("listen", "0.0.0.0") },
            { it.put("settings", JSONObject().put("auth", "noauth")) },
            { it.getJSONObject("settings").getJSONArray("accounts").getJSONObject(0).put("pass", "") },
            { it.getJSONObject("settings").getJSONArray("accounts").getJSONObject(0).put("user", "foreign-canary") },
            { it.getJSONObject("settings").getJSONArray("accounts").put(JSONObject().put("user", user).put("pass", "second-canary")) }
        )
        for (mutate in mutations) {
            val input = document(); mutate(inbound(input))
            rejected(NativeRoutingSpecFailure.INVALID_MANAGED_INBOUND) { freeze(bytes(input)) }
        }
        val duplicate = document(); duplicate.getJSONArray("inbounds").getJSONObject(1).put("tag", tag)
        rejected(NativeRoutingSpecFailure.INVALID_MANAGED_INBOUND) { freeze(bytes(duplicate)) }
        val ipv6Loopback = document(); inbound(ipv6Loopback).put("listen", "::1")
        assertNotNull(freeze(bytes(ipv6Loopback)))
    }

    @Test fun managedPortMustBeSingleIntegerAndNotBooleanOrString() {
        for (port in listOf<Any>(true, "19891", JSONObject.NULL, 0, -1, 65536, 1.5)) {
            val input = document(); inbound(input).put("port", port)
            rejected(NativeRoutingSpecFailure.INVALID_MANAGED_INBOUND) { freeze(bytes(input)) }
        }
        for (port in listOf(1, 65535)) {
            val input = document(); inbound(input).put("port", port)
            assertNotNull(freeze(bytes(input)))
        }
    }

    @Test fun selectedDefaultMustExistExactlyOnceWithByteExactTag() {
        for (target in listOf("missing-canary", "selected ", "native-e\u0301")) {
            val input = document(); input.getJSONArray("outbounds").getJSONObject(1).put("tag", "native-\u00e9")
            rejected(NativeRoutingSpecFailure.INVALID_DEFAULT_OUTBOUND) { freeze(bytes(input), NativeRoutingIntent(defaultOutboundTag = target), mapped = null) }
        }
        val input = document(); val outputs = input.getJSONArray("outbounds"); outputs.put(JSONObject(outputs.getJSONObject(1).toString()))
        rejected(NativeRoutingSpecFailure.INVALID_DEFAULT_OUTBOUND) { freeze(bytes(input)) }
        val noOutputs = document().apply { remove("outbounds") }
        assertNotNull(freeze(bytes(noOutputs), NativeRoutingIntent(), mapped = null))
    }

    @Test fun onlyExplicitValidGuardIndicesAreIncludedAndNoCallerRuleIsInferred() {
        for (indices in listOf(listOf(-1), listOf(3), listOf(0, 0)))
            rejected(NativeRoutingSpecFailure.INVALID_GUARD_RULES) { freeze(guards = indices) }
        val mutations: List<(JSONObject) -> Unit> = listOf(
            { it.put("inboundTag", JSONArray()) }, { it.put("inboundTag", JSONArray().put("")) },
            { it.put("inboundTag", JSONArray().put(JSONObject.NULL)) }, { it.put("inboundTag", "caller,") },
            { it.put("outboundTag", "") }, { it.put("balancerTag", "caller") }, { it.put("webhook", JSONObject()) }
        )
        for (mutate in mutations) {
            val input = document(); mutate(rule(input))
            rejected(NativeRoutingSpecFailure.INVALID_GUARD_RULES) { freeze(bytes(input)) }
            assertNotNull(freeze(bytes(input), guards = listOf(2)))
        }
        val input = document(); rule(input).put("balancerTag", JSONObject.NULL).put("webhook", JSONObject.NULL)
        assertNotNull(freeze(bytes(input)))
    }

    @Test fun foldedSchemaKeysAreAcceptedButAmbiguousAliasesFailClosed() {
        val input = document(); input.put("INBOUND\u017f", input.remove("inbounds"))
        val managed = input.getJSONArray("INBOUND\u017f").getJSONObject(0)
        managed.put("SETTINGS", managed.remove("settings"))
        val result = requireNotNull(freeze(bytes(input))); assertArrayEquals(bytes(input), result.configurationData)
        input.put("inbounds", JSONArray())
        rejected(NativeRoutingSpecFailure.MALFORMED_CONFIGURATION) { freeze(bytes(input)) }
        val nested = document(); inbound(nested).put("TAG", tag)
        rejected(NativeRoutingSpecFailure.MALFORMED_CONFIGURATION) { freeze(bytes(nested)) }
    }

    @Test fun malformedUtf8JsonAndWrongRootTypesRefuseWithContentFreeErrors() {
        for (input in listOf("not-json".toByteArray(), "[]".toByteArray(), bytes() + "{}".toByteArray(), byteArrayOf(0xC3.toByte(), 0x28)))
            rejected(NativeRoutingSpecFailure.MALFORMED_CONFIGURATION) { freeze(input) }
        val malformed = document().put("inbounds", JSONArray().put("canary-not-an-object"))
        rejected(NativeRoutingSpecFailure.MALFORMED_CONFIGURATION) { freeze(bytes(malformed)) }
    }
}
