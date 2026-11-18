package com.github.tfox.flutter_vless.xray.core

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

@RunWith(AndroidJUnit4::class)
class AndroidCoreInspectionDeviceTest {
    @Test fun validatesWithTheInstalledCoreWithoutBindingTheAuthoredListener() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val existingWorker = XrayCoreManager.currentCoreProcess()
        val existingFiles = context.filesDir.list()?.toSet().orEmpty()
        val existingPrivate = context.noBackupFilesDir.list()?.toSet().orEmpty()
        val capabilities = AndroidCoreInspection.capabilities(context)
        assertTrue(capabilities["coreVersion"] is String)
        assertEquals(true, capabilities["profileValidation"])
        val loopback = InetAddress.getByName("127.0.0.1")
        ServerSocket(0, 1, loopback).use { listener ->
            val directory = context.noBackupFilesDir
            val callerLog = java.io.File(directory, "inspect-core-no-log-${java.util.UUID.randomUUID()}")
            val valid = """{
                "log":{"access":"${callerLog.absolutePath}","error":"${callerLog.absolutePath}"},
                "inbounds":[{"listen":"127.0.0.1","port":${listener.localPort},"protocol":"socks"}],
                "outbounds":[{"protocol":"freedom"}]
            }"""
            assertEquals(mapOf("status" to "valid"), AndroidCoreInspection.validate(context, valid, null, null))
            assertEquals(mapOf("status" to "invalid", "stage" to "coreCheck"), AndroidCoreInspection.validate(
                context, valid.replace("\"freedom\"", "\"fixture-unknown-protocol\""), null, null))
            assertEquals(mapOf("status" to "unsupported"), AndroidCoreInspection.validate(
                context, """{"env":{"XRAY_LOCATION_ASSET":"fixture"}}""", null, null))
            assertEquals(mapOf("status" to "invalid", "stage" to "prepare"), AndroidCoreInspection.validate(
                context, """{"env":{"XRAY_LOCATION_ASSET":123}}""", null, null))
            assertFalse(callerLog.exists())
            listener.soTimeout = 1_000
            Socket().use { client ->
                client.connect(InetSocketAddress(loopback, listener.localPort), 1_000)
                listener.accept().use { accepted ->
                    assertTrue(accepted.isConnected)
                }
            }
        }
        assertSame(existingWorker, XrayCoreManager.currentCoreProcess())
        assertEquals(existingFiles, context.filesDir.list()?.toSet().orEmpty())
        assertEquals(existingPrivate, context.noBackupFilesDir.list()?.toSet().orEmpty())
    }
}
