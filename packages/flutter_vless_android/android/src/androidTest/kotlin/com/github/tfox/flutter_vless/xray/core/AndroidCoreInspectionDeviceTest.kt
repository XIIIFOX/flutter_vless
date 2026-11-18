package com.github.tfox.flutter_vless.xray.core

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.github.tfox.flutter_vless.xray.service.SessionRuntimeFiles
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

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

    @Test fun pendingInspectionsSurviveDaemonCleanupBeforeEitherParserStarts() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val directory = context.noBackupFilesDir
        val existing = directory.list()?.toSet().orEmpty()
        val abandoned = File(directory, "validate-${UUID.randomUUID()}.json").apply { writeText("fixture") }
        val beforeCheck = CountDownLatch(2)
        val resume = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(2)
        fun inspect(protocol: String) = executor.submit<Map<String, String>> {
            AndroidCoreInspection.validate(context, """{"outbounds":[{"protocol":"$protocol"}]}""", null, null) {
                beforeCheck.countDown()
                check(resume.await(10, TimeUnit.SECONDS))
            }
        }
        try {
            val good = inspect("freedom")
            val bad = inspect("fixture-unknown-protocol")
            assertTrue(beforeCheck.await(10, TimeUnit.SECONDS))
            SessionRuntimeFiles.removeAbandoned(directory)
            assertFalse(abandoned.exists())
            resume.countDown()
            assertEquals(mapOf("status" to "valid"), good.get(15, TimeUnit.SECONDS))
            assertEquals(mapOf("status" to "invalid", "stage" to "coreCheck"), bad.get(15, TimeUnit.SECONDS))
            assertEquals(existing, directory.list()?.toSet().orEmpty())
        } finally {
            resume.countDown()
            executor.shutdownNow()
            executor.awaitTermination(10, TimeUnit.SECONDS)
            abandoned.delete()
        }
    }
}
