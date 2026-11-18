package com.github.tfox.flutter_vless.xray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class NativeBalancerDiagnosticsTest {
    private fun frame(encodedRows: String = "") = "{\"stage\":\"selections\",\"code\":0,\"rows\":\"$encodedRows\"}"

    @Test fun capabilityRequiresExactlyOneAffirmativeFrame() {
        val supported = "{\"stage\":\"capabilities\",\"code\":0,\"capability\":1}\n"
        assertTrue(NativeBalancerDiagnostics.supported(supported.toByteArray()))
        assertFalse(NativeBalancerDiagnostics.supported(null))
        assertFalse(NativeBalancerDiagnostics.supported(supported.replace("\":1", "\":0").toByteArray()))
        assertFalse(NativeBalancerDiagnostics.supported((supported + "Xray log text").toByteArray()))
    }

    @Test fun validatesNumericRowsBeforeTakingTheNewestBoundedSuffix() {
        val history = frame("20,1,8\\n21,1,9\\n22,1,1")
        assertEquals("20,1,8\n21,1,9\n22,1,1", NativeBalancerDiagnostics.rows(history, 10, 4096))
        assertEquals("22,1,1", NativeBalancerDiagnostics.rows(history, 10, 8))
        assertNull(NativeBalancerDiagnostics.rows(history, 2, 4096))
        for (line in listOf(frame("1,1,2\\n3,1,4"), frame("3,1,5\\n3,1,9"), frame("0,1,1"),
            frame("1,1,user.example"), frame("1,2147483648,1"), frame("9223372036854775808,1,1"),
            frame().dropLast(2) + "}", frame("1,1,1") + "extra",
            "{\"stage\":\"selections\",\"code\":1,\"rows\":\"\"}")) {
            assertNull(NativeBalancerDiagnostics.rows(line, 300, 4096))
        }
    }

    @Test fun snapshotsAreOnDemandAndDisableIsPermanentForTheWorker() {
        val native = fakeProcess(NativeBalancerDiagnostics.STARTED, frame("4,1,1\\n5,1,2"), frame())
        val one = NativeBalancerProcess(native, 2)
        assertTrue(one.awaitStarted())
        assertEquals("5,1,2", one.snapshot(1, 4096))
        assertTrue(one.disable())
        assertEquals("", one.snapshot(2, 4096))
        assertTrue(one.disable())
        assertEquals("snapshot\ndisable\n", native.commands.toString(Charsets.US_ASCII.name()))
        // An independently started worker has its own sequence and lifetime.
        val replacement = NativeBalancerProcess(fakeProcess(NativeBalancerDiagnostics.STARTED, frame("1,1,2")), 2)
        assertTrue(replacement.awaitStarted())
        assertEquals("1,1,2", replacement.snapshot(2, 4096))
    }

    private fun fakeProcess(vararg lines: String) = object : Process() {
        val commands = ByteArrayOutputStream()
        private val responses = ByteArrayInputStream(lines.joinToString("\n", postfix = "\n").toByteArray())
        private var alive = true
        override fun getInputStream() = responses
        override fun getOutputStream() = commands
        override fun getErrorStream() = ByteArrayInputStream(ByteArray(0))
        override fun isAlive() = alive
        override fun waitFor() = 0
        override fun exitValue() = if (alive) error("Still alive") else 0
        override fun destroy() { alive = false }
    }
}
