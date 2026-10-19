package com.github.tfox.flutter_vless

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.ResultReceiver
import com.github.tfox.flutter_vless.xray.service.NativeOptionsStore
import com.github.tfox.flutter_vless.xray.service.NativeVlessOptions
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import org.junit.Assert.*
import org.junit.Test
import org.mockito.Mockito
import java.util.concurrent.ExecutorService

/** Actual channel callbacks only; no Android service, worker, probe or process starts. */
class StartupPreparationChannelTest {
    private class Reply : MethodChannel.Result {
        var successes = 0
        var value: Any? = null
        var details: Any? = null
        var code: String? = null
        override fun success(result: Any?) { successes++; value = result }
        override fun error(errorCode: String, errorMessage: String?, errorDetails: Any?) {
            code = errorCode; details = errorDetails
        }
        override fun notImplemented() = fail("Startup channel unavailable")
    }

    private fun response(change: String? = null, stage: String? = null): Bundle {
        val data = Mockito.mock(Bundle::class.java)
        Mockito.`when`(data.getString("stage")).thenReturn(stage)
        if (stage == null) {
            val report = Mockito.mock(Bundle::class.java)
            Mockito.`when`(report.getInt("version")).thenReturn(1)
            Mockito.`when`(report.getString("scope")).thenReturn("runtimeFinal")
            Mockito.`when`(report.getString("coreCheck")).thenReturn("passed")
            Mockito.`when`(report.getStringArrayList("changes")).thenReturn(ArrayList(listOfNotNull(change)))
            Mockito.`when`(data.getBundle("preparationReport")).thenReturn(report)
        }
        return data
    }

    private fun withCallbacks(body: (List<ResultReceiver>, List<Reply>) -> Unit) {
        val plugin = FlutterVlessPlugin()
        val context = Mockito.mock(Context::class.java)
        FlutterVlessPlugin::class.java.getDeclaredField("context").apply { isAccessible = true }.set(plugin, context)
        val callbacks = mutableListOf<ResultReceiver>()
        try {
            Mockito.mockConstruction(NativeOptionsStore::class.java) { store, _ ->
                Mockito.`when`(store.read()).thenReturn(NativeVlessOptions())
            }.use {
                Mockito.mockConstruction(Intent::class.java) { intent, _ ->
                    Mockito.doAnswer { invocation ->
                        if (invocation.getArgument<String>(0) == "start_receiver") callbacks += invocation.getArgument<ResultReceiver>(1)
                        intent
                    }.`when`(intent).putExtra(Mockito.anyString(), Mockito.any(android.os.Parcelable::class.java))
                }.use {
                    val replies = (0..1).map {
                        Reply().also { reply -> plugin.onMethodCall(MethodCall("startVless", mapOf(
                            "config" to """{"inbounds":[{"tag":"caller","protocol":"socks","listen":"127.0.0.1","port":10807,"settings":{"auth":"noauth"}}],"outbounds":[{"protocol":"freedom"}]}""",
                            "proxy_only" to true)), reply) }
                    }
                    assertEquals("Both actual starts must retain their own service receiver", 2, callbacks.size)
                    body(callbacks, replies)
                }
            }
        } finally {
            (FlutterVlessPlugin::class.java.getDeclaredField("executor").apply { isAccessible = true }.get(plugin) as ExecutorService).shutdownNow()
        }
    }

    private fun deliver(receiver: ResultReceiver, code: Int, data: Bundle?) {
        receiver.javaClass.getDeclaredMethod("onReceiveResult", Int::class.javaPrimitiveType, Bundle::class.java)
            .apply { isAccessible = true }.invoke(receiver, code, data)
    }

    @Test fun reverseCallbacksReturnTheirOwnSafePreparedReportInsteadOfGlobalOrNullReply() = withCallbacks { callbacks, replies ->
        deliver(callbacks[1], 0, response("certificate_refs_bound"))
        deliver(callbacks[0], 0, response("private_listener_added"))
        for ((index, change) in listOf("private_listener_added", "certificate_refs_bound").withIndex()) {
            val expected = mapOf("preparationReport" to mapOf("version" to 1, "scope" to "runtimeFinal", "coreCheck" to "passed", "changes" to listOf(change)))
            assertEquals("A success must describe the same checked invocation", expected, replies[index].value)
        }
    }

    @Test fun directlyKnownFailureStageSurvivesTheActualCallbackWithoutRawDiagnostics() = withCallbacks { callbacks, replies ->
        deliver(callbacks[0], 1, response(stage = "core-check"))
        assertEquals("INVALID_CONFIG", replies[0].code)
        assertEquals(mapOf("stage" to "core-check"), replies[0].details)
        deliver(callbacks[1], 1, response(stage = "PRIVATE_CANARY_raw_error"))
        assertNull("Unknown diagnostic text must never become a public stage", replies[1].details)
    }

    @Test fun legacyNullReplyAndUnrecognizedChangeStayUnavailableWithoutInventingAPassedReport() = withCallbacks { callbacks, replies ->
        deliver(callbacks[0], 0, null)
        deliver(callbacks[1], 0, response("PRIVATE_CANARY_unknown_operation"))
        replies.forEach { assertEquals(1, it.successes); assertNull(it.value); assertNull(it.code) }
    }
}
