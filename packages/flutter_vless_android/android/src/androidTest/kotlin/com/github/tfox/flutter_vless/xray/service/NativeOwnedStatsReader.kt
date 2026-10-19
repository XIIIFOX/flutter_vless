package com.github.tfox.flutter_vless.xray.service

import android.content.Context
import com.github.tfox.flutter_vless.xray.core.BoundedCoreCommand
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import java.io.File

/** Fixtures without caller API derive the current owned endpoint across process/recovery boundaries. */
internal object NativeOwnedStatsReader {
    fun ownedPort(runtime: JSONObject): Int = try {
        val api = runtime.getJSONObject("api")
        check(!api.has("listen") && api.getJSONArray("services").toString() == "[\"StatsService\"]")
        val tag = api.getString("tag"); check(tag.isNotEmpty())
        val rules = runtime.getJSONObject("routing").getJSONArray("rules")
        val rule = (0 until rules.length()).map { rules.getJSONObject(it) }
            .single { it.optString("outboundTag") == tag }
        val selectors = rule.getJSONArray("inboundTag"); check(selectors.length() == 1)
        val inputTag = selectors.getString(0); check(inputTag.isNotEmpty())
        val inputs = runtime.getJSONArray("inbounds")
        val input = (0 until inputs.length()).map { inputs.getJSONObject(it) }
            .single { it.optString("tag") == inputTag }
        check(input.getString("protocol") == "dokodemo-door" && input.getString("listen") == "127.0.0.1")
        val value = input.get("port") as? Number ?: error("Invalid owned port")
        val port = value.toInt(); check(port in 1..65535 && value.toDouble() == port.toDouble())
        port
    } catch (_: Exception) { error("Owned stats API descriptor is unavailable") }

    fun parse(output: ByteArray): JSONArray = try {
        val decoder = JSONTokener(output.toString(Charsets.UTF_8))
        val root = decoder.nextValue()
        check(root is JSONObject && decoder.nextClean() == '\u0000')
        root.getJSONArray("stat")
    } catch (_: Exception) { error("Owned stats API response is invalid") }

    fun read(context: Context): JSONArray {
        val files = context.noBackupFilesDir.listFiles().orEmpty().filter {
            it.isFile && it.name.startsWith("xray-") && it.name.endsWith(".json") && !it.name.endsWith(".spec.json")
        }
        check(files.size == 1) { "Owned stats runtime file count=${files.size}" }
        val port = try { ownedPort(JSONObject(files.single().readText())) }
            catch (_: Exception) { error("Owned stats runtime descriptor is unavailable") }
        println("NATIVE_OWNED_STATS port=$port stage=START")
        val process = try {
            ProcessBuilder(File(context.applicationInfo.nativeLibraryDir, "libxray.so").absolutePath,
                "api", "statsquery", "--server=127.0.0.1:$port", "--pattern", "outbound>>>")
                .redirectErrorStream(true).start()
        } catch (_: Exception) { error("Owned stats query port=$port stage=START_FAILED") }
        val output = BoundedCoreCommand.capture(process, timeoutMillis = 3000)
        val exit = runCatching { process.exitValue() }.getOrDefault(-1)
        val diagnostic = "Owned stats query port=$port exit=$exit bytes=${output?.size ?: 0}"
        check(output != null && output.isNotEmpty()) { "$diagnostic stage=COMMAND_FAILED" }
        return try { parse(output) }
        catch (_: Exception) { error("$diagnostic stage=JSON_FAILED") }
    }
}
