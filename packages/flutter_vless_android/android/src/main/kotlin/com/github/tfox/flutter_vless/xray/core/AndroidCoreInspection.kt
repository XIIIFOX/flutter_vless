package com.github.tfox.flutter_vless.xray.core

import android.content.Context
import android.system.Os
import com.github.tfox.flutter_vless.xray.utils.Utilities
import org.json.JSONObject
import org.json.JSONTokener
import java.io.File
import java.io.IOException
import java.util.Locale
import java.util.UUID

/** A configuration compiler running in a separate child. It never constructs a Core instance. */
internal object AndroidCoreInspection {
    private val versionPattern = Regex("^Xray ([0-9]+\\.[0-9]+\\.[0-9]+)(?:\\s|$)")
    private val parserUsage = Regex("^usage: (?:libxray\\.so|xray) convert pb \\[-outpbfile(?: |])")
    private val bundledDat = listOf("geoip.dat", "geosite.dat")

    private enum class Status(val code: String) {
        VALID("valid"), INVALID("invalid"), UNSUPPORTED("unsupported"), UNAVAILABLE("unavailable");

        fun result(stage: String? = null): Map<String, String> =
            if (stage == null) mapOf("status" to code) else mapOf("status" to code, "stage" to stage)
    }

    fun capabilities(context: Context): Map<String, Any> {
        val executable = XrayCoreManager.runtimeExecutable(context, routing = false)
        val version = if (usable(executable)) version(run(executable, listOf("version"))) else null
        val managed = if (version != null) XrayCoreManager.managedServiceCapabilities(context) else 0
        return buildMap {
            if (version != null) put("coreVersion", version)
            put("profileValidation", version != null && parserSupport(run(executable, listOf("help", "convert", "pb"))) == Status.VALID)
            put("vpnRouting", XrayCoreManager.supportsNativeRouting(context))
            put("geoDataUpdates", (managed and ManagedServiceCapabilities.GEODATA) != 0)
            put("xdrive", (managed and ManagedServiceCapabilities.XDRIVE) == ManagedServiceCapabilities.XDRIVE)
            put("balancerSelections", version != null && XrayCoreManager.supportsBalancerDiagnostics(context))
        }
    }

    fun validate(context: Context, json: String, geoDirectory: String?, certificateDirectory: String?): Map<String, String> =
        validate(json, geoDirectory, certificateDirectory, context.noBackupFilesDir,
            availability = {
                val executable = XrayCoreManager.runtimeExecutable(context, routing = false)
                if (usable(executable)) run(executable, listOf("help", "convert", "pb")) else null
            },
            serviceCapabilities = { XrayCoreManager.managedServiceCapabilities(context) },
            check = { input, assets, prepared, needsGeoData ->
                withAssets(context, assets) { directory ->
                    if (needsGeoData) XrayGeodataAssets.validateWritableRoot(prepared, directory, checkAtomicReplace = false)
                    // convert pb calls LoadConfig/Build, without constructing
                    // an Xray instance. The compiled output may contain keys.
                    run(XrayCoreManager.runtimeExecutable(context, routing = false),
                        listOf("convert", "pb", "-o", "/dev/null", input.absolutePath), directory)
                }
            })

    internal fun validate(json: String, geoDirectory: String?, certificateDirectory: String?, privateDirectory: File,
        availability: () -> BoundedCoreCommand.Completion?, serviceCapabilities: () -> Int,
        check: (File, File?, String, Boolean) -> BoundedCoreCommand.Completion?): Map<String, String> {
        val configuration: JSONObject
        val assets: File?
        val required: Int
        try {
            val tokenizer = JSONTokener(json)
            require(tokenizer.nextValue() is JSONObject && tokenizer.nextClean() == '\u0000')
            configuration = XrayCertificateAssets.prepare(json, certificateDirectory)
            assets = Utilities.validateAssetsDirectory(geoDirectory)
            val keys = configuration.keys().asSequence().toList()
            val envKeys = keys.filter { schemaName(it) == "env" }
            require(envKeys.size <= 1)
            val environment = envKeys.singleOrNull()?.let(configuration::opt)
            require(environment == null || environment == JSONObject.NULL || environment is JSONObject)
            if (environment is JSONObject && environment.length() > 0) {
                require(environment.keys().asSequence().map(environment::opt).all { it is String || it == JSONObject.NULL })
                return Status.UNSUPPORTED.result()
            }
            // Same private logging policy as startup. Unrecognized JSON and
            // nested caller settings are left for the installed Core parser.
            keys.filter { schemaName(it) == "log" }.forEach(configuration::remove)
            configuration.put("log", JSONObject().put("loglevel", "none").put("access", "none").put("error", "none"))
            required = ManagedServiceCapabilities.required(configuration.toString())
        } catch (_: Exception) {
            return Status.INVALID.result("prepare")
        }

        val support = parserSupport(availability())
        if (support != Status.VALID) return support.result()
        if (required != 0 && (required and serviceCapabilities()) != required) return Status.UNSUPPORTED.result()
        val snapshot = NativeRuntimeConfig.freeze(configuration)
        val input = try { snapshot.createInputs(privateDirectory, "validate") }
        catch (_: Exception) { return Status.UNAVAILABLE.result() }
        return try {
            input.use {
                val result = check(it.config, assets, configuration.toString(), (required and ManagedServiceCapabilities.GEODATA) != 0)
                when {
                    result?.exitCode == 0 -> Status.VALID.result()
                    result?.exitCode == 1 && result.output.toString(Charsets.UTF_8).lineSequence()
                        .any { line -> line.startsWith("failed to load config:") } -> Status.INVALID.result("coreCheck")
                    else -> Status.UNAVAILABLE.result()
                }
            }
        } catch (_: IllegalArgumentException) {
            Status.INVALID.result("prepare")
        } catch (_: Exception) {
            Status.UNAVAILABLE.result()
        }
    }

    private fun schemaName(name: String) = name.replace('\u017f', 's').replace('\u212a', 'k').lowercase(Locale.ROOT)

    private fun usable(file: File) = file.isFile && file.canExecute()

    private fun version(result: BoundedCoreCommand.Completion?): String? =
        result?.takeIf { it.exitCode == 0 }?.output?.toString(Charsets.UTF_8)
            ?.let { versionPattern.find(it)?.groupValues?.get(1) }

    private fun parserSupport(result: BoundedCoreCommand.Completion?): Status = when {
        result == null -> Status.UNAVAILABLE
        result.exitCode == 0 && result.output.toString(Charsets.UTF_8).lineSequence()
            .any { parserUsage.containsMatchIn(it) } -> Status.VALID
        result.output.toString(Charsets.UTF_8).lineSequence().any { it.startsWith("panic:") } -> Status.UNAVAILABLE
        result.exitCode in 0..2 -> Status.UNSUPPORTED
        else -> Status.UNAVAILABLE
    }

    private fun run(executable: File, args: List<String>, assets: File? = null): BoundedCoreCommand.Completion? = try {
        val builder = ProcessBuilder(listOf(executable.absolutePath) + args).redirectErrorStream(true)
        builder.environment().apply {
            remove("FLUTTER_VLESS_PROTECT_SOCKET")
            if (assets != null) {
                put("xray.location.asset", assets.absolutePath)
                put("XRAY_LOCATION_ASSET", assets.absolutePath)
            }
        }
        BoundedCoreCommand.complete(builder.start(), timeoutMillis = if (assets == null) 2_000 else 10_000)
    } catch (_: Exception) { null }

    private fun <T> withAssets(context: Context, requested: File?, run: (File) -> T): T {
        if (requested != null) return run(requested)
        val installed = context.filesDir
        val packaged = context.assets.list("").orEmpty().toSet()
        val missing = bundledDat.filter { name -> name in packaged && !File(installed, name).exists() }
        if (missing.isEmpty()) return run(installed)
        // Startup normally seeds APK data into filesDir. Use a disposable
        // overlay during inspection so caller-owned files and the active
        // worker's assets are never written or replaced.
        val temporary = File(context.noBackupFilesDir, "inspect-assets-${UUID.randomUUID()}")
        if (!temporary.mkdir()) throw IOException("Private inspection assets unavailable")
        try {
            installed.listFiles().orEmpty().filter { it.name !in missing }.forEach { file ->
                Os.symlink(file.absolutePath, File(temporary, file.name).absolutePath)
            }
            missing.forEach { name ->
                context.assets.open(name).use { input -> File(temporary, name).outputStream().use { input.copyTo(it) } }
            }
            return run(temporary)
        } finally {
            // Unlink only our direct children, never walk a linked directory.
            val failures = temporary.listFiles().orEmpty().count { !it.delete() }
            if (failures != 0 || !temporary.delete()) throw IOException("Private inspection assets could not be removed")
        }
    }
}
