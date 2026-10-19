package com.github.tfox.flutter_vless.xray.core

import android.os.Bundle

/** Fixed operations only: never retain configuration values, identities or paths. */
internal enum class PreparationChange(val code: String) {
    CERTIFICATE_REFS_BOUND("certificate_refs_bound"),
    PRIVATE_LISTENER_ADDED("private_listener_added"),
    SYSTEM_DNS_GUARD_ADDED("system_dns_guard_added"),
    PRIVATE_LOGGING_APPLIED("private_logging_applied"),
    PORT_ENVIRONMENT_BOUND("port_environment_bound"),
    ADDRESS_ENVIRONMENT_BOUND("address_environment_bound")
}

/** One invocation's producer observations; a candidate takes an immutable snapshot. */
internal class PreparationChanges {
    private val changes = mutableSetOf<PreparationChange>()
    fun record(change: PreparationChange) { changes += change }
    fun snapshot(): List<PreparationChange> = PreparationChange.values().filter { it in changes }
}

/** Created only after the exact final candidate passed native preflight. This is not network readiness. */
internal class PreparationReport private constructor(changes: List<PreparationChange>) {
    private val changes = changes.toList()
    fun asMap(): Map<String, Any> = mapOf("version" to 1, "scope" to "runtimeFinal",
        "coreCheck" to "passed", "changes" to changes.map { it.code })
    fun toBundle(): Bundle = Bundle().apply {
        putInt("version", 1); putString("scope", "runtimeFinal"); putString("coreCheck", "passed")
        putStringArrayList("changes", ArrayList(changes.map { it.code }))
    }
    companion object {
        fun checked(changes: List<PreparationChange>) = PreparationReport(changes)
        fun fromBundle(data: Bundle?): PreparationReport? {
            val report = data?.getBundle("preparationReport") ?: return null
            if (report.getInt("version") != 1 || report.getString("scope") != "runtimeFinal" ||
                report.getString("coreCheck") != "passed") return null
            val codes = report.getStringArrayList("changes") ?: return null
            if (codes.size > PreparationChange.values().size || codes.distinct().size != codes.size) return null
            val changes = codes.map { code -> PreparationChange.values().singleOrNull { it.code == code } ?: return null }
            return PreparationReport(changes)
        }
    }
}

internal enum class PreparationStage(val code: String) {
    PREPARE("prepare"), CORE_CHECK("core-check"), PERSIST("persist"), START("start");
    companion object {
        fun details(data: Bundle?): Map<String, String>? = values().singleOrNull { it.code == data?.getString("stage") }
            ?.let { mapOf("stage" to it.code) }
    }
}

/** Allocated inside one queued START closure, never a service/global last-report field. */
internal class StartupPreparationOutcome {
    var stage = PreparationStage.PREPARE
    var report: PreparationReport? = null
    fun toBundle(accepted: Boolean): Bundle = Bundle().apply {
        if (accepted) report?.let { putBundle("preparationReport", it.toBundle()) }
        else putString("stage", stage.code)
    }
}
