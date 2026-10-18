package com.github.tfox.flutter_vless.xray.service

/** One captured network's admission. Revocation is permanent and ordered against ACK writes. */
internal class NativePreviewNetworkGeneration {
    private val admission = Any()
    private var active = true
    private var claimed = false

    internal fun claim(): Boolean = synchronized(admission) {
        if (!active || claimed) return@synchronized false
        claimed = true
        true
    }

    fun isCurrent(): Boolean = synchronized(admission) { active }
    fun revoke() = synchronized(admission) { active = false }

    internal fun acknowledge(action: () -> Unit): Boolean = synchronized(admission) {
        if (!active || !claimed) return@synchronized false
        action()
        true
    }
}

/** No platform resolver, network selection, raw configuration or process-global policy lives here. */
internal class NativePreviewSocketPolicy(
    private val generation: NativePreviewNetworkGeneration,
    private val capturedNetworkIsValid: () -> Boolean
) {
    init { require(generation.claim()) { "Captured network generation is already claimed or revoked" } }

    fun isCurrent(): Boolean {
        if (!generation.isCurrent()) return false
        val valid = try { capturedNetworkIsValid() } catch (_: Exception) { false }
        if (!valid) {
            generation.revoke()
            return false
        }
        return generation.isCurrent()
    }

    fun revoke() = generation.revoke()

    fun protectBindAndAcknowledge(command: Int, descriptorCount: Int,
        protect: () -> Boolean, bind: () -> Unit, acknowledge: () -> Unit): Boolean {
        if (!accepts(command, descriptorCount) || !isCurrent()) return false
        return try {
            if (!protect() || !isCurrent()) return false
            bind()
            if (!isCurrent()) return false
            // Protect/bind happen outside admission. Only the final one-byte ACK
            // is serialized with revoke; a revoked generation cannot publish it.
            generation.acknowledge(acknowledge)
        } catch (_: Exception) {
            false
        }
    }

    companion object {
        fun accepts(command: Int, descriptorCount: Int) =
            descriptorCount == 1 && command in setOf('S'.code, 'Q'.code)
    }
}
