package com.github.tfox.flutter_vless.xray.service

/** A bounded transfer attempt does not release the caller-owned TUN or session authorization. */
internal object FileDescriptorTransfer {
    fun send(
        ownsGeneration: () -> Boolean,
        workerAlive: () -> Boolean,
        transfer: () -> Unit,
        backoff: () -> Unit = { Thread.sleep(250) },
    ): Boolean {
        repeat(10) { attempt ->
            if (!ownsGeneration() || !workerAlive()) return false
            try {
                transfer()
                // STOP or a replacement can invalidate ownership during a blocking socket write.
                return ownsGeneration() && workerAlive()
            } catch (_: Exception) {
                if (!ownsGeneration() || !workerAlive()) return false
                if (attempt < 9) {
                    try { backoff() }
                    catch (_: InterruptedException) { Thread.currentThread().interrupt(); return false }
                }
            }
        }
        return false
    }
}
