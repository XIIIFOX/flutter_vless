package com.github.tfox.flutter_vless.xray.service

import android.accessibilityservice.AccessibilityServiceInfo
import android.os.Build
import android.os.ParcelFileDescriptor
import android.view.accessibility.AccessibilityNodeInfo
import androidx.test.platform.app.InstrumentationRegistry

/** Test-only OS controls through the real Settings UI; no private API or platform security bypass. */
internal class EmulatorVpnPolicy {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val ui = instrumentation.uiAutomation
    init {
        check(Build.HARDWARE in setOf("ranchu", "goldfish")) { "Dedicated emulator required" }
        ui.serviceInfo = ui.serviceInfo.apply { flags = flags or AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS }
    }
    fun shell(command: String): String = ui.executeShellCommand(command).use {
        ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText().trim()
    }
    fun alwaysOn(): String? = shell("settings --user 0 get secure always_on_vpn_app").takeUnless { it == "null" || it.isEmpty() }
    fun locked() = shell("settings --user 0 get secure always_on_vpn_lockdown") == "1"
    private fun nodes(root: AccessibilityNodeInfo?): List<AccessibilityNodeInfo> {
        if (root == null) return emptyList()
        return listOf(root) + (0 until root.childCount).flatMap { nodes(root.getChild(it)) }
    }
    private fun find(predicate: (AccessibilityNodeInfo) -> Boolean) = nodes(ui.rootInActiveWindow).firstOrNull(predicate)
    private fun waitFor(description: String, predicate: () -> Boolean) {
        repeat(100) { if (predicate()) return; Thread.sleep(100) }
        val visible = nodes(ui.rootInActiveWindow).filter { it.text != null || it.isCheckable }
            .joinToString("; ") { "${it.viewIdResourceName}:${it.text}:checkable=${it.isCheckable}:checked=${it.isChecked}" }
        error("OS VPN Settings did not reach $description; visible=$visible")
    }
    private fun row(title: String): AccessibilityNodeInfo? {
        var node = find { it.text?.toString() == title } ?: return null
        while (!node.isClickable) node = node.parent ?: return null
        return node
    }
    private fun open() {
        // A reused Settings activity can expose its old detail tree while
        // CLEAR_TOP asynchronously navigates back to the VPN list. Start a new
        // Settings activity on this dedicated emulator to avoid acting on it.
        shell("am force-stop com.android.settings")
        waitFor("previous Settings activity to close") {
            ui.rootInActiveWindow?.packageName?.toString() != "com.android.settings"
        }
        shell("am start -f 0x14000000 -a android.settings.VPN_SETTINGS")
        var lastOpenAttempt = 0L
        waitFor("test VPN policy page") {
            // Activity/fragment transitions can replace the accessibility root
            // between reads. Decide from one snapshot and retry stale nodes;
            // never assume a list entry still exists after a prior wait.
            val current = nodes(ui.rootInActiveWindow)
            val ownPage = current.any { it.text?.toString() == "Always-on VPN" } && current.any {
                it.contentDescription?.toString() == XrayVPNService::class.java.name
            }
            if (ownPage) return@waitFor true
            val now = System.nanoTime()
            if (now - lastOpenAttempt < 1_000_000_000L) return@waitFor false
            val title = current.firstOrNull { it.text?.toString() == XrayVPNService::class.java.name }
                ?: return@waitFor false
            var parent = title.parent
            var gear: AccessibilityNodeInfo? = null
            while (parent != null && gear == null) {
                gear = nodes(parent).firstOrNull { it.viewIdResourceName == "com.android.settings:id/settings_button" }
                parent = parent.parent
            }
            val control = gear
            if (control?.isEnabled == true && control.performAction(AccessibilityNodeInfo.ACTION_CLICK)) {
                lastOpenAttempt = now
            }
            false
        }
    }
    private fun policyState(title: String): Boolean = when (title) {
        "Always-on VPN" -> alwaysOn() == context.packageName
        "Block connections without VPN" -> locked()
        else -> error("Unknown test VPN policy: $title")
    }
    private fun toggle(title: String, enabled: Boolean) {
        if (policyState(title) == enabled) return
        for (attempt in 0 until 3) {
            // Settings can dismiss/rebuild its dialog after a VPN state change.
            // Reopen the identified test profile and verify the actual OS policy,
            // rather than reading a checkbox from a replaced accessibility tree.
            open()
            if (policyState(title) == enabled) return
            val control = row(title)
            if (control?.isEnabled != true || !control.performAction(AccessibilityNodeInfo.ACTION_CLICK)) continue
            repeat(30) {
                if (policyState(title) == enabled) return
                // AppDialog's positive button is Done. Only acknowledge the
                // actual ConfirmLockdownFragment prompt, never close the page.
                find {
                    it.viewIdResourceName == "android:id/button1" &&
                        it.text?.toString()?.lowercase() in setOf("turn on", "ok", "okay")
                }?.takeIf { it.isEnabled }?.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                Thread.sleep(100)
            }
        }
        error("OS VPN policy did not change: $title=$enabled; alwaysOn=${alwaysOn()}; lockdown=${locked()}")
    }
    fun enableLockdown() {
        check(alwaysOn() == null || alwaysOn() == context.packageName) { "Another always-on profile is configured" }
        open(); toggle("Always-on VPN", true); toggle("Block connections without VPN", true)
        waitFor("active lockdown") { alwaysOn() == context.packageName && locked() }
    }
    fun clearLockdown() {
        if (alwaysOn() == null) return
        check(alwaysOn() == context.packageName) { "Refusing to change another always-on profile" }
        open(); toggle("Block connections without VPN", false); toggle("Always-on VPN", false)
        waitFor("disabled lockdown") { alwaysOn() == null && !locked() }
    }
    fun forget() {
        check(alwaysOn() == null) { "Remove test lockdown before revoking this profile" }
        open()
        // The preference screen's heading can be present before its rows are
        // laid out. Wait for this action instead of dereferencing a stale root.
        waitFor("test profile Forget VPN action") {
            row("Forget VPN")?.takeIf { it.isEnabled }
                ?.performAction(AccessibilityNodeInfo.ACTION_CLICK) == true
        }
        // Android's VPN dialog labels its negative button "Forget" and its positive one "Done".
        waitFor("forget confirmation") {
            find { it.text?.toString()?.equals("Forget", ignoreCase = true) == true }
                ?.takeIf { it.isEnabled }?.performAction(AccessibilityNodeInfo.ACTION_CLICK) == true
        }
    }
    fun restoreTestConsent() {
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        check(android.net.VpnService.prepare(context) == null) { "Unable to restore disposable test VPN consent" }
    }
}
