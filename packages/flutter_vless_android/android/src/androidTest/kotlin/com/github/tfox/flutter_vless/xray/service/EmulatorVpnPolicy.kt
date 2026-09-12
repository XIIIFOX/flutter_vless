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
        error("OS VPN Settings did not reach $description")
    }
    private fun row(title: String): AccessibilityNodeInfo? {
        var node = find { it.text?.toString() == title } ?: return null
        while (!node.isClickable) node = node.parent ?: return null
        return node
    }
    private fun click(node: AccessibilityNodeInfo) {
        check(node.isEnabled && node.performAction(AccessibilityNodeInfo.ACTION_CLICK)) { "OS VPN control was unavailable" }
    }
    private fun open() {
        shell("am start -a android.settings.VPN_SETTINGS")
        fun alreadyOpen() = row("Always-on VPN") != null && find {
            it.contentDescription?.toString() == XrayVPNService::class.java.name
        } != null
        waitFor("test VPN entry") {
            alreadyOpen() || (find { it.text?.toString() == XrayVPNService::class.java.name } != null &&
                find { it.viewIdResourceName == "com.android.settings:id/settings_button" } != null)
        }
        if (alreadyOpen()) return
        val title = requireNotNull(find { it.text?.toString() == XrayVPNService::class.java.name })
        var parent = title.parent
        var gear: AccessibilityNodeInfo? = null
        while (parent != null && gear == null) {
            gear = nodes(parent).firstOrNull { it.viewIdResourceName == "com.android.settings:id/settings_button" }
            parent = parent.parent
        }
        click(requireNotNull(gear))
        waitFor("app policy page") { row("Always-on VPN") != null }
    }
    private fun checked(title: String) = nodes(row(title)).single { it.isCheckable }.isChecked
    private fun toggle(title: String, enabled: Boolean) {
        if (checked(title) == enabled) return
        click(requireNotNull(row(title)))
        // Settings can present the OS lockdown confirmation on the first enable.
        repeat(20) {
            find { it.viewIdResourceName == "android:id/button1" }?.let { click(it) }
            if (row(title) != null && checked(title) == enabled) return
            Thread.sleep(100)
        }
        error("OS VPN toggle did not change")
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
        open(); click(requireNotNull(row("Forget VPN")))
        // Android's VPN dialog labels its negative button "Forget" and its positive one "Done".
        waitFor("forget confirmation") { find { it.text?.toString()?.equals("Forget", ignoreCase = true) == true } != null }
        click(requireNotNull(find { it.text?.toString()?.equals("Forget", ignoreCase = true) == true }))
    }
    fun restoreTestConsent() {
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        check(android.net.VpnService.prepare(context) == null) { "Unable to restore disposable test VPN consent" }
    }
}
