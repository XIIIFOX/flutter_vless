package com.github.tfox.flutter_vless.xray.service

import android.content.Intent
import android.net.ConnectivityManager
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.os.ResultReceiver
import com.github.tfox.flutter_vless.xray.core.AuthenticatedSocksClient
import com.github.tfox.flutter_vless.xray.core.AndroidTunnelDnsPolicy
import com.github.tfox.flutter_vless.xray.core.LocalProxyCredentials
import com.github.tfox.flutter_vless.xray.core.LocalProxyAccessPolicy
import com.github.tfox.flutter_vless.xray.core.XrayCoreManager
import com.github.tfox.flutter_vless.xray.core.XrayDiagnosticsStore
import com.github.tfox.flutter_vless.xray.core.XrayDiagnosticsStore.Event
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import org.json.JSONObject
import java.io.File
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Owns the session and TUN. Worker failures never deactivate established protection. */
class XrayVPNService : VpnService() {
    private val worker = Executors.newSingleThreadScheduledExecutor()
    private val recovery = SessionRecoveryPolicy()
    private val requests = java.util.concurrent.atomic.AtomicLong()
    private var interfaceSignature: String? = null
    private var tun: ParcelFileDescriptor? = null
    private var process: Process? = null
    private var protector: XraySocketProtector? = null
    private var readinessProbe: SessionReadinessProbe? = null
    private var config: XrayConfig? = null
    private var sourceConfig: XrayConfig? = null
    private var prepared: JSONObject? = null
    private var dnsServers = listOf("8.8.8.8", "1.1.1.1")
    private var credentials: LocalProxyCredentials? = null
    private var tunConfigFile: File? = null
    private var socketFile: File? = null
    private var diagnosticsGeneration = 0L
    private var connectedAt = 0L
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private lateinit var profiles: AuthorizedProfileStore

    override fun onCreate() {
        super.onCreate()
        profiles = AuthorizedProfileStore(this)
        // Cold start cleanup must also run when authorization cannot be decrypted or is absent.
        // The helper preserves files referenced by live native workers and all standalone delays.
        worker.execute { SessionRuntimeFiles.removeAbandoned(noBackupFilesDir) }
        val manager = getSystemService(ConnectivityManager::class.java)
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = physicalLinkChanged()
            override fun onLost(network: Network) = physicalLinkChanged()
            private fun physicalLinkChanged() {
                worker.execute {
                    if (recovery.authorized && config != null && AppConfigs.V2RAY_STATE == AppConfigs.V2RAY_STATES.V2RAY_CONNECTED) recover(Event.RECOVERING)
                }
            }
        }
        networkCallback = callback
        manager.registerNetworkCallback(NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), callback)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_MEASURE_DELAY) {
            @Suppress("DEPRECATION")
            val receiver = intent.getParcelableExtra<ResultReceiver>("receiver")
            val url = intent.getStringExtra("url") ?: DEFAULT_DELAY_URL
            worker.execute {
                val result = runCatching {
                    check(recovery.authorized && AppConfigs.V2RAY_STATE == AppConfigs.V2RAY_STATES.V2RAY_CONNECTED)
                    AuthenticatedSocksClient.measure(requireNotNull(config).LOCAL_SOCKS5_PORT, credentials, url)
                }.getOrDefault(-1L)
                receiver?.send(0, Bundle().apply { putLong("delay", result) })
            }
            return if (recovery.authorized) START_STICKY else START_NOT_STICKY
        }
        @Suppress("DEPRECATION")
        val command = intent?.getSerializableExtra("COMMAND") as? AppConfigs.V2RAY_SERVICE_COMMANDS
        if (command == AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE) {
            val request = requests.incrementAndGet()
            profiles.disarm()
            recovery.disarm() // Invalidate queued callbacks immediately, before slow native I/O finishes.
            worker.execute {
                profiles.disarm(); deactivateSession()
                // A queued STOP releases its old session, but must not destroy a newer START.
                if (requests.get() == request) stopSelfResult(startId)
            }
            return START_NOT_STICKY
        }
        val request = requests.incrementAndGet()
        showForeground("Connecting; traffic protection is being prepared")
        worker.execute {
            @Suppress("DEPRECATION")
            val receiver = intent?.getParcelableExtra<ResultReceiver>("start_receiver")
            @Suppress("DEPRECATION")
            val incoming = if (command == AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE)
                (intent?.getSerializableExtra("V2RAY_CONFIG") as? XrayConfig)?.apply {
                    PROXY_ONLY = intent.getBooleanExtra("PROXY_ONLY", false)
                }
            else runCatching { profiles.load() }.getOrNull()
            if (incoming == null) {
                event(Event.PROFILE_UNAVAILABLE)
                receiver?.send(1, Bundle())
                if (request == requests.get() && tun == null && !recovery.authorized) {
                    XrayCoreManager.publishState(this, AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED)
                    stopForeground(STOP_FOREGROUND_REMOVE); stopSelfResult(startId)
                }
                return@execute
            }
            val accepted = runCatching { acceptSession(incoming, command == AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE, request) }
                .getOrElse { event(Event.CONFIG_REJECTED); false }
            receiver?.send(if (accepted) 0 else 1, Bundle())
            if (!accepted && request == requests.get() && tun == null && !recovery.authorized) {
                stopForeground(STOP_FOREGROUND_REMOVE); stopSelfResult(startId)
            }
        }
        return START_STICKY
    }

    private fun acceptSession(incoming: XrayConfig, explicit: Boolean, request: Long): Boolean {
        if (request != requests.get()) return false
        val candidate = incoming.copy(BLOCKED_APPS = ArrayList(incoming.BLOCKED_APPS), BYPASS_SUBNETS = ArrayList(incoming.BYPASS_SUBNETS))
        val secret = LocalProxyCredentials.generate()
        var candidateDnsServers = dnsServers
        val json = try {
            XrayCoreManager.validateConfiguration(candidate)
            val dns = AndroidTunnelDnsPolicy.prepare(candidate.V2RAY_FULL_JSON_CONFIG, candidate.ANDROID_DNS_POLICY,
                candidate.ANDROID_DNS_PROXY_OUTBOUND_TAG, candidate.BYPASS_SUBNETS) {
                XraySocketProtector.resolveBootstrapHostname(this, it)
            }
            candidate.V2RAY_FULL_JSON_CONFIG = dns.configJson
            candidateDnsServers = dns.systemDnsServers
            val runtime = XrayCoreManager.buildRuntimeConfigJson(candidate, noBackupFilesDir, secret)
            require(XrayCoreManager.validateNative(this, runtime)) { "Native configuration rejected" }
            if (!candidate.PROXY_ONLY) SessionReadinessProbe.selectHost(runtime)
            runtime
        } catch (_: Exception) {
            event(Event.CONFIG_REJECTED)
            return false
        }
        val candidateCredentials = try {
            if (candidate.PROXY_ONLY) LocalProxyAccessPolicy.credentialsForProxyOnly(json, candidate.LOCAL_SOCKS5_PORT) else secret
        } catch (_: Exception) { event(Event.CONFIG_REJECTED); return false }
        if (request != requests.get()) return false
        // This transaction precedes every mutation of the active workers and their profile.
        try { if (explicit) { if (candidate.PROXY_ONLY) profiles.disarm() else profiles.save(incoming) } }
        catch (_: Exception) { event(Event.PROFILE_SAVE_FAILED); return false }
        // Mode changes intentionally deactivate VPN protection; VPN-to-VPN replacements retain it.
        if (candidate.PROXY_ONLY && tun != null) { deactivateSession() }
        val owner = recovery.activate()
        if (!stopWorkers()) { event(Event.WORKER_START_FAILED); recover(Event.WORKER_START_FAILED); return false }
        SessionRuntimeFiles.removeAbandoned(noBackupFilesDir)
        diagnosticsGeneration = XrayDiagnosticsStore.reset(filesDir)
        // Delete only known legacy config names after the preceding native writers have exited.
        listOf("config.json", "temp_delay_config.json").forEach { File(filesDir, it).delete() }
        sourceConfig = incoming.copy()
        config = candidate; credentials = candidateCredentials
        prepared = json; dnsServers = candidateDnsServers
        event(Event.SESSION_START)
        worker.execute { restartWorkers(owner) }
        return true
    }

    private fun restartWorkers(owner: Long) {
        if (!recovery.owns(owner)) return
        XrayCoreManager.publishState(this, AppConfigs.V2RAY_STATES.V2RAY_CONNECTING)
        showForeground(if (tun != null) "Recovering; VPN traffic remains captured" else "Connecting")
        if (!stopWorkers()) { recover(Event.WORKER_START_FAILED); return }
        val current = config ?: return
        try {
            if (current.ANDROID_DNS_POLICY == "proxy" && recovery.failures > 0) {
                val source = requireNotNull(sourceConfig)
                val dns = AndroidTunnelDnsPolicy.prepare(source.V2RAY_FULL_JSON_CONFIG, source.ANDROID_DNS_POLICY,
                    source.ANDROID_DNS_PROXY_OUTBOUND_TAG, source.BYPASS_SUBNETS) {
                    XraySocketProtector.resolveBootstrapHostname(this, it)
                }
                current.V2RAY_FULL_JSON_CONFIG = dns.configJson
                prepared = XrayCoreManager.buildRuntimeConfigJson(current, noBackupFilesDir, credentials)
                dnsServers = dns.systemDnsServers
            }
            protector = if (current.PROXY_ONLY) null else XraySocketProtector(this).also {
                it.allowPhysicalDnsForEndpointNames(if (current.ANDROID_DNS_POLICY == "proxy") emptySet() else null)
            }
            val runtime = if (current.PROXY_ONLY) requireNotNull(prepared) else {
                SessionReadinessProbe(SessionReadinessProbe.selectHost(requireNotNull(prepared)))
                    .also { readinessProbe = it }.configure(requireNotNull(prepared))
            }
            val started = XrayCoreManager.startCore(this, current, runtime, protector, owner) { generation, code ->
                worker.execute { if (recovery.owns(generation)) { event(Event.WORKER_EXIT, code.toLong()); recover(Event.WORKER_EXIT) } }
            }
            if (!started) { recover(Event.PROTECT_FAILED); return }
            if (!recovery.owns(owner)) { stopWorkers(); return }
            if (!current.PROXY_ONLY) {
                // The broker was positively verified before TUN installation, including cold start.
                if (tun == null || interfaceSignature != interfaceSignature(current)) setupVpn(current)
                startTun2socks(current, requireNotNull(credentials), owner)
                if (!sendFd(owner)) { recover(Event.FD_FAILED); return }
                event(Event.FD_SENT)
            }
            if (!current.PROXY_ONLY) {
                try { probeAuthenticatedPath() }
                catch (_: Exception) { recover(Event.AUTH_PROBE_FAILED); return }
                // A real host-UID request traverses the captured TUN and authenticated tun2socks.
                // Explicit user app exclusions mean this cannot prove that path; do not claim it.
                if (!current.BLOCKED_APPS.contains(packageName)) {
                    try { requireNotNull(readinessProbe).verify() } catch (_: Exception) { recover(Event.PATH_PROBE_FAILED); return }
                }
            }
            if (!recovery.owns(owner)) return
            recovery.recovered()
            connectedAt = System.nanoTime()
            event(Event.CONNECTED)
            XrayCoreManager.publishState(this, AppConfigs.V2RAY_STATES.V2RAY_CONNECTED)
            showForeground("Connected")
            tick(owner, 0)
        } catch (_: Exception) { if (recovery.owns(owner)) recover(if (tun == null) Event.TUN_FAILED else Event.WORKER_START_FAILED) }
    }

    private fun setupVpn(current: XrayConfig) {
        val builder = Builder().setSession(current.REMARK).setMtu(1500).addAddress("26.26.26.1", 30).addRoute("0.0.0.0", 0)
        // No IPv6 address/route enables Android's default IPv6 blocking, never allowFamily bypass.
        if (Build.VERSION.SDK_INT >= 29) builder.setMetered(false)
        current.BLOCKED_APPS.forEach {
            try { builder.addDisallowedApplication(it) }
            catch (_: android.content.pm.PackageManager.NameNotFoundException) { /* An uninstalled exclusion has no UID to bypass. */ }
        }
        dnsServers.forEach { builder.addDnsServer(it) }
        val previous = tun
        tun = builder.establish() ?: error("TUN establishment denied")
        previous?.close()
        interfaceSignature = interfaceSignature(current)
        event(Event.TUN_ESTABLISHED)
    }

    private fun interfaceSignature(current: XrayConfig) = current.BLOCKED_APPS.sorted().joinToString("|") + ":" + current.ANDROID_DNS_POLICY

    private fun startTun2socks(current: XrayConfig, secret: LocalProxyCredentials, owner: Long) {
        val unique = UUID.randomUUID().toString()
        val file = File(noBackupFilesDir, "tun-$unique.yaml")
        // All values are generated native tokens or numeric fields. No secret appears in argv.
        file.writeText("proxy: 'socks5://${secret.username}:${secret.password}@127.0.0.1:${current.LOCAL_SOCKS5_PORT}'\nmtu: 1500\nloglevel: error\n")
        tunConfigFile = file
        val socket = File(noBackupFilesDir, "fd-${unique.take(12)}")
        socketFile = socket
        val child = ProcessBuilder(File(applicationInfo.nativeLibraryDir, "libtun2socks.so").absolutePath,
            "-sock-path", socket.absolutePath, "-config", file.absolutePath).directory(noBackupFilesDir).redirectErrorStream(true).start()
        process = child
        event(Event.WORKERS_START)
        Thread({
            runCatching { child.inputStream.use { val bytes = ByteArray(4096); while (it.read(bytes) >= 0) { } } }
            val code = runCatching { child.waitFor() }.getOrDefault(-1)
            worker.execute { if (recovery.owns(owner) && process === child) { event(Event.WORKER_EXIT, code.toLong()); recover(Event.WORKER_EXIT) } }
        }, "tun2socks-monitor").apply { isDaemon = true; start() }
    }

    private fun sendFd(owner: Long): Boolean {
        return FileDescriptorTransfer.send({ recovery.owns(owner) }, { process?.isAlive == true }, {
                LocalSocket().use { socket ->
                    socket.connect(LocalSocketAddress(requireNotNull(socketFile).absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))
                    socket.soTimeout = 1000
                    socket.setFileDescriptorsForSend(arrayOf(requireNotNull(tun).fileDescriptor))
                    socket.outputStream.write(32)
                    socket.setFileDescriptorsForSend(null)
                    socket.shutdownOutput()
                }
        })
    }

    private fun recover(reason: Event) {
        if (!recovery.authorized) return
        val next = recovery.restart() // Late callbacks from both workers lose ownership together.
        event(reason)
        stopWorkers() // TUN remains installed throughout backoff, including persistent failure.
        XrayCoreManager.publishState(this, AppConfigs.V2RAY_STATES.V2RAY_CONNECTING)
        val delay = recovery.nextDelayMillis()
        event(Event.RECOVERING, recovery.failures.toLong())
        showForeground(if (tun != null) "Recovering; VPN traffic remains captured" else "Waiting to establish VPN protection")
        worker.schedule({ restartWorkers(next) }, delay, TimeUnit.MILLISECONDS)
    }

    private fun tick(owner: Long, count: Int) {
        worker.schedule({
            if (!recovery.owns(owner)) return@schedule
            if (count > 0 && count % 30 == 0 && config?.PROXY_ONLY == false) {
                try { probeAuthenticatedPath() }
                catch (_: Exception) { recover(Event.AUTH_PROBE_FAILED); return@schedule }
                if (config?.BLOCKED_APPS?.contains(packageName) == false) {
                    try { requireNotNull(readinessProbe).verify() }
                    catch (_: Exception) { recover(Event.PATH_PROBE_FAILED); return@schedule }
                }
            }
            XrayCoreManager.publishState(this, AppConfigs.V2RAY_STATES.V2RAY_CONNECTED, (System.nanoTime() - connectedAt) / 1_000_000_000)
            tick(owner, count + 1)
        }, 1, TimeUnit.SECONDS)
    }

    private fun probeAuthenticatedPath() {
        val probe = requireNotNull(readinessProbe)
        probe.verify {
            AuthenticatedSocksClient.connect(requireNotNull(config).LOCAL_SOCKS5_PORT,
                requireNotNull(credentials), probe.host, probe.port)
        }
    }

    private fun stopWorkers(): Boolean {
        val child = process; process = null
        if (child != null) {
            child.destroy()
            if (!child.waitFor(1, TimeUnit.SECONDS)) child.destroyForcibly()
            if (!child.waitFor(1, TimeUnit.SECONDS)) { process = child; return false }
        }
        if (!XrayCoreManager.stopWorkers()) return false
        readinessProbe?.close(); readinessProbe = null
        protector?.close(); protector = null
        tunConfigFile?.delete(); tunConfigFile = null
        socketFile?.delete(); socketFile = null
        return true
    }

    private fun deactivateSession() {
        recovery.disarm()
        stopWorkers()
        runCatching { tun?.close() }; tun = null
        config = null; sourceConfig = null; prepared = null; credentials = null
        event(Event.SESSION_STOP)
        XrayCoreManager.publishState(this, AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED)
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    override fun onRevoke() {
        requests.incrementAndGet()
        profiles.disarm()
        recovery.disarm()
        worker.execute { deactivateSession(); stopSelf() }
        super.onRevoke()
    }
    override fun onDestroy() {
        requests.incrementAndGet()
        recovery.disarm()
        networkCallback?.let { runCatching { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) } }
        worker.execute { deactivateSession() }
        worker.shutdown()
        super.onDestroy()
    }

    private fun event(value: Event, number: Long? = null) = XrayDiagnosticsStore.event(filesDir, value,
        diagnosticsGeneration.takeIf { it > 0 }, number)

    private fun showForeground(content: String) {
        val id = "vpn_service_channel"
        if (Build.VERSION.SDK_INT >= 26) getSystemService(android.app.NotificationManager::class.java)
            .createNotificationChannel(android.app.NotificationChannel(id, "VPN Service", android.app.NotificationManager.IMPORTANCE_LOW))
        val builder = if (Build.VERSION.SDK_INT >= 26) android.app.Notification.Builder(this, id) else android.app.Notification.Builder(this)
        val current = config
        packageManager.getLaunchIntentForPackage(packageName)?.let { launch ->
            launch.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            builder.setContentIntent(android.app.PendingIntent.getActivity(this, 0, launch,
                android.app.PendingIntent.FLAG_IMMUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT))
        }
        val stop = android.app.PendingIntent.getService(this, 0,
            Intent(this, XrayVPNService::class.java).putExtra("COMMAND", AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE),
            android.app.PendingIntent.FLAG_IMMUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT)
        val notification = builder.setContentTitle(current?.REMARK?.takeIf { it.isNotBlank() } ?: "VPN Service").setContentText(content)
            .setSmallIcon(current?.APPLICATION_ICON?.takeIf { it != 0 } ?: android.R.drawable.ic_dialog_info)
            .addAction(android.app.Notification.Action.Builder(null, current?.NOTIFICATION_DISCONNECT_BUTTON_NAME ?: "Disconnect", stop).build())
            .setOngoing(true).build()
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, notification, 0x40000000) else startForeground(1, notification)
    }
    companion object {
        const val ACTION_MEASURE_DELAY = "com.github.tfox.flutter_vless.MEASURE_DELAY"
        private const val DEFAULT_DELAY_URL = "https://www.gstatic.com/generate_204"
    }
}
