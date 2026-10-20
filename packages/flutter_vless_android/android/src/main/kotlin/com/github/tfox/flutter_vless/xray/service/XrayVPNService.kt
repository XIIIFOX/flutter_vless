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
import com.github.tfox.flutter_vless.xray.core.XrayPortSpec
import com.github.tfox.flutter_vless.xray.core.NativeRuntimeConfig
import com.github.tfox.flutter_vless.xray.core.PreparationChanges
import com.github.tfox.flutter_vless.xray.core.PreparationStage
import com.github.tfox.flutter_vless.xray.core.StartupPreparationOutcome
import com.github.tfox.flutter_vless.xray.core.XrayDiagnosticsStore
import com.github.tfox.flutter_vless.xray.core.XrayDiagnosticsStore.Event
import com.github.tfox.flutter_vless.xray.core.StartupReadiness
import com.github.tfox.flutter_vless.xray.core.ReadinessFailure
import com.github.tfox.flutter_vless.xray.core.ReadinessStage
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import com.github.tfox.flutter_vless.NativeQuickAccess
import com.google.gson.Gson
import org.json.JSONObject
import java.io.File
import java.util.UUID
import java.util.concurrent.TimeUnit

/** Owns the session and TUN. Worker failures never deactivate established protection. */
class XrayVPNService : VpnService() {
    private val worker = SessionWorkQueue()
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
    private var routingPreparation: NativeRoutingPreparation? = null
    private var pendingRuntime: Pair<Long, SessionRuntimeCandidate<SessionReadinessProbe>>? = null
    // Guarded by recovery, so Stop can revoke an in-flight periodic check without
    // waiting for this service's serial worker. Only the owning phase clears it.
    private var periodicReadiness: Pair<Long, StartupReadiness>? = null
    private var dnsServers = listOf(AndroidTunnelDnsPolicy.VIRTUAL_SERVER)
    private var credentials: LocalProxyCredentials? = null
    private var tunConfigFile: File? = null
    private var socketFile: File? = null
    private var diagnosticsGeneration = 0L
    private var connectedAt = 0L
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private lateinit var profiles: AuthorizedProfileStore
    private var sessionOptions = NativeVlessOptions()
    @Volatile private var tileStartPending = false

    override fun onCreate() {
        super.onCreate()
        currentRecovery = recovery
        profiles = AuthorizedProfileStore(this)
        // Cold start cleanup must also run when authorization cannot be decrypted or is absent.
        // The helper preserves files referenced by live native workers and all standalone delays.
        worker.execute { SessionRuntimeFiles.removeAbandoned(noBackupFilesDir) }
        val manager = getSystemService(ConnectivityManager::class.java)
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = physicalLinkChanged()
            override fun onLost(network: Network) = physicalLinkChanged()
            private fun physicalLinkChanged() {
                // A queued physical-link event belongs to the session that received it.
                val owner = recovery.generation
                worker.execute {
                    if (recovery.owns(owner) && config != null && AppConfigs.V2RAY_STATE == AppConfigs.V2RAY_STATES.V2RAY_CONNECTED) recover(Event.RECOVERING)
                }
            }
        }
        networkCallback = callback
        manager.registerNetworkCallback(NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), callback)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (Build.VERSION.SDK_INT >= 29) {
            // Public getters are false before an active VPN network exists.
            // The readable OS lockdown bit plus current VPN consent identifies
            // this owner even during a cold sticky restart, without guessing
            // from preferences or another application's Always-on policy.
            val ownConfiguredLockdown = VpnService.prepare(this) == null && runCatching {
                android.provider.Settings.Secure.getInt(contentResolver, "always_on_vpn_lockdown", 0) == 1
            }.getOrDefault(false)
            AppConfigs.ALWAYS_ON_ENABLED = isAlwaysOn || ownConfiguredLockdown
            AppConfigs.LOCKDOWN_ENABLED = isLockdownEnabled || ownConfiguredLockdown
        }
        if (intent?.action == ACTION_QUERY_SYSTEM_STATE || intent?.action == ACTION_CLEAR_QUICK_ACCESS) {
            @Suppress("DEPRECATION")
            val receiver = intent.getParcelableExtra<ResultReceiver>("receiver")
            if (intent.action == ACTION_CLEAR_QUICK_ACCESS) worker.execute {
                NativeQuickAccess.profile(this).disarm()
                NativeQuickAccess.refresh(this)
                receiver?.send(0,Bundle())
            } else receiver?.send(0,Bundle().apply {
                putBoolean("alwaysOn",AppConfigs.ALWAYS_ON_ENABLED)
                putBoolean("lockdown",AppConfigs.LOCKDOWN_ENABLED)
            })
            if (requests.get() == 0L && !recovery.authorized && config == null) {
                worker.execute { if (requests.get() == 0L && !recovery.authorized) stopSelfResult(startId) }
            }
            return if (recovery.authorized) START_STICKY else START_NOT_STICKY
        }
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
        val suppliedCommand = intent?.getSerializableExtra("COMMAND") as? AppConfigs.V2RAY_SERVICE_COMMANDS
        val tileToggle = intent?.action == ACTION_QUICK_ACCESS_TOGGLE
        if (tileToggle && !QuickTilePolicy.mayToggle(NativeOptionsStore(this).read().quickAccess.enabled,
                recovery.authorized, tileStartPending,
                AppConfigs.V2RAY_STATE != AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED,
                VpnService.prepare(this) == null)) {
            if (!recovery.authorized && requests.get() == 0L) stopSelfResult(startId)
            return if (recovery.authorized) START_STICKY else START_NOT_STICKY
        }
        val command = if (tileToggle) {
            if (recovery.authorized) AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE else AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE
        } else suppliedCommand
        if (command == AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE) {
            @Suppress("DEPRECATION")
            val receiver = intent?.getParcelableExtra<ResultReceiver>("stop_receiver")
            if (AppConfigs.ALWAYS_ON_ENABLED || AppConfigs.LOCKDOWN_ENABLED) {
                receiver?.send(2,Bundle())
                return START_STICKY
            }
            val request = requests.incrementAndGet()
            disarmRecovery() // Invalidate callbacks and release owned health I/O before queued cleanup.
            NativeQuickAccess.refresh(this)
            profiles.disarm()
            worker.execute {
                profiles.disarm(); deactivateSession()
                receiver?.send(0,Bundle())
                // A queued STOP releases its old session, but must not destroy a newer START.
                if (requests.get() == request) stopSelfResult(startId)
            }
            return START_NOT_STICKY
        }
        // Android sends this action when starting its configured Always-on owner.
        // Before establish(), isAlwaysOn can be false because no VPN network exists.
        // The service is non-exported and protected by BIND_VPN_SERVICE.
        val systemAlwaysOnStart = intent?.action == SERVICE_INTERFACE && suppliedCommand == null
        val request = requests.incrementAndGet()
        if (tileToggle) tileStartPending = true
        showForeground("Connecting; traffic protection is being prepared")
        worker.execute {
            val outcome = StartupPreparationOutcome()
            @Suppress("DEPRECATION")
            val receiver = intent?.getParcelableExtra<ResultReceiver>("start_receiver")
            @Suppress("DEPRECATION")
            val incoming = if (tileToggle) runCatching {
                NativeQuickAccess.profile(this).load().also { saved ->
                    require(!saved.PROXY_ONLY)
                    saved.PLUGIN_OPTIONS_JSON = Gson().toJson(NativeOptionsStore(this).read())
                    saved.APPLICATION_ICON = resources.getIdentifier(saved.NOTIFICATION_ICON_RESOURCE_NAME,
                        saved.NOTIFICATION_ICON_RESOURCE_TYPE,packageName)
                }
            }.getOrElse { NativeQuickAccess.profile(this).disarm(); null }
            else if (command == AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE)
                (intent?.getSerializableExtra("V2RAY_CONFIG") as? XrayConfig)?.apply {
                    PROXY_ONLY = intent.getBooleanExtra("PROXY_ONLY", false)
                }
            else runCatching { profiles.load() }.getOrNull()
            val restoreDisabled = command == null && incoming != null && !AppConfigs.ALWAYS_ON_ENABLED && !systemAlwaysOnStart && runCatching {
                val raw = incoming.PLUGIN_OPTIONS_JSON?.let { Gson().fromJson(it,Map::class.java) }
                !(if (raw == null) NativeOptionsStore(this).read() else NativeVlessOptions.parse(raw)).reconnect.enabled
            }.getOrDefault(true)
            if (restoreDisabled) profiles.disarm()
            if (incoming == null || restoreDisabled) {
                tileStartPending = false
                NativeQuickAccess.refresh(this)
                event(Event.PROFILE_UNAVAILABLE)
                receiver?.send(1, outcome.toBundle(false))
                if (request == requests.get() && tun == null && !recovery.authorized) {
                    XrayCoreManager.publishState(this, AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED)
                    stopForeground(STOP_FOREGROUND_REMOVE); stopSelfResult(startId)
                }
                return@execute
            }
            val accepted = runCatching { acceptSession(incoming, command == AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE, request, systemAlwaysOnStart, outcome) }
                .getOrElse { event(Event.CONFIG_REJECTED); false }
            if (tileToggle && accepted) XrayCoreManager.publishState(this,AppConfigs.V2RAY_STATES.V2RAY_CONNECTING)
            tileStartPending = false
            receiver?.send(if (accepted) 0 else 1, outcome.toBundle(accepted))
            if (!accepted && request == requests.get() && tun == null && !recovery.authorized) {
                stopForeground(STOP_FOREGROUND_REMOVE); stopSelfResult(startId)
            }
        }
        return START_STICKY
    }

    private fun acceptSession(incoming: XrayConfig, explicit: Boolean, request: Long, systemAlwaysOnStart: Boolean,
                              outcome: StartupPreparationOutcome): Boolean {
        if (request != requests.get()) return false
        val options = try {
            val parsed = incoming.PLUGIN_OPTIONS_JSON?.let { Gson().fromJson(it,Map::class.java) }
            (if (parsed == null) NativeOptionsStore(this).read() else NativeVlessOptions.parse(parsed)).also {
                it.validateAndroid(Build.VERSION.SDK_INT)
                require(incoming.PROXY_ONLY || it.protection.alwaysOn != "requireEnabled" || AppConfigs.ALWAYS_ON_ENABLED || systemAlwaysOnStart)
            }
        } catch (_: Exception) { event(Event.CONFIG_REJECTED); return false }
        val candidate = incoming.copy(BLOCKED_APPS = ArrayList(incoming.BLOCKED_APPS), BYPASS_SUBNETS = ArrayList(incoming.BYPASS_SUBNETS))
        val secret = LocalProxyCredentials.generate()
        val changes = PreparationChanges()
        var candidateDnsServers = dnsServers
        var candidateRouting: NativeRoutingPreparation? = null
        val (json, finalCandidate, candidateCredentials) = try {
            XrayCoreManager.validateConfiguration(candidate)
            if (candidate.VPN_ROUTING_SELECTION_JSON != null)
                require(XrayCoreManager.supportsNativeRouting(this)) { "Native VPN routing is unavailable" }
            if (request != requests.get()) return false
            val dns = if (candidate.PROXY_ONLY) null else AndroidTunnelDnsPolicy.prepare(candidate.V2RAY_FULL_JSON_CONFIG, candidate.ANDROID_DNS_POLICY,
                candidate.ANDROID_DNS_PROXY_OUTBOUND_TAG, candidate.BYPASS_SUBNETS, changes = changes) {
                XraySocketProtector.resolveBootstrapHostname(this, it)
            }
            if (dns != null) {
                candidate.V2RAY_FULL_JSON_CONFIG = dns.configJson
                candidateDnsServers = dns.systemDnsServers
            }
            val runtime = XrayCoreManager.buildRuntimeConfigJson(candidate, noBackupFilesDir, secret, dns,
                routingPrepared = { candidateRouting=it },
                changes = changes,
                tcpAvailable = if (candidate.PROXY_ONLY) null else XrayCoreManager::tcpListenerAvailable)
            val localCredentials = if (candidate.PROXY_ONLY)
                LocalProxyAccessPolicy.credentialsForProxyOnly(runtime, candidate.LOCAL_SOCKS5_PORT) else secret
            // The candidate probe/rule belong to this request. Final native
            // preflight happens before profiles, generations or active workers change.
            Triple(runtime, finalizeRuntime(candidate, runtime, candidateRouting, secret.username, capabilityChecked=true,
                changes = changes, outcome = outcome), localCredentials)
        } catch (_: Exception) {
            event(Event.CONFIG_REJECTED)
            return false
        }
        val admitted = finalCandidate.admit(isCurrent = { request == requests.get() }, persist = {
            outcome.stage = PreparationStage.PERSIST
            try { if (explicit) { if (candidate.PROXY_ONLY) profiles.disarm() else profiles.save(incoming) } }
            catch (error: Exception) { event(Event.PROFILE_SAVE_FAILED); throw error }
            outcome.stage = PreparationStage.PREPARE
        }, commit = { accepted ->
            outcome.stage = PreparationStage.START
            // Mode changes intentionally deactivate VPN protection; VPN-to-VPN replacements retain it.
            if (candidate.PROXY_ONLY && tun != null) deactivateSession()
            val owner = recovery.activate()
            recovery.options = options.reconnect
            sessionOptions = options
            if (!stopWorkers()) {
                closePendingRuntime()
                event(Event.WORKER_START_FAILED); recover(Event.WORKER_START_FAILED)
                false
            } else {
                closePendingRuntime()
                SessionRuntimeFiles.removeAbandoned(noBackupFilesDir)
                diagnosticsGeneration = XrayDiagnosticsStore.reset(filesDir)
                listOf("config.json", "temp_delay_config.json").forEach { File(filesDir, it).delete() }
                sourceConfig = incoming.copy()
                config = candidate; credentials = candidateCredentials
                AppConfigs.V2RAY_CONFIG = candidate
                XrayDiagnosticsStore.configure(filesDir,NativeOptionsStore(this).read().diagnostics)
                if (explicit) {
                    runCatching {
                        val retained = NativeQuickAccess.profile(this)
                        if (NativeOptionsStore(this).read().quickAccess.enabled && !candidate.PROXY_ONLY) retained.save(incoming)
                        else retained.disarm()
                    }.onFailure { NativeQuickAccess.profile(this).disarm() }
                    NativeQuickAccess.refresh(this)
                }
                prepared = json; dnsServers = candidateDnsServers; routingPreparation = candidateRouting
                // Keep this separate from active readinessProbe: the queued first
                // restart still drains old workers before adopting the new probe.
                pendingRuntime = owner to accepted
                event(Event.SESSION_START)
                worker.execute { restartWorkers(owner) }
                true
            }
        })
        if (admitted) outcome.report = finalCandidate.preparationReport
        return admitted
    }

    private fun finalizeRuntime(current: XrayConfig, base: JSONObject,
                                routing: NativeRoutingPreparation? = routingPreparation,
                                authUser: String = credentials?.username.orEmpty(), capabilityChecked: Boolean = false,
                                changes: PreparationChanges? = null, outcome: StartupPreparationOutcome? = null): SessionRuntimeCandidate<SessionReadinessProbe> {
        if (current.VPN_ROUTING_SELECTION_JSON != null) {
            requireNotNull(routing) { "Native VPN routing preparation unavailable" }
            if (!capabilityChecked) require(XrayCoreManager.supportsNativeRouting(this)) { "Native VPN routing unavailable" }
        }
        return SessionRuntimeCandidate.prepare(
            base, createProbe = { if (current.PROXY_ONLY) null else createReadinessProbe(base) },
            configure = { probe, json -> probe.configure(json, current.LOCAL_SOCKS5_PORT) },
            validate = { final ->
                outcome?.stage = PreparationStage.CORE_CHECK
                XrayCoreManager.validateNative(this, final, current.GEO_ASSETS_DIRECTORY)
            },
            freeze = { final -> routing?.freeze(final, authUser) ?: NativeRuntimeConfig.freeze(final) },
            changes = changes).also { outcome?.stage = PreparationStage.PREPARE }
    }

    /** Test seam supplies an inert probe; normal startup still uses the existing owned listener. */
    internal fun createReadinessProbe(base: JSONObject): SessionReadinessProbe {
        val excluded = XrayPortSpec.serviceListenerPorts(base).toMutableSet()
        base.optJSONArray("inbounds")?.let { inputs ->
            for (index in 0 until inputs.length()) {
                val input = inputs.getJSONObject(index)
                if (!XrayPortSpec.isUnixListen(input.optString("listen")) && input.has("port"))
                    excluded.addAll(XrayPortSpec.reservedPorts(input.get("port")))
            }
        }
        return SessionReadinessProbe(SessionReadinessProbe.selectHost(base), excluded)
    }

    private fun closePendingRuntime() {
        pendingRuntime?.second?.close()
        pendingRuntime = null
    }

    private fun takePendingRuntime(owner: Long): SessionRuntimeCandidate<SessionReadinessProbe>? {
        val pending = pendingRuntime ?: return null
        if (pending.first != owner) { closePendingRuntime(); return null }
        pendingRuntime = null
        return pending.second
    }

    private fun restartWorkers(owner: Long) {
        if (!recovery.owns(owner)) return
        XrayCoreManager.publishState(this, AppConfigs.V2RAY_STATES.V2RAY_CONNECTING)
        showForeground(if (tun != null) "Recovering; VPN traffic remains captured" else "Connecting")
        if (!stopWorkers()) { closePendingRuntime(); recover(Event.WORKER_START_FAILED); return }
        val current = config ?: return
        var candidate: SessionRuntimeCandidate<SessionReadinessProbe>? = null
        try {
            if (current.ANDROID_DNS_POLICY == "proxy" && recovery.failures > 0) {
                val source = requireNotNull(sourceConfig)
                val dns = AndroidTunnelDnsPolicy.prepare(source.V2RAY_FULL_JSON_CONFIG, source.ANDROID_DNS_POLICY,
                    source.ANDROID_DNS_PROXY_OUTBOUND_TAG, source.BYPASS_SUBNETS) {
                    XraySocketProtector.resolveBootstrapHostname(this, it)
                }
                current.V2RAY_FULL_JSON_CONFIG = dns.configJson
                prepared = XrayCoreManager.buildRuntimeConfigJson(current, noBackupFilesDir, credentials, dns,
                    routingPrepared = { routingPreparation=it })
                dnsServers = dns.systemDnsServers
            }
            candidate = takePendingRuntime(owner) ?: finalizeRuntime(current, requireNotNull(prepared))
            // A STOP/new generation during slow native Check cannot adopt this probe or start Core.
            if (!recovery.owns(owner)) return
            protector = if (current.PROXY_ONLY) null else XraySocketProtector(this).also {
                it.allowPhysicalDnsForEndpointNames(if (current.ANDROID_DNS_POLICY == "proxy") emptySet() else null)
            }
            if (!recovery.owns(owner)) { stopWorkers(); return }
            val runtime = candidate.configuration
            readinessProbe = candidate.takeProbe()
            candidate.close(); candidate = null
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
                try { probeAuthenticatedPath(owner) }
                catch (error: Exception) {
                    val stage = (error as? ReadinessFailure)?.stage
                    recover(if (stage == ReadinessStage.PACKET_CHALLENGE) Event.PATH_PROBE_FAILED else Event.AUTH_PROBE_FAILED,
                        (error as? ReadinessFailure)?.diagnosticValue)
                    return
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
        finally { candidate?.close() }
    }

    private fun setupVpn(current: XrayConfig) {
        val builder = Builder().setSession(current.REMARK).setMtu(1500)
            .addAddress("26.26.26.1", 30).addRoute("0.0.0.0", 0)
            .addAddress("fd26:26:26::1", 126).addRoute("::", 0)
        // Capture both families. allowFamily would permit application bypass;
        // only Core's existing protected sockets follow caller egress policy.
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

    private fun recover(reason: Event, detail: Long? = null) {
        if (!recovery.authorized) return
        val next = recovery.restart() // Late callbacks from both workers lose ownership together.
        event(reason, detail)
        stopWorkers() // TUN remains installed throughout backoff, including persistent failure.
        if (!recovery.mayRetry()) {
            XrayCoreManager.publishState(this,AppConfigs.V2RAY_STATES.V2RAY_CONNECTING)
            showForeground("Connection failed; protection remains active. Retry from the app")
            return
        }
        XrayCoreManager.publishState(this, AppConfigs.V2RAY_STATES.V2RAY_CONNECTING)
        val delay = recovery.nextDelayMillis()
        event(Event.RECOVERING, recovery.failures.toLong())
        showForeground(if (tun != null) "Recovering; VPN traffic remains captured" else "Waiting to establish VPN protection")
        worker.schedule({ restartWorkers(next) }, delay, TimeUnit.MILLISECONDS)
    }

    private fun tick(owner: Long, count: Int) {
        worker.schedule({
            if (!recovery.owns(owner)) return@schedule
            var checkedChild: Process? = null
            if (count > 0 && count % 30 == 0 && config?.PROXY_ONLY == false) {
                val expectedChild = XrayCoreManager.currentCoreProcess()
                try { checkedChild = checkAuthenticatedPath(owner, periodic = true) }
                catch (error: Exception) {
                    // Replacement revokes this result, but death of this same
                    // child must still enter the existing recovery policy.
                    if (!recovery.owns(owner) || XrayCoreManager.currentCoreProcess() !== expectedChild) return@schedule
                    recover(if (error is ReadinessFailure && error.stage == ReadinessStage.PACKET_CHALLENGE)
                        Event.PATH_PROBE_FAILED else Event.AUTH_PROBE_FAILED,
                        (error as? ReadinessFailure)?.diagnosticValue)
                    return@schedule
                }
                if (checkedChild !== expectedChild) return@schedule
            }
            fun healthOwnerCurrent(): Boolean {
                if (!recovery.owns(owner)) return false
                val child = checkedChild ?: return true
                if (XrayCoreManager.currentCoreProcess() !== child) return false
                if (child.isAlive) return true
                // The checked child may exit after the helper's final check or
                // during publication. Keep its recovery chain alive at both edges.
                if (recovery.owns(owner) && XrayCoreManager.currentCoreProcess() === child)
                    recover(Event.AUTH_PROBE_FAILED, ReadinessFailure(ReadinessStage.OWNER).diagnosticValue)
                return false
            }
            if (!healthOwnerCurrent()) return@schedule
            XrayCoreManager.publishState(this, AppConfigs.V2RAY_STATES.V2RAY_CONNECTED, (System.nanoTime() - connectedAt) / 1_000_000_000)
            if (healthOwnerCurrent()) tick(owner, count + 1)
        }, 1, TimeUnit.SECONDS)
    }

    private fun probeAuthenticatedPath(owner: Long) {
        checkAuthenticatedPath(owner, periodic = false)
    }

    private fun checkAuthenticatedPath(owner: Long, periodic: Boolean): Process {
        if (!recovery.owns(owner)) throw ReadinessFailure(ReadinessStage.OWNER)
        val child = XrayCoreManager.currentCoreProcess() ?: throw ReadinessFailure(ReadinessStage.OWNER)
        if (!XrayCoreManager.ownsCoreProcess(child)) throw ReadinessFailure(ReadinessStage.OWNER)
        try {
            StartupReadiness(isCurrent = { recovery.owns(owner) && XrayCoreManager.ownsCoreProcess(child) }).use { readiness ->
                val phase = owner to readiness
                if (periodic) synchronized(recovery) {
                    if (!recovery.owns(owner)) throw ReadinessFailure(ReadinessStage.OWNER)
                    periodicReadiness = phase
                }
                try {
                    // Startup alone retries an exact local ECONNREFUSED. An established
                    // session's health check remains one attempt within the same budget.
                    if (periodic) probeAuthenticatedPathOnce(readiness)
                    else readiness.authenticated { probeAuthenticatedPathOnce(readiness) }
                    readiness.check()
                    // A real host-UID token also traverses TUN and the forwarder. An
                    // explicit app exclusion cannot qualify that packet path.
                    if (config?.BLOCKED_APPS?.contains(packageName) == false)
                        requireNotNull(readinessProbe).verify(readiness, ReadinessStage.PACKET_CHALLENGE)
                    readiness.check()
                } finally {
                    if (periodic) synchronized(recovery) {
                        if (periodicReadiness === phase && periodicReadiness?.first == owner) periodicReadiness = null
                    }
                }
            }
        } catch (error: Exception) {
            // A stored deadline/cleanup failure must not authorize recovery of a
            // child that replaced this phase's exact Core identity.
            if (!recovery.owns(owner) || XrayCoreManager.currentCoreProcess() !== child) throw ReadinessFailure(ReadinessStage.OWNER)
            throw error
        }
        if (!recovery.owns(owner) || !XrayCoreManager.ownsCoreProcess(child)) throw ReadinessFailure(ReadinessStage.OWNER)
        return child
    }

    private fun disarmRecovery() {
        val phase = synchronized(recovery) {
            recovery.disarm()
            periodicReadiness?.second.also { periodicReadiness = null }
        }
        // Socket close and timer draining must never hold the ownership monitor.
        phase?.cancel()
    }

    private fun probeAuthenticatedPathOnce(readiness: StartupReadiness? = null) {
        val probe = requireNotNull(readinessProbe)
        probe.verify(readiness, ReadinessStage.PRIVATE_CHALLENGE) {
            AuthenticatedSocksClient.connect(requireNotNull(config).LOCAL_SOCKS5_PORT,
                requireNotNull(credentials), probe.host, probe.port, readiness)
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
        disarmRecovery()
        try { closePendingRuntime() }
        finally {
            stopWorkers()
            runCatching { tun?.close() }; tun = null
            config = null; sourceConfig = null; prepared = null; routingPreparation = null; credentials = null
            event(Event.SESSION_STOP)
            XrayCoreManager.publishState(this, AppConfigs.V2RAY_STATES.V2RAY_DISCONNECTED)
            stopForeground(STOP_FOREGROUND_REMOVE)
        }
    }

    override fun onRevoke() {
        requests.incrementAndGet()
        profiles.disarm()
        NativeQuickAccess.profile(this).disarm()
        NativeQuickAccess.refresh(this)
        disarmRecovery()
        worker.execute { deactivateSession(); stopSelf() }
        super.onRevoke()
    }
    override fun onDestroy() {
        requests.incrementAndGet()
        disarmRecovery()
        if (currentRecovery === recovery) currentRecovery = null
        networkCallback?.let { runCatching { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) } }
        worker.close { deactivateSession() }
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
        builder.setContentTitle(current?.REMARK?.takeIf { it.isNotBlank() } ?: "VPN Service").setContentText(content)
            .setSmallIcon(current?.APPLICATION_ICON?.takeIf { it != 0 } ?: android.R.drawable.ic_dialog_info)
            .setOngoing(true)
        val label = current?.NOTIFICATION_DISCONNECT_BUTTON_NAME ?: sessionOptions.notification.buttonLabel
        if (sessionOptions.notification.action == "disconnect" && !AppConfigs.ALWAYS_ON_ENABLED && !AppConfigs.LOCKDOWN_ENABLED) {
            builder.addAction(android.app.Notification.Action.Builder(null,label,stop).build())
        } else if (sessionOptions.notification.action == "openApp") {
            packageManager.getLaunchIntentForPackage(packageName)?.let { launch ->
                val open = android.app.PendingIntent.getActivity(this,25,launch,android.app.PendingIntent.FLAG_IMMUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT)
                builder.addAction(android.app.Notification.Action.Builder(null,label,open).build())
            }
        }
        val notification = builder.build()
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, notification, 0x40000000) else startForeground(1, notification)
    }
    companion object {
        // The tile shares this native process. Expose the authoritative accepted
        // session without retaining a Service/Context or treating saved profiles
        // as authorization for an automatic restart.
        @Volatile private var currentRecovery: SessionRecoveryPolicy? = null
        internal fun hasAcceptedSession() = currentRecovery?.authorized == true
        const val ACTION_QUERY_SYSTEM_STATE = "com.github.tfox.flutter_vless.QUERY_SYSTEM_STATE"
        const val ACTION_CLEAR_QUICK_ACCESS = "com.github.tfox.flutter_vless.CLEAR_QUICK_ACCESS"
        const val ACTION_QUICK_ACCESS_TOGGLE = "com.github.tfox.flutter_vless.QUICK_ACCESS_TOGGLE"
        const val ACTION_MEASURE_DELAY = "com.github.tfox.flutter_vless.MEASURE_DELAY"
        private const val DEFAULT_DELAY_URL = "https://www.gstatic.com/generate_204"
    }
}
