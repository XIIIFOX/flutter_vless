package com.github.tfox.flutter_vless.xray.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.RouteInfo
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.os.ResultReceiver
import com.github.tfox.flutter_vless.xray.core.AuthenticatedSocksClient
import java.io.Closeable
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/** Explicit debug-only controlled IPv4/TCP preview. Never a production service fallback. */
class NativePreviewVpnService : VpnService() {
    private val worker = SessionWorkQueue()
    private val requests = AtomicLong()
    private val admission = Any()
    private val unavailable = ConcurrentHashMap.newKeySet<Network>()
    @Volatile private var authorized = false
    @Volatile private var generation: NativePreviewNetworkGeneration? = null
    @Volatile private var captured: Network? = null
    @Volatile private var accepted: NativePreviewVpnInput? = null
    @Volatile private var active: Session? = null
    private val retiring = mutableListOf<Session>() // Failed drains retain their exact owned processes/files.
    private var tun: ParcelFileDescriptor? = null
    private var browserScope = false
    private var state = "IDLE"
    private var reason = "none"
    private var callback: ConnectivityManager.NetworkCallback? = null
    private val manager by lazy { getSystemService(ConnectivityManager::class.java) }

    private inner class Session(val spec: NativePreviewVpnSpec) : Closeable {
        var broker: XraySocketProtector? = null
        @Volatile var core: NativePreviewProcessOwner? = null
        @Volatile var forwarder: NativePreviewForwarderOwner? = null
        private var brokerClosed = false
        private var filesClosed = false
        override fun close() {
            spec.generation.revoke()
            var primary: Throwable? = null
            fun attempt(action: () -> Unit): Boolean = try { action(); true } catch (error: Throwable) {
                if (primary == null) primary = error else primary!!.addSuppressed(error)
                false
            }
            forwarder?.let { child -> if (attempt { child.close() }) forwarder = null }
            core?.let { child ->
                attempt { if (child.isAlive) child.stop() }
                if (attempt { child.close() }) core = null
            }
            if (!brokerClosed) brokerClosed = attempt { broker?.let { it.close(); check(it.awaitClosed()) { "broker-not-drained" } } }
            // Never delete executable inputs/socket paths while an owned child
            // or broker could still use them. Failed ownership stays retained.
            if (!filesClosed && core == null && forwarder == null && brokerClosed)
                filesClosed = attempt { spec.close() }
            primary?.let { throw it }
        }
    }

    override fun onCreate() {
        super.onCreate()
        foreground()
        callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) { unavailable.remove(network); changed(network, false) }
            override fun onLost(network: Network) { unavailable.add(network); changed(network, true) }
            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) { changed(network, false) }
        }.also {
            manager.registerNetworkCallback(NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), it)
        }
    }

    private fun selectNetwork(): Network? {
        val fixture = InetAddress.getByAddress(byteArrayOf(10, 0, 2, 2))
        fun eligible(network: Network): Boolean {
            val caps = manager.getNetworkCapabilities(network) ?: return false
            val links = manager.getLinkProperties(network) ?: return false
            return network !in unavailable && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                links.linkAddresses.any { it.address is Inet4Address } && links.routes.any {
                    it.type == RouteInfo.RTN_UNICAST && it.destination.address is Inet4Address && it.matches(fixture)
                }
        }
        manager.activeNetwork?.takeIf(::eligible)?.let { return it }
        // While this UID's active network is our VPN, this is an explicit
        // preview preference, not a claim to observe the OS physical default.
        return manager.allNetworks.filter(::eligible).sortedWith(compareByDescending<Network> {
            manager.getNetworkCapabilities(it)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
        }.thenByDescending {
            manager.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        }).firstOrNull()
    }

    private fun changed(network: Network, lost: Boolean) {
        val selected = selectNetwork()
        val change = synchronized(admission) {
            val owner = active
            if (!authorized || accepted == null) return
            if (owner == null && selected == null) return
            val current = owner?.spec?.network
            if (!(lost && network == current) && selected == current) return
            Pair(owner, requests.incrementAndGet())
        }
        // Revocation happens on the callback, ahead of any slow queued native work.
        change.first?.spec?.generation?.revoke()
        val request = change.second
        worker.execute {
            if (authorized && request == requests.get()) restart(request, "network-change")
        }
    }

    @Suppress("DEPRECATION")
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val receiver = intent?.getParcelableExtra<ResultReceiver>("receiver")
        when (intent?.action) {
            START -> {
                val request = synchronized(admission) { requests.incrementAndGet() }
                worker.execute {
                    val incoming = runCatching { NativePreviewVpnInput.fromIntent(this, intent) }.getOrNull()
                    val ready = incoming != null && accept(incoming, request)
                    receiver?.send(if (ready) 0 else 1, snapshot())
                }
            }
            STOP -> {
                val gate = synchronized(admission) { requests.incrementAndGet(); authorized = false; generation }
                gate?.revoke()
                worker.execute {
                    val clean = stopOwned(true)
                    accepted = null; captured = null; generation = null
                    state = if (clean) "STOPPED" else "FAILED"; reason = if (clean) "explicit-stop" else "cleanup"
                    receiver?.send(if (clean) 0 else 1, snapshot())
                    if (clean) { stopForeground(STOP_FOREGROUND_REMOVE); stopSelfResult(startId) }
                    else foreground() // Retain failed ownership for an explicit bounded Stop retry.
                }
            }
            STATE -> worker.execute { receiver?.send(0, snapshot()) }
            KILL_OWNED -> worker.execute {
                when (intent.getStringExtra("child")) {
                    "core" -> active?.core?.forceForTest()
                    "forwarder" -> active?.forwarder?.forceForTest()
                }
                receiver?.send(0, snapshot())
            }
            else -> worker.execute { receiver?.send(1, snapshot()) }
        }
        return START_NOT_STICKY
    }

    private fun newCandidate(input: NativePreviewVpnInput, network: Network): Session {
        val session = Session(NativePreviewVpnSpec.create(this, input, network))
        try {
            session.broker = XraySocketProtector.forNumericPreview(this, network, session.spec.generation)
            return session
        } catch (error: Throwable) {
            if (!retire(session)) { state = "FAILED"; reason = "cleanup" }
            throw error
        }
    }

    private fun preflight(session: Session) {
        val child = NativePreviewProcessOwner(session.spec)
        session.core = child // Adopt before spawn, pipe submission, await or monitor construction.
        child.launch("check")
        child.prepared()
        child.close()
        session.core = null
    }

    private fun retire(session: Session): Boolean {
        session.spec.generation.revoke()
        if (session !in retiring) retiring.add(session)
        return drainRetiring()
    }

    private fun accept(input: NativePreviewVpnInput, request: Long): Boolean {
        val network = selectNetwork() ?: return false
        var candidate: Session? = null
        try {
            check(retiring.isEmpty()) { "preview-retiring-owner" }
            check(VpnService.prepare(this) == null)
            candidate = newCandidate(input, network)
            // Pure native admission occurs before touching the accepted owner/TUN.
            preflight(candidate)
            if (request != requests.get()) return false
            generation?.revoke()
            check(stopOwned(false))
            synchronized(admission) {
                if (request != requests.get()) return false
                authorized = true; accepted = input
            }
            val committed = candidate
            candidate = null
            return launch(committed, request)
        } catch (_: Throwable) {
            if (active == null) { state = "FAILED"; reason = "candidate" }
            return false
        } finally {
            candidate?.let { if (!retire(it)) { state = "FAILED"; reason = "cleanup" } }
        }
    }

    private fun restart(request: Long, why: String) {
        if (!authorized || request != requests.get()) return
        state = "RECOVERING"; reason = why
        if (!stopOwned(false)) { state = "FAILED"; reason = "cleanup"; return }
        val input = accepted ?: return
        val network = selectNetwork()
        if (network == null) {
            captured = null
            if (tun != null) setUnderlyingNetworks(emptyArray())
            state = "WAITING_NETWORK"
            return
        }
        var candidate: Session? = null
        try {
            candidate = newCandidate(input, network)
            preflight(candidate)
            if (!authorized || request != requests.get()) return
            val committed = candidate; candidate = null
            launch(committed, request)
        } catch (_: Throwable) { state = "FAILED"; reason = "restart" }
        finally { candidate?.let { if (!retire(it)) { state = "FAILED"; reason = "cleanup" } } }
    }

    private fun owns(spec: NativePreviewVpnSpec, request: Long) = authorized && requests.get() == request &&
        generation === spec.generation && spec.generation.isCurrent()

    private fun launch(owned: Session, request: Long): Boolean {
        val spec = owned.spec
        try {
            check(retiring.isEmpty()) { "preview-retiring-owner" }
            state = "PREPARING"; reason = "none"
            val broker = requireNotNull(owned.broker)
            synchronized(admission) {
                check(authorized && request == requests.get())
                captured = spec.network; generation = spec.generation; active = owned
            }
            val core = NativePreviewProcessOwner(spec)
            owned.core = core
            spec.reservation.close() // The unavoidable release-to-Core.bind handoff is immediate.
            core.launch("run", broker)
            core.started(broker) { child -> lost(child, null) }
            check(owns(spec, request))
            // Numeric and controlled: no changes to source routing/hosts/DNS for readiness.
            check(AuthenticatedSocksClient.measure(spec.socksPort, spec.credentials, "http://10.0.2.2:18083/native-vpn-preflight") >= 0)
            check(owns(spec, request))
            if (tun == null || browserScope != spec.input.includeBrowser) {
                val builder = Builder().setSession("Development native DNS preview").setMtu(1500)
                    .addAddress("26.26.26.1", 30).addRoute("0.0.0.0", 0)
                    .addDnsServer(NativePreviewVpnInput.VIRTUAL_DNS).addAllowedApplication(packageName)
                    .setUnderlyingNetworks(arrayOf(spec.network))
                if (spec.input.includeBrowser) builder.addAllowedApplication("com.android.chrome")
                if (Build.VERSION.SDK_INT >= 29) builder.setMetered(false)
                val previous = tun
                tun = builder.establish() ?: error("preview-tun-denied")
                previous?.close(); browserScope = spec.input.includeBrowser
            } else check(setUnderlyingNetworks(arrayOf(spec.network)))
            check(owns(spec, request))
            val forwarder = NativePreviewForwarderOwner(spec) { child -> lost(null, child) }
            owned.forwarder = forwarder
            forwarder.launch()
            check(FileDescriptorTransfer.send({ owns(spec, request) }, { owned.forwarder?.isAlive == true }, {
                LocalSocket().use { socket ->
                    socket.connect(LocalSocketAddress(spec.fdSocket.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))
                    socket.soTimeout = 1000
                    socket.setFileDescriptorsForSend(arrayOf(requireNotNull(tun).fileDescriptor))
                    socket.outputStream.write(32); socket.setFileDescriptorsForSend(null); socket.shutdownOutput()
                }
            }))
            val until = NativePreviewProcessOwner.deadline(10000)
            var ready = false
            while (owns(spec, request) && System.nanoTime() < until && !ready) {
                ready = runCatching {
                    check(manager.getNetworkCapabilities(manager.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true)
                    defaultHttp("/native-vpn-ready-${spec.epoch}")
                }.getOrDefault(false)
                if (!ready) Thread.sleep(50)
            }
            check(ready && owns(spec, request))
            state = "RUNNING"; foreground()
            return true
        } catch (_: Throwable) {
            synchronized(admission) { if (active === owned) active = null }
            val clean = retire(owned)
            state = "FAILED"; reason = if (clean) "launch" else "cleanup"
            return false
        }
    }

    private fun defaultHttp(path: String): Boolean = Socket().use { socket ->
        socket.connect(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(10, 0, 2, 2)), 18083), 1000)
        socket.soTimeout = 1000
        socket.outputStream.write("GET $path HTTP/1.1\r\nHost: 10.0.2.2\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
        val bytes = ByteArray(4096)
        var used = 0
        while (used < bytes.size) {
            val count = socket.inputStream.read(bytes, used, bytes.size - used)
            if (count < 0) break
            used += count
        }
        String(bytes, 0, used, Charsets.US_ASCII).contains("flutter-vless-direct-bypass")
    }

    private fun lost(core: NativePreviewProcessOwner?, forwarder: NativePreviewForwarderOwner?) {
        val lost = synchronized(admission) {
            val session = active ?: return
            if (!authorized || core != null && session.core !== core || forwarder != null && session.forwarder !== forwarder) return
            Pair(session, requests.incrementAndGet())
        }
        lost.first.spec.generation.revoke()
        worker.execute {
            if (!authorized || active !== lost.first || requests.get() != lost.second) return@execute
            val request = lost.second
            state = "RECOVERING"; reason = "owned-child-exit"
            if (!stopOwned(false)) { state = "FAILED"; reason = "cleanup"; return@execute }
            worker.schedule({ if (authorized && requests.get() == request) restart(request, "owned-child-exit") }, 500, TimeUnit.MILLISECONDS)
        }
    }

    private fun drainRetiring(): Boolean {
        var clean = true
        retiring.toList().forEach { session ->
            try { session.close(); retiring.remove(session) } catch (_: Throwable) { clean = false }
        }
        return clean
    }

    private fun stopOwned(dropTun: Boolean): Boolean {
        val session = synchronized(admission) { val previous = active; active = null; previous }
        session?.spec?.generation?.revoke()
        if (session != null && session !in retiring) retiring.add(session)
        var clean = drainRetiring()
        if (dropTun) {
            try { tun?.close(); tun = null } catch (_: Throwable) { clean = false }
        }
        return clean
    }

    private fun snapshot() = Bundle().apply {
        putString("state", state); putString("reason", reason)
        putString("sourceDigest", accepted?.sourceDigest)
        putString("epoch", active?.spec?.epoch)
        putString("brokerName", active?.broker?.socketName)
        putBoolean("generationCurrent", active?.spec?.generation?.isCurrent() == true)
        putLong("networkHandle", captured?.networkHandle ?: 0)
        putBoolean("coreAlive", active?.core?.isAlive == true)
        putBoolean("forwarderAlive", active?.forwarder?.isAlive == true)
        putBoolean("tunOwned", tun != null)
        putBoolean("authorized", authorized)
        putInt("retiringOwners", retiring.size)
        putBoolean("retiringChildAlive", retiring.any { it.core?.isAlive == true || it.forwarder?.isAlive == true })
        putBoolean("countersAvailable", false)
        putBoolean("hostQualified", false)
    }

    private fun foreground() {
        val channel = "native-dns-preview"
        if (Build.VERSION.SDK_INT >= 26) getSystemService(NotificationManager::class.java)
            .createNotificationChannel(NotificationChannel(channel, "Development VPN", NotificationManager.IMPORTANCE_LOW))
        val builder = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, channel) else Notification.Builder(this)
        val stop = PendingIntent.getService(this, 717, Intent(this, NativePreviewVpnService::class.java).setAction(STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        builder.setContentTitle("Development native DNS preview").setContentText(state)
            .setSmallIcon(android.R.drawable.ic_dialog_info).setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Stop preview", stop).build())
        startForeground(717, builder.build())
    }

    override fun onRevoke() {
        val gate = synchronized(admission) { requests.incrementAndGet(); authorized = false; generation }
        gate?.revoke()
        worker.execute {
            val clean = stopOwned(true); accepted = null
            if (clean) { stopForeground(STOP_FOREGROUND_REMOVE); stopSelf() }
            else { state = "FAILED"; reason = "cleanup"; foreground() }
        }
        super.onRevoke()
    }

    override fun onDestroy() {
        val gate = synchronized(admission) { requests.incrementAndGet(); authorized = false; generation }
        gate?.revoke()
        callback?.let { runCatching { manager.unregisterNetworkCallback(it) } }; callback = null
        worker.close { stopOwned(true); accepted = null }
        super.onDestroy()
    }

    companion object {
        const val START = "com.github.tfox.flutter_vless.DEV_NATIVE_VPN_START"
        const val STOP = "com.github.tfox.flutter_vless.DEV_NATIVE_VPN_STOP"
        const val STATE = "com.github.tfox.flutter_vless.DEV_NATIVE_VPN_STATE"
        const val KILL_OWNED = "com.github.tfox.flutter_vless.DEV_NATIVE_VPN_KILL_OWNED"
    }
}
