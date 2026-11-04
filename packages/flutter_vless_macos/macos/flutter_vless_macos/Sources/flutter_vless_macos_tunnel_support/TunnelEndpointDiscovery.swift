import Foundation
import Darwin
import dnssd
import flutter_vless_macos_privacy

/// One initial provider preparation's bounded DNS subscriptions. A usable
/// initial batch from every usable family can admit startup before the two
/// second collection ceiling; subscriptions continue retaining later updates.
/// This helper never changes caller DNS, opens a Core, or caches across paths.
public final class TunnelEndpointDiscovery: @unchecked Sendable {
    enum FamilyEvent: Sendable {
        case answer(TunnelEndpointDNSAnswer, moreComing: Bool)
        case failure(TunnelEndpointDNSAnswer.Failure)
    }
    typealias Query = (String, UInt32, TunnelEndpointAddress.Family, DispatchQueue,
        @escaping (FamilyEvent) -> Void) -> (() -> Void)?

    private final class Host {
        let name: String
        // Pending DNS-SD changes are committed as a value snapshot only after
        // all open family batches drain. A Remove/Add replacement must not
        // transiently invalidate a selected address between two callbacks.
        var accumulator: TunnelEndpointDNSAccumulator
        var visible: TunnelEndpointDNSAccumulator
        var batchOpen = [false, false]
        var answered = [false, false]
        var sealed = false
        var started = false
        var published = false
        var collectionEnd: TimeInterval = 0
        var active = false
        var loggedLateAAAA = false
        var startedTiming: NativeDiagnosticTimer?
        var queueDelayMs: UInt64 = 0
        var waiters: [CheckedContinuation<[TunnelEndpointCandidate], Error>] = []
        // These resources and continuations are used only on the serial queue.
        var closes: [() -> Void] = []
        var cancelTimer: (() -> Void)?
        let timing = NativeDiagnosticTimer()

        init(name: String, path: TunnelEndpointPath) {
            self.name = name
            accumulator = TunnelEndpointDNSAccumulator(host: name, path: path)
            visible = TunnelEndpointDNSAccumulator(host: name, path: path)
        }
    }

    /// Cancellation can precede queue registration. A per-waiter gate resumes
    /// exactly once without revoking another waiter or the owning discovery.
    private final class SealWaiter: @unchecked Sendable {
        let id = UUID()
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Void, Error>?
        private var result: Result<Void, Error>?

        var isFinished: Bool { lock.lock(); defer { lock.unlock() }; return result != nil }

        func install(_ continuation: CheckedContinuation<Void, Error>) {
            lock.lock()
            if let result { lock.unlock(); continuation.resume(with: result) }
            else { self.continuation = continuation; lock.unlock() }
        }

        func finish(_ result: Result<Void, Error>) {
            lock.lock()
            guard self.result == nil else { lock.unlock(); return }
            self.result = result
            let continuation = self.continuation; self.continuation = nil
            lock.unlock()
            continuation?.resume(with: result)
        }
    }

    private let queue = DispatchQueue(label: "dev.tfox.flutter-vless.endpoint-discovery", qos: .userInitiated)
    private let lock = NSLock()
    private let path: TunnelEndpointPath
    private let deadline: TimeInterval
    private let now: () -> TimeInterval
    private let current: () -> Bool
    private let event: (NativeDiagnosticMessage) -> Void
    private let onInvalidated: () -> Void
    private let query: Query
    private let schedule: TunnelEndpointDNSCollection.Schedule
    private let collectionWindow: TimeInterval
    private let synthesis: ((String, TimeInterval) async throws -> [String])?
    private let fallback: ((String, TimeInterval) async throws -> String?)?
    private var hosts: [String: Host] = [:]
    private var cancelled = false
    private var invalidated = false
    private var admitted: [TunnelEndpointSelection]?
    private var sealWaiters: [UUID: SealWaiter] = [:]
    private var committed = false
    // Queue-owned resource admission: at most eight DNSService references.
    private var activeHosts = 0
    private var queuedHosts: [Host] = []
    private let timing = NativeDiagnosticTimer()
    private var protectedSettingsCheckpoint: UInt64?

    /// `isCurrent` and `onInvalidated` must be thread-safe, nonblocking, and
    /// weakly capture the owning provider. Notifications run outside our lock.
    public convenience init(path: TunnelEndpointPath, deadline: TimeInterval,
        isCurrent: @escaping () -> Bool,
        event: @escaping (NativeDiagnosticMessage) -> Void = { _ in },
        onInvalidated: @escaping () -> Void) {
        self.init(path: path, deadline: deadline, now: { ProcessInfo.processInfo.systemUptime },
            isCurrent: isCurrent, event: event, onInvalidated: onInvalidated, query: FamilyQuery.start)
    }

    init(path: TunnelEndpointPath, deadline: TimeInterval, now: @escaping () -> TimeInterval,
        isCurrent: @escaping () -> Bool, event: @escaping (NativeDiagnosticMessage) -> Void = { _ in },
        onInvalidated: @escaping () -> Void, query: @escaping Query, collectionWindow: TimeInterval = 2,
        synthesis: ((String, TimeInterval) async throws -> [String])? = nil,
        fallback: ((String, TimeInterval) async throws -> String?)? = nil,
        schedule: @escaping TunnelEndpointDNSCollection.Schedule = TunnelEndpointDNSCollection.scheduleDeadline) {
        self.path = path; self.deadline = deadline; self.now = now
        current = isCurrent; self.event = event; self.onInvalidated = onInvalidated; self.query = query
        self.collectionWindow = collectionWindow
        self.synthesis = synthesis; self.fallback = fallback; self.schedule = schedule
    }

    deinit {
        let pending = Array(hosts.values)
        let waiters = Array(sealWaiters.values)
        queue.async {
            for host in pending { Self.close(host, failure: CancellationError()) }
            for waiter in waiters { waiter.finish(.failure(CancellationError())) }
        }
    }

    /// True for an admitted selection invalidated during the original DNS
    /// collection window, including after an early native runtime start.
    /// Stop/cancel is separate and never emits an invalidation notification.
    public var isInvalidated: Bool {
        lock.lock(); defer { lock.unlock() }
        return invalidated
    }

    /// Whether an admitted system selection still belongs to an incomplete
    /// initial collection. Remains readable after cancellation so Sleep/Wake
    /// can distinguish a provisional snapshot from an established sealed one.
    /// Unselected hosts and literal/encrypted-fallback selections do not count.
    public var hasUnsealedSystemSelections: Bool {
        lock.lock(); defer { lock.unlock() }
        return hasUnsealedSystemSelectionsLocked()
    }

    private func hasUnsealedSystemSelectionsLocked() -> Bool {
        return admitted?.contains { selection in
            selection.selected.origin == .systemNameAnswer &&
                hosts[Self.key(selection.logicalHost)]?.sealed == false
        } == true
    }

    /// Finish only the admitted system selections' existing collection windows
    /// before suspension. No query or deadline is created or renewed. A canceled
    /// waiting task detaches only itself; Wake can retain the active discovery.
    /// Group cancellation or invalidation fails every waiter.
    public func waitForInitialSelectionsToSeal() async throws {
        let waiter = SealWaiter()
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { continuation in
                waiter.install(continuation)
                queue.async { [weak self] in
                    guard let self else { waiter.finish(.failure(CancellationError())); return }
                    guard !waiter.isFinished else { return }
                    self.lock.lock(); self.sealWaiters[waiter.id] = waiter; self.lock.unlock()
                    self.finishSealWaitersIfReady()
                }
            }
        } onCancel: {
            waiter.finish(.failure(CancellationError()))
            self.queue.async { [weak self] in
                guard let self else { return }
                self.lock.lock(); self.sealWaiters.removeValue(forKey: waiter.id); self.lock.unlock()
            }
        }
    }

    private func finishSealWaitersIfReady() {
        let isCurrent = current()
        lock.lock()
        let result: Result<Void, Error>
        if cancelled || invalidated || !isCurrent { result = .failure(CancellationError()) }
        else if hasUnsealedSystemSelectionsLocked() { lock.unlock(); return }
        else { result = .success(()) }
        let waiters = Array(sealWaiters.values); sealWaiters.removeAll()
        lock.unlock()
        for waiter in waiters { waiter.finish(result) }
    }

    // Internal lifecycle observability keeps tests ordered by registration,
    // rather than assuming a worker ran after a wall-clock sleep.
    var pendingInitialSealWaiterCount: Int {
        lock.lock(); defer { lock.unlock() }
        return sealWaiters.count
    }

    /// Atomically claim a selected system record's expiry while its own initial
    /// collection is still active. A sealed record's later ordinary TTL expiry
    /// never borrows this authority. Returns true only for a new claim; after
    /// false, a caller must recheck freshness because the record may have healed.
    @discardableResult
    public func claimInitialInvalidationIfNeeded() -> Bool {
        guard current() else { return false }
        lock.lock()
        let needsCorrection = !cancelled && !invalidated && hosts.values.contains {
            !$0.sealed && selectedRecordMissingLocked(in: $0, at: now())
        }
        if needsCorrection { invalidated = true }
        let pending = needsCorrection ? Array(hosts.values) : []
        lock.unlock()
        if needsCorrection { completeInvalidation(pending) }
        return needsCorrection
    }

    /// Record successful protected-settings installation using this discovery's
    /// monotonic clock. At most one checkpoint and one later IPv6-add event per
    /// host are emitted; no address, hostname or interface value is recorded.
    public func noteProtectedSettingsInstalled() {
        guard current() else { return }
        lock.lock()
        guard !cancelled, !invalidated, protectedSettingsCheckpoint == nil else { lock.unlock(); return }
        let elapsed = timing.elapsedMilliseconds()
        protectedSettingsCheckpoint = elapsed
        lock.unlock()
        event("Endpoint DNS discovery protectedSettingsMs=\(elapsed)")
    }

    private func owns() -> Bool {
        lock.lock(); let permitted = !cancelled && !invalidated; lock.unlock()
        return permitted && current()
    }

    /// Resolve physical endpoints. Literal synthesis and encrypted fallback
    /// retain their existing resolver policy; only named system answers lease.
    public func resolveCandidates(_ host: String) async throws -> TunnelEndpointCandidates {
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            guard owns() else { throw CancellationError() }
            return try await TunnelEndpointResolver.resolveCandidates(host, on: path, deadline: deadline,
                now: now, system: { name, _, _ in try await self.initial(name) },
                synthesis: { name, limit in
                    if let synthesis = self.synthesis { return try await synthesis(name, limit) }
                    return try await TunnelIPv4SynthesisWorker.shared.resolve(name, deadline: limit, isCurrent: self.owns)
                }, fallback: { name, limit in
                    if let fallback = self.fallback { return try await fallback(name, limit) }
                    return try await TunnelEndpointResolver.encryptedLookup(name, timeout: limit)
                },
                isCurrent: owns, event: event)
        } onCancel: { self.cancel() }
    }

    /// Arm selected-address validation while preflight, settings and native
    /// startup are in flight. A false result requires a fresh provider plan.
    public func admitSelections(_ selections: [TunnelEndpointSelection]) -> Bool {
        guard current() else { return false }
        lock.lock()
        guard !cancelled, !invalidated, !committed else { lock.unlock(); return false }
        let valid = freshLocked(selections, at: now())
        if valid { admitted = selections }
        else { invalidated = true }
        lock.unlock()
        return valid
    }

    /// Validate current system witnesses through the original collection bound.
    /// A selected-address removal can invalidate even an early-started runtime:
    /// Core starts lazily, so the old full snapshot might otherwise choose a
    /// different live address before its first remote connection.
    public func isFresh(_ selections: [TunnelEndpointSelection], at time: TimeInterval = ProcessInfo.processInfo.systemUptime) -> Bool {
        guard current() else { return false }
        lock.lock(); defer { lock.unlock() }
        guard !cancelled, !invalidated else { return false }
        return freshLocked(selections, at: time)
    }

    /// Call after Core and the packet worker start successfully. Never clears
    /// a prior revocation or stops the bounded selected-address watcher.
    @discardableResult
    public func finishAdmission() -> Bool {
        guard current() else { return false }
        lock.lock(); defer { lock.unlock() }
        guard !cancelled, !invalidated, let admitted, freshLocked(admitted, at: now()) else { return false }
        committed = true
        return true
    }

    /// Revoke immediately, then close each DNS reference on its registered
    /// queue. Safe before registration, during an await, or after initial return.
    public func cancel() {
        lock.lock(); cancelled = true; let pending = Array(hosts.values); lock.unlock()
        finishSealWaitersIfReady()
        queue.async { for host in pending { Self.close(host, failure: CancellationError()) } }
    }

    private static func key(_ name: String) -> String {
        (name.hasSuffix(".") ? String(name.dropLast()) : name).lowercased()
    }

    private func initial(_ name: String) async throws -> [TunnelEndpointCandidate] {
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                queue.async { self.attach(name, continuation) }
            }
        } onCancel: { self.cancel() }
    }

    private func attach(_ name: String, _ waiter: CheckedContinuation<[TunnelEndpointCandidate], Error>) {
        guard owns(), deadline.isFinite, now().isFinite, now() < deadline else {
            cancel()
            waiter.resume(throwing: CancellationError()); return
        }
        lock.lock()
        let identity = Self.key(name)
        let host: Host
        if let existing = hosts[identity] { host = existing }
        else {
            guard hosts.count < 64 else {
                lock.unlock()
                waiter.resume(throwing: TunnelXrayConfigPreparer.StartupError.invalidConfiguration); return
            }
            host = Host(name: name, path: path); hosts[identity] = host
        }
        host.waiters.append(waiter)
        let start = !host.started
        host.started = true
        lock.unlock()
        if start {
            if activeHosts < 4 { startQueries(host) }
            else { queuedHosts.append(host) }
        }
        else { publishIfReady(host) }
    }

    private func startQueries(_ host: Host) {
        guard owns(), now() < deadline else { cancel(); return }
        activeHosts += 1; host.active = true
        host.queueDelayMs = host.timing.elapsedMilliseconds()
        host.startedTiming = NativeDiagnosticTimer()
        let bound = min(deadline, now() + collectionWindow)
        lock.lock(); host.collectionEnd = bound; lock.unlock()
        // Match mDNSResponder's combined GetAddrInfo request creation order.
        // Candidate preference still follows actual callbacks, without sorting.
        for family in [TunnelEndpointAddress.Family.ipv6, .ipv4] {
            guard owns(), now().isFinite, now() < deadline else { cancel(); return }
            if let close = query(host.name, path.interfaceIndex, family, queue, { [weak self, weak host] update in
                guard let self, let host else { return }
                self.queue.async { self.receive(update, family: family, host: host) }
            }) { host.closes.append(close) }
        }
        guard !host.closes.isEmpty else { seal(host); return }
        host.cancelTimer = schedule(queue, max(0, bound - now())) { [weak self, weak host] in
            guard let self, let host else { return }
            self.seal(host)
        }
    }

    private func receive(_ update: FamilyEvent, family: TunnelEndpointAddress.Family, host: Host) {
        guard owns() else { cancel(); return }
        lock.lock()
        guard !cancelled, !invalidated, !host.sealed else { lock.unlock(); return }
        let index = family == .ipv4 ? 0 : 1
        var lateAAAA: (UInt64, Bool)?
        switch update {
        case .answer(let answer, let moreComing):
            let accepted = host.accumulator.accept(answer, at: now())
            host.batchOpen[index] = moreComing
            if accepted, answer.added, !moreComing { host.answered[index] = true }
            if accepted, answer.added, family == .ipv6,
               let address = TunnelEndpointAddress(text: answer.text, source: .systemNameAnswer), address.family == .ipv6,
               host.published, !host.loggedLateAAAA, let checkpoint = protectedSettingsCheckpoint {
                host.loggedLateAAAA = true
                let elapsed = timing.elapsedMilliseconds()
                let usable = host.accumulator.snapshot(at: now()).contains { $0.address.text == address.text }
                lateAAAA = (elapsed >= checkpoint ? elapsed - checkpoint : 0, usable)
            }
        case .failure(let failure):
            host.accumulator.accept(.failed(failure), at: now())
            if case .noRecord = failure { host.answered[index] = true }
        }
        if !host.batchOpen.contains(true) { host.visible = host.accumulator }
        lock.unlock()
        if let (elapsed, usable) = lateAAAA {
            event("Endpoint DNS discovery lateAAAAAfterSettingsMs=\(elapsed) usable=\(usable) initialReady=true")
        }
        notifyIfInvalidated(host)
        publishIfReady(host)
    }

    private func freshLocked(_ selections: [TunnelEndpointSelection], at time: TimeInterval) -> Bool {
        selections.allSatisfy { selection in
            guard selection.candidates.path == path else { return false }
            if selection.selected.origin == .systemNameAnswer {
                guard let host = hosts[Self.key(selection.logicalHost)] else { return false }
                return host.visible.snapshot(at: time).contains { $0.address.text == selection.selected.address.text }
            }
            return selection.selected.isUsable(on: path, at: time,
                allowFreshZeroTTL: selection.selected.isSingleAttemptOnly)
        }
    }

    private func selectedRecordMissingLocked(in host: Host, at time: TimeInterval) -> Bool {
        let values = host.visible.snapshot(at: time)
        return admitted?.contains { selection in
            selection.selected.origin == .systemNameAnswer && Self.key(selection.logicalHost) == Self.key(host.name) &&
                !values.contains { $0.address.text == selection.selected.address.text }
        } == true
    }

    private func completeInvalidation(_ pending: [Host]) {
        // The latch is visible before either callback or resource cancellation.
        // The provider can refresh its token synchronously before a caller
        // rejects the stale plan; DNSService ownership stays on our queue.
        onInvalidated()
        finishSealWaitersIfReady()
        queue.async { for host in pending { Self.close(host, failure: CancellationError()) } }
    }

    private func notifyIfInvalidated(_ changedHost: Host) {
        guard current() else { return }
        lock.lock()
        let shouldNotify = !cancelled && !invalidated && selectedRecordMissingLocked(in: changedHost, at: now())
        if shouldNotify { invalidated = true }
        let pending = shouldNotify ? Array(hosts.values) : []
        lock.unlock()
        if shouldNotify { completeInvalidation(pending) }
    }

    private func publishIfReady(_ host: Host) {
        guard owns() else { cancel(); return }
        lock.lock()
        let values = host.visible.snapshot(at: now())
        let initialComplete = (!path.supportsIPv4 || host.answered[0]) && (!path.supportsIPv6 || host.answered[1])
        // TTL zero is a fresh single attempt only. A short positive record may
        // disappear before the old full snapshot: do not change its semantics
        // merely to release startup early.
        let survivesCollection = values.allSatisfy {
            !$0.isSingleAttemptOnly && ($0.validUntil.map { $0 > host.collectionEnd } ?? false)
        }
        guard host.sealed || (initialComplete && !host.batchOpen.contains(true) && !values.isEmpty && survivesCollection) else { lock.unlock(); return }
        let waiters = host.waiters; host.waiters.removeAll()
        let first = !host.published
        host.published = true
        lock.unlock()
        if first {
            event("Endpoint DNS discovery initialReadyMs=\(host.timing.elapsedMilliseconds()) queueDelayMs=\(host.queueDelayMs) collectionMs=\(host.startedTiming?.elapsedMilliseconds() ?? 0) candidates=\(values.count)")
        }
        for waiter in waiters { waiter.resume(returning: values) }
    }

    private func seal(_ host: Host) {
        guard owns() else { cancel(); return }
        lock.lock(); host.sealed = true; host.visible = host.accumulator; lock.unlock()
        let closes = host.closes; host.closes.removeAll()
        let cancelTimer = host.cancelTimer; host.cancelTimer = nil
        cancelTimer?()
        for close in closes { close() }
        if host.active { host.active = false; activeHosts -= 1 }
        notifyIfInvalidated(host)
        publishIfReady(host)
        finishSealWaitersIfReady()
        event("Endpoint DNS discovery finalCollectionMs=\(host.startedTiming?.elapsedMilliseconds() ?? 0) queueDelayMs=\(host.queueDelayMs)")
        while owns(), activeHosts < 4, !queuedHosts.isEmpty {
            let next = queuedHosts.removeFirst()
            startQueries(next)
        }
    }

    private static func close(_ host: Host, failure: Error) {
        let cancelTimer = host.cancelTimer; host.cancelTimer = nil
        cancelTimer?()
        let closes = host.closes; host.closes.removeAll()
        for close in closes { close() }
        let waiters = host.waiters; host.waiters.removeAll()
        for waiter in waiters { waiter.resume(throwing: failure) }
    }
}

private final class FamilyQuery {
    private var service: DNSServiceRef?
    private let family: TunnelEndpointAddress.Family
    private let receive: (TunnelEndpointDiscovery.FamilyEvent) -> Void

    private init(family: TunnelEndpointAddress.Family, receive: @escaping (TunnelEndpointDiscovery.FamilyEvent) -> Void) {
        self.family = family; self.receive = receive
    }

    static func start(_ name: String, index: UInt32, family: TunnelEndpointAddress.Family, queue: DispatchQueue,
        receive: @escaping (TunnelEndpointDiscovery.FamilyEvent) -> Void) -> (() -> Void)? {
        let owner = FamilyQuery(family: family, receive: receive)
        let flags = DNSServiceFlags(kDNSServiceFlagsTimeout | kDNSServiceFlagsReturnIntermediates)
        let proto = DNSServiceProtocol(family == .ipv4 ? kDNSServiceProtocol_IPv4 : kDNSServiceProtocol_IPv6)
        let error = DNSServiceGetAddrInfo(&owner.service, flags, index, proto, name,
            { _, flags, index, error, hostname, address, ttl, context in
                guard let context else { return }
                let owner = Unmanaged<FamilyQuery>.fromOpaque(context).takeUnretainedValue()
                guard error == kDNSServiceErr_NoError else {
                    let failure: TunnelEndpointDNSAnswer.Failure
                    switch error {
                    case DNSServiceErrorType(kDNSServiceErr_NoSuchRecord): failure = .noRecord
                    case DNSServiceErrorType(kDNSServiceErr_Timeout): failure = .timeout
                    case DNSServiceErrorType(kDNSServiceErr_ServiceNotRunning): failure = .serviceUnavailable
                    case DNSServiceErrorType(kDNSServiceErr_DefunctConnection): failure = .defunct
                    case DNSServiceErrorType(kDNSServiceErr_PolicyDenied): failure = .policyDenied
                    default: failure = .other
                    }
                    // On errors only the immutable request context identifies
                    // the family. No flags, name, sockaddr, index or TTL is read.
                    owner.receive(.failure(failure)); return
                }
                guard let hostname, let address else { return }
                let expected = owner.family == .ipv4 ? AF_INET : AF_INET6
                guard address.pointee.sa_family == sa_family_t(expected) else { return }
                var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                let text: String
                if expected == AF_INET {
                    guard address.pointee.sa_len >= MemoryLayout<sockaddr_in>.size else { return }
                    var ip = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
                    guard inet_ntop(AF_INET, &ip, &buffer, socklen_t(buffer.count)) != nil else { return }
                    text = String(cString: buffer)
                } else {
                    guard address.pointee.sa_len >= MemoryLayout<sockaddr_in6>.size else { return }
                    var ip = address.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
                    guard inet_ntop(AF_INET6, &ip, &buffer, socklen_t(buffer.count)) != nil else { return }
                    text = String(cString: buffer)
                }
                owner.receive(.answer(.init(hostname: String(cString: hostname), text: text, interfaceIndex: index,
                    ttl: ttl, added: flags & DNSServiceFlags(kDNSServiceFlagsAdd) != 0),
                    moreComing: flags & DNSServiceFlags(kDNSServiceFlagsMoreComing) != 0))
            }, Unmanaged.passUnretained(owner).toOpaque())
        guard error == kDNSServiceErr_NoError, let service = owner.service,
              DNSServiceSetDispatchQueue(service, queue) == kDNSServiceErr_NoError else {
            owner.close(); return nil
        }
        return { owner.close() }
    }

    private func close() {
        if let service { DNSServiceRefDeallocate(service); self.service = nil }
    }
}
