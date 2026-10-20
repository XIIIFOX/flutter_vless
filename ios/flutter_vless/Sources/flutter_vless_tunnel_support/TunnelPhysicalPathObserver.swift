import Foundation
import Darwin
import Network

/// Observes provider-process paths without opening a connection or changing any
/// route. It selects a concrete interface for later DNS/socket binding; a path
/// flag is neither remote reachability nor a NAT64-prefix witness.
public final class TunnelPhysicalPathObserver: @unchecked Sendable {
    public enum Failure: Error { case unavailable, cancelled, notStarted }

    private let queue = DispatchQueue(label: "dev.tfox.flutter-vless.underlay-path")
    private let excludedInterfaceIndex: @Sendable () -> UInt32?
    enum Event: Sendable {
        case preference([UInt32])
        case scoped(TunnelUnderlayPathSelection.Kind, TunnelUnderlayPathSelection.ScopedPath, changed: Bool)
    }
    struct Boundary {
        var install: (DispatchQueue, @escaping @Sendable (Event) -> Void) -> [() -> Void]
        var ownedIndexes: () -> Set<UInt32>?
        static var system: Self { .init(install: TunnelPhysicalPathObserver.install,
                                       ownedIndexes: TunnelPhysicalPathObserver.ownedTunnelIndexes) }
    }
    private let boundary: Boundary
    private var cancellations: [() -> Void] = []
    private var paths: [TunnelUnderlayPathSelection.Kind: TunnelUnderlayPathSelection.ScopedPath] = [:]
    private var preferred: [UInt32]?
    private var current: TunnelEndpointPath?
    private var selectedKind: TunnelUnderlayPathSelection.Kind?
    private var change: (@Sendable (TunnelEndpointPath?) -> Void)?
    private var started = false
    private var cancelled = false
    private struct Waiter {
        let continuation: CheckedContinuation<TunnelEndpointPath, Error>
        let timer: DispatchWorkItem
    }
    private var waiters: [UUID: Waiter] = [:]
    private final class Request: @unchecked Sendable {
        private let lock = NSLock()
        private var cancelled = false
        func cancel() { lock.lock(); cancelled = true; lock.unlock() }
        var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
    }

    public init(excludedInterfaceIndex: @escaping @Sendable () -> UInt32? = { nil }) {
        self.excludedInterfaceIndex = excludedInterfaceIndex
        self.boundary = .system
    }

    init(boundary: Boundary, excludedInterfaceIndex: @escaping @Sendable () -> UInt32? = { nil }) {
        self.excludedInterfaceIndex = excludedInterfaceIndex
        self.boundary = boundary
    }

    public func start(onChange: @escaping @Sendable (TunnelEndpointPath?) -> Void) {
        queue.async { [self] in
            guard !started, !cancelled else { return }
            started = true
            change = onChange
            cancellations = boundary.install(queue) { [weak self] event in
                guard let self, !self.cancelled else { return }
                switch event {
                case .preference(let indexes):
                    self.preferred = indexes
                    self.publish(force: false)
                case .scoped(let kind, let snapshot, let changed):
                    let selectedKind = self.selectedKind
                    self.paths[kind] = snapshot
                    // A new scoped path may contain changed DNS64 state even
                    // when its public name/family fields are unchanged.
                    self.publish(force: changed && selectedKind == kind)
                }
            }
        }
    }

    public func initialSnapshot(deadline: TimeInterval) async throws -> TunnelEndpointPath {
        let id = UUID()
        let request = Request()
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            let snapshot: TunnelEndpointPath = try await withCheckedThrowingContinuation { continuation in
                queue.async { [self] in
                    guard !request.isCancelled else { continuation.resume(throwing: CancellationError()); return }
                    guard !cancelled else { continuation.resume(throwing: Failure.cancelled); return }
                    guard started else { continuation.resume(throwing: Failure.notStarted); return }
                    guard deadline.isFinite, deadline > ProcessInfo.processInfo.systemUptime else {
                        continuation.resume(throwing: Failure.unavailable); return
                    }
                    if let current { continuation.resume(returning: current); return }
                    let timer = DispatchWorkItem { [weak self] in
                        self?.finish(id, result: .failure(Failure.unavailable))
                    }
                    waiters[id] = Waiter(continuation: continuation, timer: timer)
                    queue.asyncAfter(deadline: .now() + (deadline - ProcessInfo.processInfo.systemUptime), execute: timer)
                }
            }
            try Task.checkCancellation()
            return snapshot
        } onCancel: {
            request.cancel()
            self.queue.async { self.finish(id, result: .failure(CancellationError())) }
        }
    }

    public func cancel() {
        queue.async { [self] in
            guard !cancelled else { return }
            cancelled = true
            cancellations.forEach { $0() }
            cancellations.removeAll()
            paths.removeAll()
            current = nil
            change = nil
            for id in Array(waiters.keys) { finish(id, result: .failure(Failure.cancelled)) }
        }
    }

    private func finish(_ id: UUID, result: Result<TunnelEndpointPath, Error>) {
        guard let waiter = waiters.removeValue(forKey: id) else { return }
        waiter.timer.cancel()
        waiter.continuation.resume(with: result)
    }

    private func publish(force: Bool) {
        guard !cancelled, let preferred,
              paths.count == TunnelUnderlayPathSelection.Kind.allCases.count else { return }
        let explicit = excludedInterfaceIndex()
        let excluded = explicit.flatMap { $0 == 0 ? nil : Set([$0]) } ?? boundary.ownedIndexes()
        // Failure to identify our tunnel is unknown, not proof of no tunnel.
        let choice = excluded.flatMap {
            TunnelUnderlayPathSelection.selection(preferred: preferred, scoped: paths, excluding: $0)
        }
        let selected = choice?.path
        let changed = selected != current
        current = selected
        selectedKind = choice?.kind
        if let selected {
            for id in Array(waiters.keys) { finish(id, result: .success(selected)) }
        }
        if changed || force { change?(selected) }
    }

    private final class NetworkPaths: @unchecked Sendable {
        // Every Network callback below is delivered on the same supplied queue.
        var values: [TunnelUnderlayPathSelection.Kind: Network.NWPath] = [:]
    }

    private static func install(queue: DispatchQueue, event: @escaping @Sendable (Event) -> Void) -> [() -> Void] {
        var cancellations: [() -> Void] = []
        let previous = NetworkPaths()
        let preference = NWPathMonitor()
        preference.pathUpdateHandler = { event(.preference($0.availableInterfaces.compactMap(index))) }
        preference.start(queue: queue)
        cancellations.append { preference.cancel() }
        for kind in TunnelUnderlayPathSelection.Kind.allCases {
            let monitor = NWPathMonitor(requiredInterfaceType: interfaceType(kind))
            monitor.pathUpdateHandler = { path in
                let changed = previous.values[kind].map { $0 != path } ?? true
                previous.values[kind] = path
                let interfaces = path.availableInterfaces.filter { $0.type == interfaceType(kind) }.map { interface in
                    let value = index(interface) ?? 0
                    // Retain an invalid first entry as invalid. Removing it
                    // would transfer its family flags to a different interface.
                    let verified = interface.name.withCString { if_nametoindex($0) } == value
                    return TunnelUnderlayPathSelection.Interface(index: verified ? value : 0, name: interface.name)
                }
                event(.scoped(kind, .init(satisfied: path.status == .satisfied,
                    interfaces: interfaces, supportsIPv4: path.supportsIPv4,
                    supportsIPv6: path.supportsIPv6, supportsDNS: path.supportsDNS), changed: changed))
            }
            monitor.start(queue: queue)
            cancellations.append { monitor.cancel() }
        }
        return cancellations
    }

    private static func index(_ interface: NWInterface) -> UInt32? {
        UInt32(exactly: interface.index).flatMap { $0 == 0 ? nil : $0 }
    }

    private static func interfaceType(_ kind: TunnelUnderlayPathSelection.Kind) -> NWInterface.InterfaceType {
        switch kind {
        case .wired: return .wiredEthernet
        case .wifi: return .wifi
        case .cellular: return .cellular
        case .other: return .other
        }
    }

    // Older supported OS versions do not expose virtualInterface. Match the
    // provider's assigned addresses, never every interface named "utun".
    private static func ownedTunnelIndexes() -> Set<UInt32>? {
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0 else { return nil }
        defer { freeifaddrs(first) }
        var matches: [UInt32: Set<Int>] = [:]
        var entry = first
        while let value = entry {
            defer { entry = value.pointee.ifa_next }
            guard let address = value.pointee.ifa_addr else { continue }
            var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            let match: Bool
            if address.pointee.sa_family == sa_family_t(AF_INET) {
                var ip = UnsafeRawPointer(address).assumingMemoryBound(to: sockaddr_in.self).pointee.sin_addr
                match = inet_ntop(AF_INET, &ip, &text, socklen_t(text.count)) != nil
                    && String(cString: text) == "10.0.85.2"
            } else if address.pointee.sa_family == sa_family_t(AF_INET6) {
                var ip = UnsafeRawPointer(address).assumingMemoryBound(to: sockaddr_in6.self).pointee.sin6_addr
                match = inet_ntop(AF_INET6, &ip, &text, socklen_t(text.count)) != nil
                    && String(cString: text) == "fd00:198:18::1"
            } else { match = false }
            if match {
                let index = if_nametoindex(value.pointee.ifa_name)
                if index != 0 { matches[index, default: []].insert(Int(address.pointee.sa_family)) }
            }
        }
        // A physical LAN can legitimately use the same private IPv4 address.
        // Require both configured tunnel addresses on the same interface.
        return Set(matches.filter { $0.value.count == 2 }.keys)
    }
}
