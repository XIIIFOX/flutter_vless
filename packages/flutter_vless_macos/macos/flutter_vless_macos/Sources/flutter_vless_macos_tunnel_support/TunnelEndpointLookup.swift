import Foundation
import Darwin
import dnssd

/// Serial lifetime for one scoped dual-family DNSService query. The short
/// collection window is inside the caller's absolute deadline, not renewed per RR.
final class TunnelEndpointDNSCollection: @unchecked Sendable {
    typealias Query = (String, UInt32, DispatchQueue, @escaping (TunnelEndpointDNSAnswer) -> Void) -> (() -> Void)?
    private let queue = DispatchQueue(label: "dev.tfox.flutter-vless.endpoint-candidates")
    private var continuation: CheckedContinuation<[TunnelEndpointCandidate], Error>?
    private var cancelQuery: (() -> Void)?
    private var timer: DispatchWorkItem?
    private var cancelled = false
    private var accumulator: TunnelEndpointDNSAccumulator
    private let now: () -> TimeInterval
    private let isCurrent: () -> Bool

    private init(host: String, path: TunnelEndpointPath, now: @escaping () -> TimeInterval, isCurrent: @escaping () -> Bool) {
        accumulator = TunnelEndpointDNSAccumulator(host: host, path: path)
        self.now = now
        self.isCurrent = isCurrent
    }

    static func collect(_ host: String, path: TunnelEndpointPath, deadline: TimeInterval,
                        now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
                        isCurrent: @escaping () -> Bool = { true },
                        query: @escaping Query = TunnelEndpointDNSQuery.start) async throws -> [TunnelEndpointCandidate] {
        let owner = TunnelEndpointDNSCollection(host: host, path: path, now: now, isCurrent: isCurrent)
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                owner.queue.async { owner.start(host, path: path, deadline: deadline, query: query, continuation: continuation) }
            }
        } onCancel: {
            owner.queue.async { owner.cancelled = true; owner.finish(.failure(CancellationError())) }
        }
    }

    private func start(_ host: String, path: TunnelEndpointPath, deadline: TimeInterval,
                       query: Query, continuation: CheckedContinuation<[TunnelEndpointCandidate], Error>) {
        self.continuation = continuation
        guard !cancelled, isCurrent() else { finish(.failure(CancellationError())); return }
        let remaining = deadline - now()
        guard remaining.isFinite, remaining > 0 else {
            finish(.failure(TunnelEndpointResolver.CandidateFailure.deadlineExceeded)); return
        }
        cancelQuery = query(host, path.interfaceIndex, queue) { [weak self] answer in
            guard let self else { return }
            self.queue.async {
                guard self.continuation != nil else { return }
                guard self.isCurrent() else { self.finish(.failure(CancellationError())); return }
                self.accumulator.accept(answer, at: self.now())
            }
        }
        guard cancelQuery != nil else { finish(.success([])); return }
        let timeout = DispatchWorkItem { [self] in
            guard isCurrent() else { finish(.failure(CancellationError())); return }
            finish(.success(accumulator.snapshot(at: now())))
        }
        timer = timeout
        queue.asyncAfter(deadline: .now() + min(2, remaining), execute: timeout)
    }

    private func finish(_ result: Result<[TunnelEndpointCandidate], Error>) {
        guard let continuation else { return }
        self.continuation = nil
        timer?.cancel(); timer = nil
        let cancel = cancelQuery; cancelQuery = nil
        cancel?() // always on the DNSService registration queue
        continuation.resume(with: result)
    }
}

private final class TunnelEndpointDNSQuery {
    private var service: DNSServiceRef?
    private let receive: (TunnelEndpointDNSAnswer) -> Void
    private init(receive: @escaping (TunnelEndpointDNSAnswer) -> Void) { self.receive = receive }

    static func start(_ host: String, index: UInt32, queue: DispatchQueue,
                      receive: @escaping (TunnelEndpointDNSAnswer) -> Void) -> (() -> Void)? {
        let owner = TunnelEndpointDNSQuery(receive: receive)
        let status = DNSServiceGetAddrInfo(&owner.service, DNSServiceFlags(kDNSServiceFlagsTimeout), index,
            DNSServiceProtocol(kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6), host,
            { _, flags, interfaceIndex, error, name, address, ttl, context in
                guard error == kDNSServiceErr_NoError, let context, let name, let address else { return }
                let owner = Unmanaged<TunnelEndpointDNSQuery>.fromOpaque(context).takeUnretainedValue()
                var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                let text: String
                if address.pointee.sa_family == sa_family_t(AF_INET) {
                    guard address.pointee.sa_len >= MemoryLayout<sockaddr_in>.size else { return }
                    var ip = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
                    guard inet_ntop(AF_INET, &ip, &buffer, socklen_t(buffer.count)) != nil else { return }
                    text = String(cString: buffer)
                } else if address.pointee.sa_family == sa_family_t(AF_INET6) {
                    guard address.pointee.sa_len >= MemoryLayout<sockaddr_in6>.size else { return }
                    var ip = address.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
                    guard inet_ntop(AF_INET6, &ip, &buffer, socklen_t(buffer.count)) != nil else { return }
                    text = String(cString: buffer)
                } else { return }
                owner.receive(.init(hostname: String(cString: name), text: text, interfaceIndex: interfaceIndex,
                    ttl: ttl, added: flags & DNSServiceFlags(kDNSServiceFlagsAdd) != 0))
            }, Unmanaged.passUnretained(owner).toOpaque())
        guard status == kDNSServiceErr_NoError, let service = owner.service,
              DNSServiceSetDispatchQueue(service, queue) == kDNSServiceErr_NoError else {
            owner.close(); return nil
        }
        return { owner.close() }
    }

    private func close() {
        if let service { DNSServiceRefDeallocate(service); self.service = nil }
    }
}

/// getaddrinfo has no cancellation or interface argument. At most one native
/// call can remain outstanding process-wide; caller cancellation/deadline only
/// discards its result. The slot is released only when that native call returns.
final class TunnelIPv4SynthesisWorker: @unchecked Sendable {
    static let shared = TunnelIPv4SynthesisWorker(lookup: systemLookup)
    private let gate = NSLock()
    private var busy = false
    private let queue = DispatchQueue(label: "dev.tfox.flutter-vless.literal-synthesis", qos: .utility)
    private let lookup: (String) -> [String]
    private let now: () -> TimeInterval

    init(lookup: @escaping (String) -> [String], now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.lookup = lookup
        self.now = now
    }

    func resolve(_ ipv4: String, deadline: TimeInterval, isCurrent: @escaping () -> Bool = { true }) async throws -> [String] {
        try Task.checkCancellation()
        guard isCurrent() else { throw CancellationError() }
        guard deadline.isFinite, now() < deadline else { throw TunnelEndpointResolver.CandidateFailure.deadlineExceeded }
        guard TunnelEndpointAddress(text: ipv4, source: .literal)?.family == .ipv4 else { return [] }
        guard acquire() else { return [] }
        let job = SynthesisResult()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                job.attach(continuation)
                let timer = DispatchWorkItem { job.finish(.failure(TunnelEndpointResolver.CandidateFailure.deadlineExceeded)) }
                job.install(timer)
                DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + max(0, deadline - now()), execute: timer)
                queue.async { [self] in
                    defer { release() }
                    guard !job.isFinished else { return }
                    guard isCurrent() else { job.finish(.failure(CancellationError())); return }
                    guard now() < deadline else { job.finish(.failure(TunnelEndpointResolver.CandidateFailure.deadlineExceeded)); return }
                    let values = lookup(ipv4)
                    guard isCurrent() else { job.finish(.failure(CancellationError())); return }
                    guard now() < deadline else { job.finish(.failure(TunnelEndpointResolver.CandidateFailure.deadlineExceeded)); return }
                    job.finish(.success(values))
                }
            }
        } onCancel: { job.finish(.failure(CancellationError())) }
    }

    private func acquire() -> Bool {
        gate.lock(); defer { gate.unlock() }
        guard !busy else { return false }; busy = true; return true
    }
    private func release() { gate.lock(); busy = false; gate.unlock() }

    private static func systemLookup(_ ipv4: String) -> [String] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_flags = AI_DEFAULT
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(ipv4, nil, &hints, &result) == 0 else { return [] }
        defer { if let result { freeaddrinfo(result) } }
        var current = result
        var values: [String] = []
        var visited = 0
        while let entry = current, visited < 256, values.count < TunnelEndpointCandidates.maximumCount {
            visited += 1
            defer { current = entry.pointee.ai_next }
            guard entry.pointee.ai_family == AF_INET6,
                  entry.pointee.ai_addrlen >= MemoryLayout<sockaddr_in6>.size,
                  let raw = entry.pointee.ai_addr else { continue }
            var ip = raw.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &ip, &buffer, socklen_t(buffer.count)) != nil else { continue }
            let text = String(cString: buffer)
            if !values.contains(text) { values.append(text) }
        }
        return values
    }
}

private final class SynthesisResult: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<[String], Error>?
    private var result: Result<[String], Error>?
    private var timer: DispatchWorkItem?
    var isFinished: Bool { lock.lock(); defer { lock.unlock() }; return result != nil }

    func attach(_ continuation: CheckedContinuation<[String], Error>) {
        lock.lock()
        if let result { lock.unlock(); continuation.resume(with: result) }
        else { self.continuation = continuation; lock.unlock() }
    }
    func install(_ timer: DispatchWorkItem) {
        lock.lock()
        if result != nil { lock.unlock(); timer.cancel() }
        else { self.timer = timer; lock.unlock() }
    }
    func finish(_ result: Result<[String], Error>) {
        lock.lock()
        guard self.result == nil else { lock.unlock(); return }
        self.result = result
        let continuation = continuation; self.continuation = nil
        let timer = timer; self.timer = nil
        lock.unlock()
        timer?.cancel()
        continuation?.resume(with: result)
    }
}
