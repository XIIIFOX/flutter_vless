import Foundation

/// The selected interface is a socket-binding choice, not an observation of a
/// Core socket. Family flags come from the corresponding scoped path monitor.
enum TunnelUnderlayPathSelection {
    enum Kind: Int, CaseIterable, Hashable, Sendable {
        case wired, wifi, cellular, other
    }

    struct Interface: Equatable, Sendable {
        let index: UInt32
        let name: String
    }

    struct ScopedPath: Equatable, Sendable {
        let satisfied: Bool
        let interfaces: [Interface]
        let supportsIPv4: Bool
        let supportsIPv6: Bool
        let supportsDNS: Bool
    }

    static func choose(preferred: [UInt32], scoped: [Kind: ScopedPath],
                       excluding: Set<UInt32>) -> TunnelEndpointPath? {
        selection(preferred: preferred, scoped: scoped, excluding: excluding)?.path
    }

    static func selection(preferred: [UInt32], scoped: [Kind: ScopedPath],
                          excluding: Set<UInt32>) -> (kind: Kind, path: TunnelEndpointPath)? {
        let choices: [(Kind, Interface, ScopedPath)] = Kind.allCases.compactMap { kind in
            guard let path = scoped[kind], path.satisfied,
                  path.supportsIPv4 || path.supportsIPv6,
                  let interface = path.interfaces.first,
                  interface.index != 0, !excluding.contains(interface.index),
                  validName(interface.name) else { return nil }
            // If the scoped path prefers our tunnel, another available interface
            // in that same path does not inherit its family-capability evidence.
            return (kind, interface, path)
        }
        let ordered = choices.sorted {
            let lhs = preferred.firstIndex(of: $0.1.index) ?? Int.max
            let rhs = preferred.firstIndex(of: $1.1.index) ?? Int.max
            return lhs == rhs ? $0.0.rawValue < $1.0.rawValue : lhs < rhs
        }
        guard let selected = ordered.first else { return nil }
        return (selected.0, TunnelEndpointPath(generation: 0, interfaceIndex: selected.1.index,
            interfaceName: selected.1.name, supportsIPv4: selected.2.supportsIPv4,
            supportsIPv6: selected.2.supportsIPv6, supportsDNS: selected.2.supportsDNS))
    }

    static func validName(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count < 16 && value.utf8.allSatisfy {
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
                || $0 == 45 || $0 == 46 || $0 == 95
        }
    }
}
