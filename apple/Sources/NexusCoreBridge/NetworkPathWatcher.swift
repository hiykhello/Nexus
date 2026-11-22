import Foundation
#if canImport(Network)
import Network
#endif

public struct AppleNetworkSnapshot: Sendable, Equatable {
    public let interfaceName: String?
    public let interfaceIndex: Int
    public let isExpensive: Bool
    public let isConstrained: Bool
    public let hasConnectivity: Bool

    public init(
        interfaceName: String?,
        interfaceIndex: Int,
        isExpensive: Bool,
        isConstrained: Bool,
        hasConnectivity: Bool
    ) {
        self.interfaceName = interfaceName
        self.interfaceIndex = interfaceIndex
        self.isExpensive = isExpensive
        self.isConstrained = isConstrained
        self.hasConnectivity = hasConnectivity
    }
}

/// Watches the active non-TUN physical interface via Apple Network.framework NWPathMonitor.
/// Filters out our own utun interface name to prevent self-triggered network-change loops.
///
/// Concurrency invariant (`@unchecked Sendable`):
/// All mutable properties (`ignoredInterfaces`, `lastSnapshot`, `monitor`) are exclusively
/// accessed on the private serial `queue`. Replace with `Mutex` when deployment raises to macOS 15+.
public final class NetworkPathWatcher: @unchecked Sendable {
    private let queue = DispatchQueue(label: "org.nexus.apple.network-watcher")
    private var ignoredInterfaces: Set<String> = []
    private var lastSnapshot: AppleNetworkSnapshot?

    #if canImport(Network)
    private var monitor: NWPathMonitor?
    #endif

    public init() {}

    public func registerMyInterface(_ name: String) {
        queue.sync { _ = ignoredInterfaces.insert(name) }
    }

    public func start(onChange: @escaping @Sendable (AppleNetworkSnapshot) -> Void) {
        queue.async { [weak self] in
            guard let self else { return }
            #if canImport(Network)
            self.monitor?.cancel()
            let m = NWPathMonitor()
            m.pathUpdateHandler = { [weak self] path in
                guard let self else { return }
                let primary = path.availableInterfaces.first { iface in
                    !self.ignoredInterfaces.contains(iface.name) && iface.type != .other
                } ?? path.availableInterfaces.first { !self.ignoredInterfaces.contains($0.name) }

                let next = AppleNetworkSnapshot(
                    interfaceName: primary?.name,
                    interfaceIndex: primary?.index ?? -1,
                    isExpensive: path.isExpensive,
                    isConstrained: path.isConstrained,
                    hasConnectivity: path.status == .satisfied
                )
                if next != self.lastSnapshot {
                    self.lastSnapshot = next
                    onChange(next)
                }
            }
            m.start(queue: self.queue)
            self.monitor = m
            #endif
        }
    }

    /// Structured AsyncStream interface with automatic NWPathMonitor cancellation on termination.
    public func updates() -> AsyncStream<AppleNetworkSnapshot> {
        AsyncStream { continuation in
            self.start { snapshot in
                continuation.yield(snapshot)
            }
            continuation.onTermination = { [weak self] _ in
                self?.stop()
            }
        }
    }

    public func stop() {
        queue.async { [weak self] in
            #if canImport(Network)
            self?.monitor?.cancel()
            self?.monitor = nil
            #endif
        }
    }
}
