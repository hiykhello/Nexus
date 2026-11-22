import Foundation
#if os(macOS) && canImport(ServiceManagement)
import ServiceManagement
#endif

public enum AppleTunnelBackend: String, Sendable, CaseIterable {
    /// Stage A: Open-source SMAppService privileged LaunchDaemon + utun (zero Apple Developer account required).
    case launchDaemonUtun = "LaunchDaemon (utun)"
    /// Stage B: Signed NEPacketTunnelProvider System Extension (native macOS/iOS VPN settings).
    case networkExtension = "Network Extension"
}

public enum DaemonRegistrationState: String, Sendable {
    case enabled
    case requiresApproval
    case notRegistered
    case unsupported
}

/// Thin wrapper over macOS 13+ SMAppService.daemon (replaces deprecated SMJobBless).
public struct PrivilegedDaemonController: Sendable {
    public let plistName: String

    public init(plistName: String = "org.nexus.apple.daemon.plist") {
        self.plistName = plistName
    }

    public func status() -> DaemonRegistrationState {
        #if os(macOS) && canImport(ServiceManagement)
        let service = SMAppService.daemon(plistName: plistName)
        switch service.status {
        case .enabled: return .enabled
        case .requiresApproval: return .requiresApproval
        case .notRegistered, .notFound: return .notRegistered
        @unknown default: return .notRegistered
        }
        #else
        return .unsupported
        #endif
    }

    public func register() throws {
        #if os(macOS) && canImport(ServiceManagement)
        try SMAppService.daemon(plistName: plistName).register()
        #endif
    }

    public func unregister() async throws {
        #if os(macOS) && canImport(ServiceManagement)
        try await SMAppService.daemon(plistName: plistName).unregister()
        #endif
    }
}
