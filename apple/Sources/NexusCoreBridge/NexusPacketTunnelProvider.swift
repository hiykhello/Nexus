import Foundation
#if canImport(Darwin)
import Darwin
#endif
#if canImport(NetworkExtension)
import NetworkExtension
#endif

public enum MemoryPressureLevel: String, Sendable, Equatable {
    case normal
    case warning
    case critical
}

public enum TunnelMemoryMonitor {
    public static let hardLimitMiB: Double = 50.0

    public static func currentResidentMemoryMiB() -> Double {
        #if canImport(Darwin)
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), intPtr, &count)
            }
        }
        if kr == KERN_SUCCESS {
            return Double(info.phys_footprint) / (1024.0 * 1024.0)
        }
        #endif
        return 0.0
    }

    public static func pressureLevel(residentMiB: Double, budgetMiB: Int) -> MemoryPressureLevel {
        let cap = min(Double(budgetMiB), hardLimitMiB)
        if residentMiB >= hardLimitMiB * 0.92 { return .critical }
        if residentMiB >= cap { return .warning }
        return .normal
    }
}

/// Configuration payload passed via NETunnelProviderProtocol.providerConfiguration
/// from the host app into the macOS/iOS NEPacketTunnelProvider extension.
public struct PacketTunnelLaunchConfig: Sendable, Codable, Equatable {
    public let appGroupIdentifier: String
    public let configRelativePath: String
    public let controlSocketRelativePath: String
    public let dataDirectoryRelativePath: String
    public let httpControlPort: UInt16
    public let memoryBudgetMiB: Int

    public init(
        appGroupIdentifier: String = "group.org.nexus.apple",
        configRelativePath: String = "config.kdl",
        controlSocketRelativePath: String = "control.sock",
        dataDirectoryRelativePath: String = "data",
        httpControlPort: UInt16 = 9090,
        memoryBudgetMiB: Int = 36
    ) {
        self.appGroupIdentifier = appGroupIdentifier
        self.configRelativePath = configRelativePath
        self.controlSocketRelativePath = controlSocketRelativePath
        self.dataDirectoryRelativePath = dataDirectoryRelativePath
        self.httpControlPort = httpControlPort
        self.memoryBudgetMiB = memoryBudgetMiB
    }

    public func resolveContainerPaths(fileManager: FileManager = .default) -> (config: URL, controlSocket: URL, dataDirectory: URL)? {
        let root = fileManager.containerURL(forSecurityApplicationGroupIdentifier: appGroupIdentifier)
            ?? fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? fileManager.temporaryDirectory
        return (
            root.appendingPathComponent(configRelativePath),
            root.appendingPathComponent(controlSocketRelativePath),
            root.appendingPathComponent(dataDirectoryRelativePath)
        )
    }

    public func coreLaunchArguments(fileManager: FileManager = .default) -> [String]? {
        guard let paths = resolveContainerPaths(fileManager: fileManager) else { return nil }
        return ["run", "--config", paths.config.path, "-D", paths.dataDirectory.path]
    }
}

#if canImport(NetworkExtension)
private actor GenerationCounter {
    private var value: UInt64 = 0
    func next() -> UInt64 {
        value += 1
        return value
    }
}

/// Production-ready NEPacketTunnelProvider base class for macOS System Extension & iOS Network Extension.
/// Enforces < 50 MiB iOS extension memory discipline, zero-loop physical interface watching via
/// NetworkPathWatcher, and clean NEXUS/1 / HTTP control plane handoff.
open class NexusPacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {
    private let pathWatcher = NetworkPathWatcher()
    private var watchTask: Task<Void, Never>?
    private var activeControlClient: HttpControlClient?
    private var embeddedCore: EmbeddedCoreBridge?
    private var activeLaunchConfig = PacketTunnelLaunchConfig()
    private let generationCounter = GenerationCounter()

    public func attachEmbeddedCore(_ bridge: EmbeddedCoreBridge) {
        embeddedCore = bridge
    }

    open override func startTunnel(
        options: [String: NSObject]? = nil,
        completionHandler: @escaping @Sendable ((any Error)?) -> Void
    ) {
        Task { [self, completionHandler] in
            do {
                try await startTunnelSession()
                completionHandler(nil)
            } catch {
                completionHandler(error)
            }
        }
    }

    private func startTunnelSession() async throws {
        let launch = decodeLaunchConfig()
        activeLaunchConfig = launch
        let profile = AppleTunnelProfile(mtu: AppleTunnelProfile.maxSafeMtu)
        let settings = TunnelSettingsBuilder.build(from: profile)
        try await setTunnelNetworkSettings(settings)

        let token = KeychainTokenStore(accessGroup: launch.appGroupIdentifier).loadToken()
        let client = HttpControlClient(port: launch.httpControlPort, bearerToken: token)
        activeControlClient = client

        if let utun = packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32, utun >= 0 {
            if let utunName = resolveInterfaceName(for: utun) {
                pathWatcher.registerMyInterface(utunName)
            }
        }

        let counter = generationCounter
        watchTask = Task { [weak self, pathWatcher, client, counter] in
            for await snapshot in pathWatcher.updates() {
                if Task.isCancelled { break }
                if snapshot.hasConnectivity {
                    let nextGen = await counter.next()
                    try? await client.notifyNetworkChange(generation: nextGen)
                }
                _ = await self?.enforceMemoryWatermark()
            }
        }
    }

    open override func stopTunnel(with reason: NEProviderStopReason) async {
        watchTask?.cancel()
        watchTask = nil
        pathWatcher.stop()
        if let embedded = embeddedCore {
            await embedded.stop()
        }
        activeControlClient = nil
    }

    public func enforceMemoryWatermark() async -> MemoryPressureLevel {
        let resident = TunnelMemoryMonitor.currentResidentMemoryMiB()
        let level = TunnelMemoryMonitor.pressureLevel(residentMiB: resident, budgetMiB: activeLaunchConfig.memoryBudgetMiB)
        if level != .normal, let client = activeControlClient {
            _ = try? await client.clearCache()
        }
        return level
    }

    open override func handleAppMessage(_ messageData: Data) async -> Data? {
        guard let command = String(data: messageData, encoding: .utf8) else { return nil }
        if command == "reload", let embedded = embeddedCore {
            do {
                try await embedded.requestReload()
                return Data("ok".utf8)
            } catch {
                return Data("error".utf8)
            }
        }
        guard let client = activeControlClient else { return nil }
        switch command {
        case "status":
            let text = (try? await client.status()) ?? ""
            return text.data(using: .utf8)
        case "reload":
            let ok = (try? await client.reload()) != nil
            return Data((ok ? "ok" : "error").utf8)
        case "clear-cache":
            let ok = (try? await client.clearCache()) != nil
            return Data((ok ? "ok" : "error").utf8)
        case "memory":
            let resident = TunnelMemoryMonitor.currentResidentMemoryMiB()
            let level = await enforceMemoryWatermark()
            return Data(String(format: "%.1f MiB (%@)", resident, level.rawValue).utf8)
        case "network-change":
            let nextGen = await generationCounter.next()
            let ok = (try? await client.notifyNetworkChange(generation: nextGen)) != nil
            return Data((ok ? "ok" : "error").utf8)
        default:
            return nil
        }
    }

    private func decodeLaunchConfig() -> PacketTunnelLaunchConfig {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let raw = proto.providerConfiguration?["nexus_launch_json"] as? Data,
              let decoded = try? JSONDecoder().decode(PacketTunnelLaunchConfig.self, from: raw)
        else {
            return PacketTunnelLaunchConfig()
        }
        return decoded
    }

    private func resolveInterfaceName(for fd: Int32) -> String? {
        var name = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        var len = socklen_t(name.count)
        let rc = getsockopt(fd, 2 /* SYSPROTO_CONTROL */, 2 /* UTUN_OPT_IFNAME */, &name, &len)
        guard rc == 0 else { return nil }
        let bytes = name.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }
}
#endif
