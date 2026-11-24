import Foundation

public enum EmbeddedCoreError: Error, Equatable, Sendable {
    case alreadyRunning
    case notRunning
    case invalidConfigurationPath
    case startFailed(code: Int32)
    case validationFailed(code: Int32)
}

public enum EmbeddedCoreState: String, Sendable, Equatable {
    case idle
    case starting
    case running
    case stopping
}

/// Hooks connecting `EmbeddedCoreBridge` to the C-ABI `NexusCoreC` static library
/// (or deterministic test doubles on Swift Package CI without native C++ linking).
public struct EmbeddedCoreHooks: Sendable {
    public let version: @Sendable () -> String
    public let runArgs: @Sendable ([String]) -> Int32
    public let checkConfig: @Sendable (String) -> Int32
    public let requestStop: @Sendable () -> Void
    public let requestReload: @Sendable () -> Void
    public let isRunning: @Sendable () -> Bool

    public init(
        version: @escaping @Sendable () -> String,
        runArgs: @escaping @Sendable ([String]) -> Int32,
        checkConfig: @escaping @Sendable (String) -> Int32,
        requestStop: @escaping @Sendable () -> Void,
        requestReload: @escaping @Sendable () -> Void,
        isRunning: @escaping @Sendable () -> Bool
    ) {
        self.version = version
        self.runArgs = runArgs
        self.checkConfig = checkConfig
        self.requestStop = requestStop
        self.requestReload = requestReload
        self.isRunning = isRunning
    }
}

/// Swift 6 actor managing the in-process embedded Nexus core inside a macOS/iOS
/// Network Extension (`NEPacketTunnelProvider`) where `fork`/`exec` is disallowed.
public actor EmbeddedCoreBridge {
    private let hooks: EmbeddedCoreHooks
    private var state: EmbeddedCoreState = .idle
    private var runnerTask: Task<Int32, Never>?

    public init(hooks: EmbeddedCoreHooks) {
        self.hooks = hooks
    }

    public func currentState() -> EmbeddedCoreState { state }

    public func coreVersion() -> String { hooks.version() }

    public func validateConfiguration(at path: String) throws {
        guard !path.isEmpty else { throw EmbeddedCoreError.invalidConfigurationPath }
        let rc = hooks.checkConfig(path)
        guard rc == 0 else { throw EmbeddedCoreError.validationFailed(code: rc) }
    }

    public func start(launchConfig: PacketTunnelLaunchConfig) async throws {
        guard state == .idle, let argv = launchConfig.coreLaunchArguments() else {
            if state != .idle { throw EmbeddedCoreError.alreadyRunning }
            throw EmbeddedCoreError.invalidConfigurationPath
        }
        let checkArgs = argv.count >= 3 && argv[1] == "--config" ? argv[2] : ""
        try validateConfiguration(at: checkArgs)

        state = .starting
        let runArgs = hooks.runArgs
        let task = Task.detached(priority: .userInitiated) {
            runArgs(argv)
        }
        runnerTask = task
        state = .running

        // Yield once so caller can observe startup failure immediately if synchronous exit happens.
        await Task.yield()
        if hooks.isRunning() == false && task.isCancelled == false {
            // If the core already returned quickly with a non-zero exit code, report failure.
            let poll = await withTaskGroup(of: Int32?.self) { group in
                group.addTask { await task.value }
                group.addTask {
                    try? await Task.sleep(for: .milliseconds(5))
                    return nil
                }
                let first = await group.next() ?? nil
                group.cancelAll()
                return first
            }
            if let exitCode = poll {
                runnerTask = nil
                state = .idle
                if exitCode != 0 { throw EmbeddedCoreError.startFailed(code: exitCode) }
            }
        }
    }

    public func requestReload() throws {
        guard state == .running else { throw EmbeddedCoreError.notRunning }
        hooks.requestReload()
    }

    @discardableResult
    public func stop() async -> Int32 {
        guard let task = runnerTask else {
            state = .idle
            return 0
        }
        state = .stopping
        hooks.requestStop()
        let code = await task.value
        runnerTask = nil
        state = .idle
        return code
    }
}
