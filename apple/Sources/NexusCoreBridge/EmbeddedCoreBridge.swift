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

/// C-ABI compatible Swift hook signatures matching `include/nexus/core_c_api.h` and Wave 23 workspace/sync contracts.
public typealias ComposeWorkspaceHook = @Sendable (
    _ workspaceJSON: String,
    _ hostJSON: String,
    _ secretsDir: String,
    _ activeProfileID: String
) -> (code: Int32, resultJSON: String, errorMessage: String)

public typealias ExportShareHook = @Sendable (
    _ workspaceJSON: String,
    _ profileIDs: [String]
) -> (code: Int32, resultJSON: String, errorMessage: String)

public typealias ImportShareHook = @Sendable (
    _ workspaceJSON: String,
    _ uri: String,
    _ subscriptionID: String
) -> (code: Int32, resultJSON: String, errorMessage: String)

public typealias SealSyncHook = @Sendable (
    _ workspaceJSON: String,
    _ passphrase: String,
    _ deviceLabel: String
) -> (code: Int32, resultJSON: String, errorMessage: String)

public typealias OpenSyncHook = @Sendable (
    _ envelopeJSON: String,
    _ passphrase: String
) -> (code: Int32, resultJSON: String, errorMessage: String)

/// Hooks connecting `EmbeddedCoreBridge` to the C-ABI `NexusCoreC` static library
/// (or deterministic test doubles on Swift Package CI without native C++ linking).
public struct EmbeddedCoreHooks: Sendable {
    public let version: @Sendable () -> String
    public let runArgs: @Sendable ([String]) -> Int32
    public let checkConfig: @Sendable (String) -> Int32
    public let requestStop: @Sendable () -> Void
    public let requestReload: @Sendable () -> Void
    public let isRunning: @Sendable () -> Bool
    public let composeWorkspace: ComposeWorkspaceHook?
    public let exportShare: ExportShareHook?
    public let importShare: ImportShareHook?
    public let sealSync: SealSyncHook?
    public let openSync: OpenSyncHook?

    public init(
        version: @escaping @Sendable () -> String,
        runArgs: @escaping @Sendable ([String]) -> Int32,
        checkConfig: @escaping @Sendable (String) -> Int32,
        requestStop: @escaping @Sendable () -> Void,
        requestReload: @escaping @Sendable () -> Void,
        isRunning: @escaping @Sendable () -> Bool,
        composeWorkspace: ComposeWorkspaceHook? = nil,
        exportShare: ExportShareHook? = nil,
        importShare: ImportShareHook? = nil,
        sealSync: SealSyncHook? = nil,
        openSync: OpenSyncHook? = nil
    ) {
        self.version = version
        self.runArgs = runArgs
        self.checkConfig = checkConfig
        self.requestStop = requestStop
        self.requestReload = requestReload
        self.isRunning = isRunning
        self.composeWorkspace = composeWorkspace
        self.exportShare = exportShare
        self.importShare = importShare
        self.sealSync = sealSync
        self.openSync = openSync
    }
}

/// Lock-protected one-shot completion box bridging the blocking worker `Foundation.Thread`
/// to Swift Concurrency without occupying a cooperative pool thread.
///
/// Concurrency invariant (`@unchecked Sendable`):
/// All mutable properties (`exitCode`, `waiters`) are exclusively accessed while holding `lock`.
/// Continuations are always resumed outside `lock` to avoid reentrancy or lock-order inversion.
/// Replace `NSLock` with `Synchronization.Mutex` when deployment raises to macOS 15+ / iOS 18+.
private final class RunCompletionBox: @unchecked Sendable {
    private let lock = NSLock()
    private var exitCode: Int32?
    private var waiters: [CheckedContinuation<Int32, Never>] = []

    func finish(code: Int32) {
        let pending: [CheckedContinuation<Int32, Never>] = lock.withLock {
            if exitCode != nil {
                return []
            }
            exitCode = code
            let current = waiters
            waiters.removeAll(keepingCapacity: false)
            return current
        }
        for continuation in pending {
            continuation.resume(returning: code)
        }
    }

    func currentExitCode() -> Int32? {
        lock.withLock { exitCode }
    }

    func wait() async -> Int32 {
        if let code = currentExitCode() {
            return code
        }
        return await withCheckedContinuation { continuation in
            enqueueOrResume(continuation)
        }
    }

    private func enqueueOrResume(_ continuation: CheckedContinuation<Int32, Never>) {
        let immediate: Int32? = lock.withLock {
            if let code = exitCode {
                return code
            }
            waiters.append(continuation)
            return nil
        }
        if let immediate {
            continuation.resume(returning: immediate)
        }
    }
}

/// Swift 6 actor managing the in-process embedded Nexus core inside a macOS/iOS
/// Network Extension (`NEPacketTunnelProvider`) where `fork`/`exec` is disallowed.
public actor EmbeddedCoreBridge {
    private let hooks: EmbeddedCoreHooks
    private var state: EmbeddedCoreState = .idle
    private var completionBox: RunCompletionBox?

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
        guard state == .idle else {
            throw EmbeddedCoreError.alreadyRunning
        }
        guard let argv = launchConfig.coreLaunchArguments() else {
            throw EmbeddedCoreError.invalidConfigurationPath
        }
        let configPath: String
        if let idx = argv.firstIndex(of: "--config"), idx + 1 < argv.count {
            configPath = argv[idx + 1]
        } else {
            configPath = ""
        }
        try validateConfiguration(at: configPath)

        state = .starting
        let box = RunCompletionBox()
        completionBox = box
        let runArgs = hooks.runArgs
        Self.launchWorkerThread(argv: argv, runArgs: runArgs, box: box)
        state = .running

        // Non-blocking early-failure probe: give the dedicated worker thread a brief window
        // to report immediate startup failure or begin running without blocking Swift's
        // cooperative thread pool.
        let maxProbeSteps = 10
        for step in 0..<maxProbeSteps {
            if completionBox !== box || state != .running { break }
            if box.currentExitCode() != nil { break }
            if step > 0 && hooks.isRunning() { break }
            do {
                try await Task.sleep(for: .milliseconds(5))
            } catch {
                break
            }
        }

        if completionBox === box, state == .running, let code = box.currentExitCode() {
            completionBox = nil
            state = .idle
            if code != 0 {
                throw EmbeddedCoreError.startFailed(code: code)
            }
        }
    }

    public func requestReload() throws {
        guard state == .running else { throw EmbeddedCoreError.notRunning }
        hooks.requestReload()
    }

    @discardableResult
    public func stop() async -> Int32 {
        guard let box = completionBox else {
            state = .idle
            return 0
        }
        if state != .stopping {
            state = .stopping
            hooks.requestStop()
        }
        let code = await box.wait()
        if completionBox === box {
            completionBox = nil
            state = .idle
        }
        return code
    }

    private static func launchWorkerThread(
        argv: [String],
        runArgs: @escaping @Sendable ([String]) -> Int32,
        box: RunCompletionBox
    ) {
        let thread = Foundation.Thread {
            let code = runArgs(argv)
            box.finish(code: code)
        }
        thread.name = "org.nexus.embedded-core"
        thread.qualityOfService = .userInitiated
        thread.start()
    }
}
