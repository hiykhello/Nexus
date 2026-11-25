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

public enum DaemonRegistrationState: String, Sendable, Equatable {
    case enabled
    case requiresApproval
    case notRegistered
    case unsupported

    public var isRegisteredOrPending: Bool {
        self == .enabled || self == .requiresApproval
    }

    public var summaryText: String {
        switch self {
        case .enabled: return "已启用 (LaunchDaemon 就绪)"
        case .requiresApproval: return "请在系统设置 -> 登录项中批准"
        case .notRegistered: return "未注册"
        case .unsupported: return "当前平台不支持 SMAppService"
        }
    }
}

public enum DaemonElevationError: Error, LocalizedError, Equatable, Sendable {
    case invalidPath(String)

    public var errorDescription: String? {
        switch self {
        case .invalidPath(let field):
            return "Invalid or unsafe path for \(field)"
        }
    }
}

/// User-selectable macOS TUN elevation policy matching Desktop's persistent vs session-only model.
public enum TunElevationMode: String, Codable, Sendable, Equatable, Hashable, CaseIterable, Identifiable {
    /// One-time privileged LaunchDaemon registration via SMAppService (zero repeated prompts).
    case persistentDaemon = "persistent_daemon"
    /// On-demand per-session administrator elevation (no background daemon installed).
    case sessionOnly = "session_only"

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .persistentDaemon: return "持久授权 (LaunchDaemon)"
        case .sessionOnly: return "仅本次会话 (按次提权)"
        }
    }

    public var detailText: String {
        switch self {
        case .persistentDaemon:
            return "一次性注册特权 LaunchDaemon（SMAppService），后续开启 TUN 无需重复输入密码或 Touch ID。"
        case .sessionOnly:
            return "不安装常驻后台守护进程，仅在本次需要 TUN 时按次请求管理员权限。"
        }
    }
}

public struct TunElevationCapability: Sendable, Equatable {
    public let supportsPersistentDaemon: Bool
    public let supportsSessionOnly: Bool
    public let daemonState: DaemonRegistrationState

    public init(
        supportsPersistentDaemon: Bool,
        supportsSessionOnly: Bool,
        daemonState: DaemonRegistrationState
    ) {
        self.supportsPersistentDaemon = supportsPersistentDaemon
        self.supportsSessionOnly = supportsSessionOnly
        self.daemonState = daemonState
    }

    public var isPersistentReady: Bool {
        supportsPersistentDaemon && daemonState == .enabled
    }

    public func requiresInteractivePrompt(for mode: TunElevationMode) -> Bool {
        switch mode {
        case .persistentDaemon:
            return !isPersistentReady
        case .sessionOnly:
            return true
        }
    }
}

/// Hardened macOS LaunchDaemon property-list specification matching `org.nexus.apple.daemon.plist`.
public struct LaunchDaemonPlistSpec: Sendable, Equatable {
    public let label: String
    public let binaryPath: String
    public let configPath: String
    public let dataDirectory: String
    public let workingDirectory: String
    public let runAtLoad: Bool
    public let keepAliveOnCrash: Bool
    public let throttleIntervalSeconds: Int
    public let umask: Int
    public let maxOpenFiles: Int
    public let standardOutPath: String
    public let standardErrorPath: String

    public init(
        label: String = PrivilegedDaemonController.defaultLabel,
        binaryPath: String = "/Library/Application Support/Nexus/bin/nexus",
        configPath: String = "/Library/Application Support/Nexus/config.kdl",
        dataDirectory: String = "/var/lib/nexus",
        workingDirectory: String = "/var/lib/nexus",
        runAtLoad: Bool = true,
        keepAliveOnCrash: Bool = true,
        throttleIntervalSeconds: Int = 5,
        umask: Int = 18,
        maxOpenFiles: Int = 65_536,
        standardOutPath: String = "/var/log/org.nexus.apple.daemon.log",
        standardErrorPath: String = "/var/log/org.nexus.apple.daemon.log"
    ) {
        self.label = label
        self.binaryPath = binaryPath
        self.configPath = configPath
        self.dataDirectory = dataDirectory
        self.workingDirectory = workingDirectory
        self.runAtLoad = runAtLoad
        self.keepAliveOnCrash = keepAliveOnCrash
        self.throttleIntervalSeconds = max(1, throttleIntervalSeconds)
        self.umask = umask
        self.maxOpenFiles = max(1024, maxOpenFiles)
        self.standardOutPath = standardOutPath
        self.standardErrorPath = standardErrorPath
    }

    public var programArguments: [String] {
        var args = [binaryPath]
        if !dataDirectory.isEmpty {
            args.append(contentsOf: ["-D", dataDirectory])
        }
        args.append(contentsOf: ["run", "--config", configPath])
        return args
    }
}

/// Thin wrapper over macOS 13+ SMAppService.daemon (replaces deprecated SMJobBless).
public struct PrivilegedDaemonController: Sendable {
    public static let defaultPlistName = "org.nexus.apple.daemon.plist"
    public static let defaultLabel = "org.nexus.apple.daemon"
    public static let elevationModeDefaultsKey = "org.nexus.apple.tunElevationMode"

    public let plistName: String

    public init(plistName: String = PrivilegedDaemonController.defaultPlistName) {
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

    public func capability() -> TunElevationCapability {
        let current = status()
        #if os(macOS) && canImport(ServiceManagement)
        return TunElevationCapability(
            supportsPersistentDaemon: true,
            supportsSessionOnly: true,
            daemonState: current
        )
        #else
        return TunElevationCapability(
            supportsPersistentDaemon: false,
            supportsSessionOnly: false,
            daemonState: current
        )
        #endif
    }

    public func shouldShowDaemonControls(
        for mode: TunElevationMode,
        state: DaemonRegistrationState? = nil
    ) -> Bool {
        let effectiveState = state ?? status()
        return mode == .persistentDaemon || effectiveState.isRegisteredOrPending
    }

    public static func loadSavedElevationMode(defaults: UserDefaults = .standard) -> TunElevationMode {
        guard let raw = defaults.string(forKey: elevationModeDefaultsKey),
              let mode = TunElevationMode(rawValue: raw)
        else {
            return .persistentDaemon
        }
        return mode
    }

    public static func saveElevationMode(_ mode: TunElevationMode, defaults: UserDefaults = .standard) {
        defaults.set(mode.rawValue, forKey: elevationModeDefaultsKey)
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

    public static func renderLaunchDaemonPlist(spec: LaunchDaemonPlistSpec = LaunchDaemonPlistSpec()) -> String {
        var lines: [String] = [
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">",
            "<plist version=\"1.0\">",
            "<dict>",
            "    <key>Label</key>",
            "    <string>\(xmlEscape(spec.label))</string>",
            "    <key>ProgramArguments</key>",
            "    <array>",
        ]
        for arg in spec.programArguments {
            lines.append("        <string>\(xmlEscape(arg))</string>")
        }
        lines.append("    </array>")
        if !spec.workingDirectory.isEmpty {
            lines.append("    <key>WorkingDirectory</key>")
            lines.append("    <string>\(xmlEscape(spec.workingDirectory))</string>")
        }
        lines.append("    <key>RunAtLoad</key>")
        lines.append(spec.runAtLoad ? "    <true/>" : "    <false/>")
        lines.append("    <key>KeepAlive</key>")
        if spec.keepAliveOnCrash {
            lines.append("    <dict>")
            lines.append("        <key>SuccessfulExit</key>")
            lines.append("        <false/>")
            lines.append("    </dict>")
        } else {
            lines.append("    <false/>")
        }
        lines.append(contentsOf: [
            "    <key>ThrottleInterval</key>",
            "    <integer>\(spec.throttleIntervalSeconds)</integer>",
            "    <key>Umask</key>",
            "    <integer>\(spec.umask)</integer>",
            "    <key>SoftResourceLimits</key>",
            "    <dict>",
            "        <key>NumberOfFiles</key>",
            "        <integer>\(spec.maxOpenFiles)</integer>",
            "    </dict>",
            "    <key>ProcessType</key>",
            "    <string>Interactive</string>",
            "    <key>StandardOutPath</key>",
            "    <string>\(xmlEscape(spec.standardOutPath))</string>",
            "    <key>StandardErrorPath</key>",
            "    <string>\(xmlEscape(spec.standardErrorPath))</string>",
            "</dict>",
            "</plist>",
        ])
        return lines.joined(separator: "\n") + "\n"
    }

    /// Quotes an arbitrary string as a single POSIX `/bin/sh` literal argument using single quotes.
    /// NUL bytes are stripped because POSIX `argv` entries are C strings and cannot hold NUL.
    public static func quotePosixShellArg(_ argument: String) -> String {
        var out = "'"
        out.reserveCapacity(argument.count + 2)
        for scalar in argument.unicodeScalars {
            if scalar.value == 0 { continue }
            if scalar == "'" {
                out.append("'\\''")
            } else {
                out.unicodeScalars.append(scalar)
            }
        }
        out.append("'")
        return out
    }

    /// Escapes a string for safe inclusion inside an AppleScript double-quoted string literal.
    public static func escapeAppleScriptString(_ value: String) -> String {
        var out = ""
        out.reserveCapacity(value.count)
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0: continue
            case 0x5C: out.append("\\\\") // \
            case 0x22: out.append("\\\"") // "
            case 0x0A: out.append("\\n")  // LF
            case 0x0D: out.append("\\r")  // CR
            case 0x09: out.append("\\t")  // TAB
            default: out.unicodeScalars.append(scalar)
            }
        }
        return out
    }

    /// Builds an injection-safe AppleScript `do shell script ... with administrator privileges`
    /// command for non-persistent macOS session-only utun elevation via `osascript`.
    public static func buildSessionElevationAppleScript(
        binaryPath: String,
        configPath: String,
        workingDirectory: String? = nil
    ) throws -> String {
        try Self.validateElevationPath(binaryPath, field: "binaryPath")
        try Self.validateElevationPath(configPath, field: "configPath")

        var commandParts: [String] = []
        if let workingDirectory, !workingDirectory.isEmpty {
            try Self.validateElevationPath(workingDirectory, field: "workingDirectory")
            let qDir = Self.quotePosixShellArg(workingDirectory)
            let qBin = Self.quotePosixShellArg(binaryPath)
            let qCfg = Self.quotePosixShellArg(configPath)
            commandParts.append("cd \(qDir) &&")
            commandParts.append("exec \(qBin) -D \(qDir) run --config \(qCfg)")
        } else {
            let qBin = Self.quotePosixShellArg(binaryPath)
            let qCfg = Self.quotePosixShellArg(configPath)
            commandParts.append("exec \(qBin) run --config \(qCfg)")
        }

        let shellCommand = commandParts.joined(separator: " ")
        return "do shell script \"\(Self.escapeAppleScriptString(shellCommand))\" with administrator privileges"
    }

    private static func validateElevationPath(_ path: String, field: String) throws {
        guard !path.isEmpty, path.hasPrefix("/") else {
            throw DaemonElevationError.invalidPath(field)
        }
        for scalar in path.unicodeScalars {
            if scalar.value == 0 || scalar.value == 0x0A || scalar.value == 0x0D {
                throw DaemonElevationError.invalidPath(field)
            }
        }
    }

    private static func xmlEscape(_ raw: String) -> String {
        var out = ""
        out.reserveCapacity(raw.count)
        for scalar in raw.unicodeScalars {
            switch scalar {
            case "&": out.append("&amp;")
            case "<": out.append("&lt;")
            case ">": out.append("&gt;")
            case "\"": out.append("&quot;")
            case "'": out.append("&apos;")
            default:
                let v = scalar.value
                if v == 0x09 || v == 0x0A || v == 0x0D || v >= 0x20 {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out
    }
}

public func renderLaunchDaemonPlist(spec: LaunchDaemonPlistSpec = LaunchDaemonPlistSpec()) -> String {
    PrivilegedDaemonController.renderLaunchDaemonPlist(spec: spec)
}

public func quotePosixShellArg(_ argument: String) -> String {
    PrivilegedDaemonController.quotePosixShellArg(argument)
}

public func buildSessionElevationAppleScript(
    binaryPath: String,
    configPath: String,
    workingDirectory: String? = nil
) throws -> String {
    try PrivilegedDaemonController.buildSessionElevationAppleScript(
        binaryPath: binaryPath,
        configPath: configPath,
        workingDirectory: workingDirectory
    )
}
