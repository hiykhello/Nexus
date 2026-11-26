#if os(macOS) || os(iOS)
import Foundation
import Observation
import NexusCoreBridge

enum AppSection: String, CaseIterable, Identifiable, Hashable {
    case overview = "概览"
    case proxies = "代理与策略组"
    case workspace = "工作区"
    case rulesDns = "规则与 DNS"
    case connections = "活跃连接"
    case logs = "实时日志"
    case settings = "设置"

    var id: String { rawValue }

    var systemImage: String {
        switch self {
        case .overview: "gauge.with.dots.needle.50percent"
        case .proxies: "arrow.triangle.branch"
        case .workspace: "tray.full"
        case .rulesDns: "list.bullet.rectangle"
        case .connections: "network"
        case .logs: "text.alignleft"
        case .settings: "gearshape"
        }
    }
}

@MainActor
@Observable
final class NexusAppModel {
    var selectedSection: AppSection = .overview
    var isRunning = false
    var outboundMode = "rule"
    var backend: AppleTunnelBackend = .launchDaemonUtun
    @ObservationIgnored var _storedTunElevationMode: TunElevationMode = .persistentDaemon
    var tunElevationMode: TunElevationMode {
        get {
            access(keyPath: \.tunElevationMode)
            return _storedTunElevationMode
        }
        set {
            guard newValue != _storedTunElevationMode else { return }
            withMutation(keyPath: \.tunElevationMode) { _storedTunElevationMode = newValue }
            let db = clientDatabase
            let previous = elevationSaveTask
            elevationSaveTask = Task {
                _ = await previous?.value
                try? await PrivilegedDaemonController.saveElevationMode(newValue, to: db)
            }
        }
    }

    var daemonState: DaemonRegistrationState = .notRegistered
    var loginItemStatus: LoginItemStatus = .unsupported
    var statusSummary = "未连接"
    var statusSnapshot = StatusSnapshot()
    var residentMemoryMiB: Double = TunnelMemoryMonitor.currentResidentMemoryMiB()
    var rxRateBytesPerSec: Double = 0
    var txRateBytesPerSec: Double = 0
    var rxHistory: [Double] = Array(repeating: 0, count: 24)
    var txHistory: [Double] = Array(repeating: 0, count: 24)

    var network = AppleNetworkSnapshot(
        interfaceName: nil,
        interfaceIndex: -1,
        isExpensive: false,
        isConstrained: false,
        hasConnectivity: false
    )

    var logLevel = "info"
    var logDomainFilter = "all"
    var logSearch = ""
    var logs: [LogRingEntry] = []
    var isLogStreaming = false
    var isLogPaused = false

    var groups: [OutboundGroupSnapshot] = []
    var probingOutbounds: Set<String> = []
    var lastProbeBanner: String?

    var rules: [RuleMetric] = []
    var dnsResponse: DnsQueryResponse?
    var dnsError: String?
    var isQueryingDns = false
    var cacheActionMessage: String?

    var connections: [ActiveConnectionSnapshot] = []
    var selectedConnectionDetail: ActiveConnectionSnapshot?
    var metrics = MetricsSnapshot()
    var diagnostics = DiagnosticsSnapshot()

    var workspace = WorkspaceDocument()
    var hostConfig = AppleHostConfig()
    var activeProfileID = ""
    var syncConfig = WebDavSyncConfig()
    var syncStatusSummary = "未配置 WebDAV 同步"
    var syncConflictSummary: String?
    var controlEndpoint = "http://127.0.0.1:9090"
    var hasStoredBearerToken = false

    let watcher = NetworkPathWatcher()
    let session: ControlSocketSession
    var httpControl: HttpControlClient
    var activeControlURL: URL
    var activeControlToken: String?
    let keychainStore = KeychainTokenStore()
    let daemonController = PrivilegedDaemonController()
    let clientDatabase: NexusClientDatabase
    var networkGeneration: UInt64 = 0
    var lastSampleUp: UInt64 = 0
    var lastSampleDown: UInt64 = 0
    var lastSampleAt: Date?
    var monitorTask: Task<Void, Never>?
    var statusStreamTask: Task<Void, Never>?
    var logStreamTask: Task<Void, Never>?
    var elevationSaveTask: Task<Void, Never>?

    init() {
        let sockPath = "/var/run/org.nexus.apple/c.sock"
        let defaultURL = URL(string: "http://127.0.0.1:9090")!
        self.clientDatabase = NexusClientDatabase(rootDirectory: Self.defaultWorkspaceDirectory())
        self.session = ControlSocketSession(socketPath: sockPath)
        let savedToken = KeychainTokenStore().loadToken()
        self.hasStoredBearerToken = (savedToken?.isEmpty == false)
        self.activeControlURL = defaultURL
        self.activeControlToken = savedToken
        self.httpControl = HttpControlClient(baseURL: defaultURL, bearerToken: savedToken)
        self.daemonState = daemonController.status()
        self.loginItemStatus = LoginItemManager.currentStatus()
        startNetworkMonitor()
    }

    var showDaemonManagementControls: Bool {
        daemonController.shouldShowDaemonControls(for: tunElevationMode, state: daemonState)
    }

    var activeWorkspaceProfile: WorkspaceProfileItem? {
        if !activeProfileID.isEmpty, let match = workspace.profiles.first(where: { $0.id == activeProfileID }) {
            return match
        }
        return workspace.profiles.first
    }

    var activeProfileKindBadge: String {
        activeWorkspaceProfile?.kind.badgeTitle ?? "未选择"
    }

    var activeProfileDisplayName: String {
        guard let profile = activeWorkspaceProfile else { return "默认配置" }
        return profile.remarks.isEmpty ? profile.id : profile.remarks
    }

    var primaryGroup: OutboundGroupSnapshot? {
        groups.first
    }

    var activeGroupRttMs: Int64? {
        guard let group = primaryGroup,
              let member = group.members.first(where: { $0.name == group.active })
        else { return nil }
        if let ewma = member.ewmaMs, ewma >= 0 { return ewma }
        return member.latencyMs >= 0 ? member.latencyMs : nil
    }

    var workspaceSummaryText: String {
        "r\(workspace.revision) · \(workspace.profiles.count) 配置 · \(workspace.subscriptions.count) 订阅"
    }

    static func defaultWorkspaceDirectory() -> URL {
        let fm = FileManager.default
        let root = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first ?? fm.temporaryDirectory
        return root.appendingPathComponent("Nexus", isDirectory: true)
    }

    private func startNetworkMonitor() {
        monitorTask?.cancel()
        let pathWatcher = watcher
        monitorTask = Task { [weak self] in
            for await snap in pathWatcher.updates() {
                guard let self, !Task.isCancelled else { break }
                self.network = snap
                if self.isRunning {
                    self.networkGeneration += 1
                    _ = try? await self.session.notifyNetworkChange(generation: self.networkGeneration)
                    try? await self.httpControl.notifyNetworkChange(generation: self.networkGeneration)
                }
            }
        }
    }

    func startLiveStreams() {
        if statusStreamTask == nil {
            let client = httpControl
            statusStreamTask = Task { [weak self] in
                do {
                    for try await snap in client.streamStatus(intervalMs: 1000) {
                        guard let self, !Task.isCancelled else { break }
                        self.applyStatusSnapshot(snap)
                    }
                } catch {}
                self?.statusStreamTask = nil
            }
        }
        if logStreamTask == nil && !isLogPaused {
            let client = httpControl
            let sinceSeq = logs.last?.seq ?? 0
            isLogStreaming = true
            logStreamTask = Task { [weak self] in
                do {
                    for try await entry in client.streamLogs(level: "trace", since: sinceSeq) {
                        guard let self, !Task.isCancelled else { break }
                        if !self.isLogPaused { self.appendLogEntry(entry) }
                    }
                } catch {}
                self?.isLogStreaming = false
                self?.logStreamTask = nil
            }
        }
    }

    func stopLiveStreams() {
        statusStreamTask?.cancel()
        statusStreamTask = nil
        logStreamTask?.cancel()
        logStreamTask = nil
        isLogStreaming = false
    }

    func toggleLogPause() {
        isLogPaused.toggle()
        if isLogPaused {
            logStreamTask?.cancel()
            logStreamTask = nil
            isLogStreaming = false
        } else {
            startLiveStreams()
        }
    }

    func applyStatusSnapshot(_ snap: StatusSnapshot) {
        statusSnapshot = snap
        isRunning = snap.state.lowercased() == "running"
        statusSummary = "\(snap.state) · \(snap.workers) 线程 · \(snap.listeners) 监听"
        metrics = MetricsSnapshot(
            controlGeneration: snap.controlGeneration,
            activeSessions: snap.activeSessions,
            uploadBytes: snap.uploadBytesTotal,
            downloadBytes: snap.downloadBytesTotal
        )
        recordThroughputSample(up: snap.uploadBytesTotal, down: snap.downloadBytesTotal)
        residentMemoryMiB = TunnelMemoryMonitor.currentResidentMemoryMiB()
    }

    func recordThroughputSample(up: UInt64, down: UInt64) {
        let now = Date()
        if let prev = lastSampleAt {
            let dt = max(0.2, now.timeIntervalSince(prev))
            let dUp = up >= lastSampleUp ? Double(up - lastSampleUp) / dt : 0
            let dDown = down >= lastSampleDown ? Double(down - lastSampleDown) / dt : 0
            txRateBytesPerSec = dUp
            rxRateBytesPerSec = dDown
            txHistory.append(dUp)
            rxHistory.append(dDown)
            if txHistory.count > 24 { txHistory.removeFirst(txHistory.count - 24) }
            if rxHistory.count > 24 { rxHistory.removeFirst(rxHistory.count - 24) }
        }
        lastSampleUp = up
        lastSampleDown = down
        lastSampleAt = now
    }

    func appendLogEntry(_ entry: LogRingEntry) {
        if logs.last?.seq == entry.seq { return }
        logs.append(entry)
        if logs.count > 500 { logs.removeFirst(logs.count - 500) }
    }
}
#endif
