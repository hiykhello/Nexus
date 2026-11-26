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

    var supportsSearchFocus: Bool {
        switch self {
        case .proxies, .workspace, .rulesDns, .connections, .logs:
            return true
        case .overview, .settings:
            return false
        }
    }
}

@MainActor
@Observable
final class NexusAppModel {
    static let compactMobileTabs: [AppSection] = [.overview, .proxies, .rulesDns, .connections, .settings]

    static var appVersionLabel: String {
        if let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String, !version.isEmpty {
            return "v\(version)"
        }
        return "v1.0"
    }

    var selectedSection: AppSection = .overview
    var pendingSearchFocusSection: AppSection?
    var searchFocusTrigger: Int = 0
    var themePreset: NexusThemePreset = .system
    var showCommandPalette = false
    var commandPaletteInitialQuery = ""
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
            elevationSaveGeneration &+= 1
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
    var actionErrorMessage: String?
    var statusSnapshot = StatusSnapshot()
    var residentMemoryMiB: Double = TunnelMemoryMonitor.currentResidentMemoryMiB()
    var coreMemoryMiB: Double?
    var rxRateBytesPerSec: Double = 0
    var txRateBytesPerSec: Double = 0
    var rxHistory: [Double] = Array(repeating: 0, count: 24)
    var txHistory: [Double] = Array(repeating: 0, count: 24)
    var sparklineOnsetTracker = SparklineOnsetTracker(capacity: 24)

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
    var syncStatusSummary = "未配置同步"
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
    var wsStreamTask: Task<Void, Never>?
    var statusStreamTask: Task<Void, Never>?
    var connectionsStreamTask: Task<Void, Never>?
    var logStreamTask: Task<Void, Never>?
    var elevationSaveTask: Task<Void, Never>?
    var themeSaveTask: Task<Void, Never>?
    var elevationSaveGeneration: UInt64 = 0
    var themeSaveGeneration: UInt64 = 0
    var isWebSocketActive = false
    var liveStreamGeneration: UInt64 = 0
    var outboundModeTransition = OptimisticTransition(initial: "rule")
    var logLevelGeneration: UInt64 = 0
    var groupSelectionGeneration: UInt64 = 0

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

    func triggerSearchFocus() {
        let target: AppSection = selectedSection.supportsSearchFocus ? selectedSection : .rulesDns
        selectedSection = target
        pendingSearchFocusSection = target
        searchFocusTrigger &+= 1
    }

    func consumeSearchFocus(for section: AppSection) {
        if pendingSearchFocusSection == section {
            pendingSearchFocusSection = nil
        }
    }

    func normalizeCompactSelection() {
        selectedSection = CompactTabNormalizer.normalize(
            selected: selectedSection,
            compactTabs: Self.compactMobileTabs,
            fallback: .overview
        )
    }

    func clearActionError() {
        actionErrorMessage = nil
    }

    func openCommandPalette(initialQuery: String = "") {
        commandPaletteInitialQuery = initialQuery
        showCommandPalette = true
    }

    func closeCommandPalette() {
        showCommandPalette = false
    }

    func recordSparklineOnset(_ label: String) {
        sparklineOnsetTracker.record(label: label, at: max(0, rxHistory.count - 1))
    }

    var sparklineOnsets: [SparklineOnsetMarker] {
        sparklineOnsetTracker.markers
    }

    private var mixedPortSuffix: String {
        if let parsed = AppleTunnelHttpProxyConfig.parseHostPort(hostConfig.desktop.mixedListen) {
            return ":\(parsed.port)"
        }
        return ":7890"
    }

    var transitInboundLabel: String {
        hostConfig.desktop.enableMixed ? "混合代理 \(mixedPortSuffix)" : "系统隧道"
    }

    var transitInboundDetail: String {
        guard isRunning else { return "待机" }
        return hostConfig.desktop.tunHttpProxyEnabled
            ? "隧道 + 系统代理"
            : "\(statusSnapshot.listeners) 监听"
    }

    var miniTransitInboundLabel: String {
        hostConfig.desktop.enableMixed ? mixedPortSuffix : "TUN"
    }

    var activeExitDisplayName: String {
        if let active = primaryGroup?.active, !active.isEmpty { return active }
        return activeProfileDisplayName
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
        "\(workspace.profiles.count) 配置 · \(workspace.subscriptions.count) 订阅"
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
        if wsStreamTask != nil { return }
        if statusStreamTask != nil || connectionsStreamTask != nil || logStreamTask != nil {
            if !isLogPaused && logStreamTask == nil { startSseLogStream() }
            return
        }
        let client = httpControl
        let sinceSeq = logs.last?.seq ?? 0
        let generation = liveStreamGeneration
        wsStreamTask = Task { [weak self] in
            var shouldFallbackToSse = false
            do {
                for try await event in client.streamControlWebSocket(
                    channels: ControlWsChannel.allCases,
                    since: sinceSeq,
                    intervalMs: 1000
                ) {
                    guard let self, !Task.isCancelled, self.liveStreamGeneration == generation else { break }
                    self.handleControlWsEvent(event)
                }
            } catch {
                if !Task.isCancelled { shouldFallbackToSse = true }
            }
            guard let self, self.liveStreamGeneration == generation else { return }
            self.wsStreamTask = nil
            self.isWebSocketActive = false
            if self.logStreamTask == nil { self.isLogStreaming = false }
            if shouldFallbackToSse && !Task.isCancelled && self.isRunning {
                self.startSseFallbackStreams()
            }
        }
    }

    func handleControlWsEvent(_ event: ControlWsEvent) {
        switch event {
        case .connected:
            isWebSocketActive = true
            isLogStreaming = !isLogPaused
        case .authOk, .subscribed, .pong:
            break
        case .log(let entry):
            if !isLogPaused { appendLogEntry(entry) }
        case .connections(let snap):
            connections = snap.connections
        case .metrics(let snap):
            applyStatusSnapshot(snap)
        case .serverError(_, let message):
            if !message.isEmpty { actionErrorMessage = "控制流异常：\(message)" }
        }
    }

    func startSseFallbackStreams() {
        let client = httpControl
        let generation = liveStreamGeneration
        if statusStreamTask == nil {
            statusStreamTask = Task { [weak self] in
                do {
                    for try await snap in client.streamStatus(intervalMs: 1000) {
                        guard let self, !Task.isCancelled, self.liveStreamGeneration == generation else { break }
                        self.applyStatusSnapshot(snap)
                    }
                } catch {}
                guard let self, self.liveStreamGeneration == generation else { return }
                self.statusStreamTask = nil
            }
        }
        if connectionsStreamTask == nil {
            connectionsStreamTask = Task { [weak self] in
                do {
                    for try await conns in client.streamConnections(intervalMs: 1000) {
                        guard let self, !Task.isCancelled, self.liveStreamGeneration == generation else { break }
                        self.connections = conns
                    }
                } catch {}
                guard let self, self.liveStreamGeneration == generation else { return }
                self.connectionsStreamTask = nil
            }
        }
        if !isLogPaused && logStreamTask == nil {
            startSseLogStream()
        }
    }

    private func startSseLogStream() {
        let client = httpControl
        let sinceSeq = logs.last?.seq ?? 0
        let generation = liveStreamGeneration
        isLogStreaming = true
        logStreamTask = Task { [weak self] in
            do {
                for try await entry in client.streamLogs(level: "trace", since: sinceSeq) {
                    guard let self, !Task.isCancelled, self.liveStreamGeneration == generation else { break }
                    if !self.isLogPaused { self.appendLogEntry(entry) }
                }
            } catch {}
            guard let self, self.liveStreamGeneration == generation else { return }
            self.isLogStreaming = false
            self.logStreamTask = nil
        }
    }

    func stopLiveStreams() {
        liveStreamGeneration &+= 1
        wsStreamTask?.cancel()
        wsStreamTask = nil
        statusStreamTask?.cancel()
        statusStreamTask = nil
        connectionsStreamTask?.cancel()
        connectionsStreamTask = nil
        logStreamTask?.cancel()
        logStreamTask = nil
        isWebSocketActive = false
        isLogStreaming = false
    }

    func toggleLogPause() {
        isLogPaused.toggle()
        if isWebSocketActive {
            isLogStreaming = !isLogPaused
            return
        }
        if isLogPaused {
            logStreamTask?.cancel()
            logStreamTask = nil
            isLogStreaming = false
        } else if isRunning {
            startLiveStreams()
        }
    }

    func applyStatusSnapshot(_ snap: StatusSnapshot) {
        statusSnapshot = snap
        isRunning = snap.state.lowercased() == "running"
        let stateTitle = NexusDisplayCopy.coreStateTitle(snap.state)
        statusSummary = "\(stateTitle) · \(snap.workers) 线程 · \(snap.listeners) 监听"
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
            sparklineOnsetTracker.shiftLeft()
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
