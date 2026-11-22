#if os(macOS) || os(iOS)
import Observation
import SwiftUI
import NexusCoreBridge
#if os(iOS)
import NexusSharedUI
#endif

@MainActor
@Observable
final class NexusAppModel {
    var isRunning = false
    var backend: AppleTunnelBackend = .launchDaemonUtun
    var daemonState: DaemonRegistrationState = .notRegistered
    var statusSummary = "未启动"
    var residentMemoryMiB: Double = TunnelMemoryMonitor.currentResidentMemoryMiB()
    var network = AppleNetworkSnapshot(
        interfaceName: nil,
        interfaceIndex: -1,
        isExpensive: false,
        isConstrained: false,
        hasConnectivity: false
    )
    var kdlText = """
        schema-version 1
        role "client"
        log {
            level "info"
            privacy "redacted"
        }
        outbound "direct" type="direct"
        routing { default-outbound "direct" }
        """
    var logLevel = "info"
    var logDomainFilter = "all"
    var logSearch = ""
    var logs: [LogRingEntry] = []
    var groups: [OutboundGroupSnapshot] = []
    var connections: [ActiveConnectionSnapshot] = []
    var selectedConnectionDetail: ActiveConnectionSnapshot?
    var metrics = MetricsSnapshot()
    var diagnostics = DiagnosticsSnapshot()

    private let watcher = NetworkPathWatcher()
    private let session: ControlSocketSession
    private let httpControl: HttpControlClient
    private let daemonController = PrivilegedDaemonController()
    private var networkGeneration: UInt64 = 0
    private var monitorTask: Task<Void, Never>?

    init() {
        let sockPath = "/var/run/org.nexus.apple/c.sock"
        self.session = ControlSocketSession(socketPath: sockPath)
        self.httpControl = HttpControlClient(baseURL: URL(string: "http://127.0.0.1:9090")!)
        self.daemonState = daemonController.status()
        startNetworkMonitor()
    }

    private func startNetworkMonitor() {
        monitorTask?.cancel()
        let stream = watcher.updates()
        monitorTask = Task { [weak self] in
            for await snap in stream {
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

    func refreshStatus() async {
        daemonState = daemonController.status()
        do {
            let text = try await session.status()
            isRunning = true
            statusSummary = text.trimmingCharacters(in: .whitespacesAndNewlines)
        } catch {
            isRunning = false
            statusSummary = "未连接: \(error.localizedDescription)"
        }
    }

    func reloadConfig() async {
        do {
            _ = try await session.reload()
            statusSummary = "热重载成功"
        } catch {
            statusSummary = "热重载失败: \(error.localizedDescription)"
        }
    }

    func applyLogLevel(_ level: String) async {
        logLevel = level
        _ = try? await session.setLogLevel(level)
        await refreshLogs()
    }

    func refreshLogs() async {
        if let snap = try? await httpControl.logs(level: "trace", domain: logDomainFilter, search: logSearch, limit: 200) {
            logs = snap.entries
        }
    }

    func clearLogs() {
        logs = []
    }

    func inspectConnection(id: String) async {
        selectedConnectionDetail = try? await httpControl.connectionDetail(id: id)
    }

    func refreshGroupsAndMetrics() async {
        if let fetched = try? await httpControl.outbounds() {
            groups = fetched
        }
        if let conns = try? await httpControl.connections() {
            connections = conns
        }
        if let snap = try? await httpControl.metrics() {
            metrics = snap
        }
        if let diag = try? await httpControl.diagnostics() {
            diagnostics = diag
        }
        residentMemoryMiB = TunnelMemoryMonitor.currentResidentMemoryMiB()
    }

    func selectMember(group: String, member: String) async {
        do {
            try await httpControl.selectGroup(tag: group, member: member)
        } catch {
            _ = try? await session.selectOutbound(group: group, member: member)
        }
        await refreshGroupsAndMetrics()
    }

    func resetGroupAuto(group: String) async {
        do {
            try await httpControl.resetGroupAuto(tag: group)
        } catch {
            _ = try? await session.resetGroupAuto(group: group)
        }
        await refreshGroupsAndMetrics()
    }

    func clearCache() async {
        do {
            try await httpControl.clearCache()
            statusSummary = "缓存已清空"
        } catch {
            statusSummary = "清缓存失败: \(error.localizedDescription)"
        }
    }

    func closeConnection(id: String) async {
        try? await httpControl.closeConnection(id: id)
        await refreshGroupsAndMetrics()
    }

    func closeAllConnections() async {
        try? await httpControl.closeAllConnections()
        await refreshGroupsAndMetrics()
    }

    func probeGroup(group: String) async {
        try? await httpControl.probeGroup(tag: group)
        await refreshGroupsAndMetrics()
    }

    func registerDaemon() {
        do {
            try daemonController.register()
            daemonState = daemonController.status()
        } catch {
            statusSummary = "Daemon 注册失败: \(error.localizedDescription)"
        }
    }

    func unregisterDaemon() async {
        do {
            try await daemonController.unregister()
            daemonState = daemonController.status()
        } catch {
            statusSummary = "Daemon 注销失败: \(error.localizedDescription)"
        }
    }
}

#if os(macOS)
@main
struct NexusMenuBarApp: App {
    @State private var model = NexusAppModel()
    @Environment(\.openWindow) private var openWindow

    var body: some Scene {
        MenuBarExtra(
            "Nexus",
            systemImage: model.isRunning ? "network.badge.shield.half.filled" : "network.slash"
        ) {
            Text(model.isRunning ? "Nexus 运行中" : "Nexus 未运行")
            if let iface = model.network.interfaceName {
                Text("物理网口: \(iface)")
            }
            Divider()
            Button("刷新状态") {
                Task { await model.refreshStatus() }
            }
            Button("热重载配置") {
                Task { await model.reloadConfig() }
            }
            .disabled(!model.isRunning)
            Button("打开控制台...") {
                openWindow(id: "dashboard")
                NSApp.activate()
            }
            SettingsLink {
                Text("设置...")
            }
            Divider()
            Button("退出 Nexus") { NSApp.terminate(nil) }
        }

        Window("Nexus 控制台", id: "dashboard") {
            DashboardView(model: model)
                .frame(minWidth: 760, minHeight: 500)
        }

        Settings {
            NexusSettingsView(model: model)
                .frame(width: 420)
                .scenePadding()
        }
    }
}

private struct NexusSettingsView: View {
    @Bindable var model: NexusAppModel

    var body: some View {
        Form {
            Section("特权 Daemon (SMAppService)") {
                LabeledContent("注册状态", value: model.daemonState.rawValue)
                HStack {
                    Button("注册 Daemon") { model.registerDaemon() }
                    Button("注销 Daemon") {
                        Task { await model.unregisterDaemon() }
                    }
                }
            }
            Section("运行日志") {
                Picker("动态日志级别", selection: Binding(
                    get: { model.logLevel },
                    set: { level in Task { await model.applyLogLevel(level) } }
                )) {
                    ForEach(["error", "warn", "info", "debug", "trace"], id: \.self) { level in
                        Text(level).tag(level)
                    }
                }
            }
        }
        .formStyle(.grouped)
    }
}
#elseif os(iOS)
@main
struct NexusMobileApp: App {
    @State private var model = NexusAppModel()

    var body: some Scene {
        WindowGroup {
            AdaptiveMobileRootView(model: model)
        }
    }
}

private struct AdaptiveMobileRootView: View {
    @Bindable var model: NexusAppModel
    @Environment(\.horizontalSizeClass) private var sizeClass
    @State private var selection: MobileTab = .overview

    enum MobileTab: String, CaseIterable, Identifiable {
        case overview = "概览"
        case connections = "连接"
        case config = "配置"
        case logs = "日志"
        var id: String { rawValue }
        var icon: String {
            switch self {
            case .overview: "gauge.with.dots.needle.50percent"
            case .connections: "network"
            case .config: "doc.text"
            case .logs: "text.alignleft"
            }
        }
    }

    var body: some View {
        Group {
            if sizeClass == .regular {
                NavigationSplitView {
                    List(MobileTab.allCases, selection: $selection) { tab in
                        Label(tab.rawValue, systemImage: tab.icon).tag(tab)
                    }
                    .navigationTitle("Nexus")
                } detail: {
                    tabContent(selection)
                }
            } else {
                TabView(selection: $selection) {
                    ForEach(MobileTab.allCases) { tab in
                        NavigationStack {
                            tabContent(tab)
                                .navigationTitle(tab.rawValue)
                        }
                        .tabItem { Label(tab.rawValue, systemImage: tab.icon) }
                        .tag(tab)
                    }
                }
            }
        }
        .task {
            await model.refreshStatus()
            await model.refreshGroupsAndMetrics()
        }
    }

    @ViewBuilder
    private func tabContent(_ tab: MobileTab) -> some View {
        switch tab {
        case .overview:
            Form {
                Section("状态") {
                    LabeledContent("连接状态", value: model.isRunning ? "在线" : "离线")
                    LabeledContent("详情", value: model.statusSummary)
                    HStack {
                        Button("刷新") { Task { await model.refreshStatus(); await model.refreshGroupsAndMetrics() } }
                        Button("热重载") { Task { await model.reloadConfig() } }.disabled(!model.isRunning)
                    }
                }
                OverviewMetricsSection(
                    metrics: model.metrics,
                    diagnostics: model.diagnostics,
                    network: model.network,
                    residentMemoryMiB: model.residentMemoryMiB
                )
            }
        case .connections:
            ConnectionsView(
                connections: model.connections,
                selectedDetail: model.selectedConnectionDetail,
                onRefresh: { Task { await model.refreshGroupsAndMetrics() } },
                onInspect: { id in Task { await model.inspectConnection(id: id) } },
                onClose: { id in Task { await model.closeConnection(id: id) } },
                onCloseAll: { Task { await model.closeAllConnections() } }
            )
        case .config:
            VStack {
                TextEditor(text: $model.kdlText).font(.system(.body, design: .monospaced))
                Button("热重载") { Task { await model.reloadConfig() } }.disabled(!model.isRunning)
            }
            .padding()
        case .logs:
            LogsPane(
                logs: model.logs,
                logLevel: $model.logLevel,
                logDomainFilter: $model.logDomainFilter,
                logSearch: $model.logSearch,
                onApplyLevel: { lvl in Task { await model.applyLogLevel(lvl) } },
                onRefresh: { Task { await model.refreshLogs() } },
                onClear: { model.clearLogs() }
            )
        }
    }
}
#endif
#else
@main
struct NexusPlaceholderMain {
    static func main() {}
}
#endif
