#if os(macOS) || os(iOS)
import SwiftUI
import NexusCoreBridge
import NexusSharedUI

#if os(macOS)
@MainActor
@main
struct NexusMenuBarApp: App {
    @State private var model = NexusAppModel()

    var body: some Scene {
        MenuBarExtra(
            "Nexus",
            systemImage: model.isRunning ? "network.badge.shield.half.filled" : "network.slash"
        ) {
            MenuBarPopoverView(model: model)
        }
        .menuBarExtraStyle(.window)

        Window("Nexus 控制台", id: "dashboard") {
            DashboardView(model: model)
                .frame(minWidth: 920, minHeight: 620)
        }
        .commands {
            CommandMenu("导航") {
                Button("概览") { model.selectedSection = .overview }
                    .keyboardShortcut("1", modifiers: .command)
                Button("代理与策略组") { model.selectedSection = .proxies }
                    .keyboardShortcut("2", modifiers: .command)
                Button("工作区") { model.selectedSection = .workspace }
                    .keyboardShortcut("3", modifiers: .command)
                Button("规则与 DNS") { model.selectedSection = .rulesDns }
                    .keyboardShortcut("4", modifiers: .command)
                Button("活跃连接") { model.selectedSection = .connections }
                    .keyboardShortcut("5", modifiers: .command)
                Button("实时日志") { model.selectedSection = .logs }
                    .keyboardShortcut("6", modifiers: .command)
                Divider()
                Button("热重载配置") { Task { await model.reloadConfig() } }
                    .keyboardShortcut("r", modifiers: .command)
                Button("快速查找规则 / 节点") { model.selectedSection = .rulesDns }
                    .keyboardShortcut("k", modifiers: .command)
            }
        }

        Settings {
            SettingsView(model: model)
                .frame(width: 520, height: 480)
                .scenePadding()
        }
    }
}
#elseif os(iOS)
@MainActor
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

    private var sidebarSelection: Binding<AppSection?> {
        Binding(
            get: { model.selectedSection },
            set: { if let section = $0 { model.selectedSection = section } }
        )
    }

    var body: some View {
        Group {
            if sizeClass == .regular {
                NavigationSplitView {
                    List(AppSection.allCases, selection: sidebarSelection) { tab in
                        Label(tab.rawValue, systemImage: tab.systemImage).tag(tab)
                    }
                    .navigationTitle("Nexus")
                } detail: {
                    mobileTabContent(model.selectedSection)
                }
            } else {
                TabView(selection: $model.selectedSection) {
                    ForEach([AppSection.overview, .proxies, .rulesDns, .connections, .settings]) { tab in
                        NavigationStack {
                            mobileTabContent(tab)
                                .navigationTitle(tab.rawValue)
                        }
                        .tabItem { Label(tab.rawValue, systemImage: tab.systemImage) }
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
    private func mobileTabContent(_ tab: AppSection) -> some View {
        switch tab {
        case .overview:
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    OverviewMetricsSection(
                        metrics: model.metrics,
                        diagnostics: model.diagnostics,
                        network: model.network,
                        residentMemoryMiB: model.residentMemoryMiB,
                        workers: max(model.statusSnapshot.workers, model.hostConfig.workers),
                        rxHistory: model.rxHistory,
                        txHistory: model.txHistory,
                        rxRateBytesPerSec: model.rxRateBytesPerSec,
                        txRateBytesPerSec: model.txRateBytesPerSec
                    )
                    if sizeClass != .regular {
                        HStack(spacing: 10) {
                            NavigationLink {
                                mobileTabContent(.workspace)
                                    .navigationTitle(AppSection.workspace.rawValue)
                            } label: {
                                Label("工作区", systemImage: AppSection.workspace.systemImage)
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(.bordered)
                            NavigationLink {
                                mobileTabContent(.logs)
                                    .navigationTitle(AppSection.logs.rawValue)
                            } label: {
                                Label("实时日志", systemImage: AppSection.logs.systemImage)
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(.bordered)
                        }
                    }
                }
                .padding()
            }
        case .proxies:
            ProxiesGroupsView(
                groups: model.groups,
                probingOutbounds: model.probingOutbounds,
                lastProbeBanner: model.lastProbeBanner,
                onSelectMember: { g, m in Task { await model.selectMember(group: g, member: m) } },
                onProbeGroup: { g in Task { await model.probeGroup(group: g) } },
                onProbeOutbound: { tag in Task { await model.probeOutbound(tag: tag) } },
                onResetGroupAuto: { g in Task { await model.resetGroupAuto(group: g) } },
                onRefresh: { Task { await model.refreshGroupsAndMetrics() } }
            )
        case .workspace:
            WorkspaceView(
                workspace: model.workspace,
                activeProfileID: model.activeProfileID,
                syncConfig: model.syncConfig,
                syncStatusSummary: model.syncStatusSummary,
                syncConflictSummary: model.syncConflictSummary,
                onSelectProfile: { id in Task { await model.selectWorkspaceProfile(id) } },
                onDeleteProfile: { id in Task { await model.deleteWorkspaceProfile(id) } },
                onImportShareLink: { uri in Task { await model.importShareLink(uri) } },
                onRefreshWorkspace: { Task { await model.loadWorkspaceState() } },
                onCompactDatabase: { Task { await model.compactDatabase() } }
            )
        case .rulesDns:
            RulesDnsView(
                rules: model.rules,
                dnsResponse: model.dnsResponse,
                dnsError: model.dnsError,
                isQueryingDns: model.isQueryingDns,
                cacheActionMessage: model.cacheActionMessage,
                onRefreshRules: { Task { await model.refreshRules() } },
                onQueryDns: { n, t, s in Task { await model.runDnsQuery(name: n, type: t, server: s) } },
                onFlushFakeIp: { Task { await model.flushFakeIpCache() } },
                onClearDnsCache: { Task { await model.clearCache(scope: "dns") } },
                onClearAllCache: { Task { await model.clearCache(scope: "all") } }
            )
        case .connections:
            ConnectionsView(
                connections: model.connections,
                selectedDetail: model.selectedConnectionDetail,
                onRefresh: { Task { await model.refreshGroupsAndMetrics() } },
                onInspect: { id in Task { await model.inspectConnection(id: id) } },
                onClose: { id in Task { await model.closeConnection(id: id) } },
                onCloseAll: { Task { await model.closeAllConnections() } }
            )
        case .logs:
            LogsPane(
                logs: model.logs,
                logLevel: $model.logLevel,
                logDomainFilter: $model.logDomainFilter,
                logSearch: $model.logSearch,
                isStreaming: model.isLogStreaming,
                isPaused: model.isLogPaused,
                onApplyLevel: { lvl in Task { await model.applyLogLevel(lvl) } },
                onRefresh: { Task { await model.refreshLogs() } },
                onClear: { model.clearLogs() },
                onTogglePause: { model.toggleLogPause() }
            )
        case .settings:
            SettingsView(model: model)
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
