#if os(macOS) || os(iOS)
import Foundation
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
                Button("快速查找当前页") { model.triggerSearchFocus() }
                    .keyboardShortcut("k", modifiers: .command)
            }
        }

        Settings {
            SettingsView(model: model)
                .frame(minWidth: 500, idealWidth: 560, minHeight: 460)
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
                    NavigationStack {
                        mobileSectionContainer(model.selectedSection)
                            .navigationTitle(model.selectedSection.rawValue)
                    }
                }
            } else {
                TabView(selection: $model.selectedSection) {
                    ForEach(NexusAppModel.compactMobileTabs) { tab in
                        NavigationStack {
                            mobileSectionContainer(tab)
                                .navigationTitle(tab.rawValue)
                        }
                        .tabItem { Label(tab.rawValue, systemImage: tab.systemImage) }
                        .tag(tab)
                    }
                }
            }
        }
        .onAppear {
            if sizeClass != .regular { model.normalizeCompactSelection() }
        }
        .onChange(of: sizeClass) { _, nextSize in
            if nextSize != .regular { model.normalizeCompactSelection() }
        }
        .task {
            await model.refreshStatus()
            await model.refreshGroupsAndMetrics()
        }
    }

    private func withShellErrorBanner<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        VStack(spacing: 0) {
            if let err = model.actionErrorMessage, !err.isEmpty {
                ActionErrorBanner(
                    message: err,
                    flush: false,
                    onRetry: {
                        Task {
                            await model.refreshStatus()
                            await model.refreshGroupsAndMetrics()
                        }
                    },
                    onDismiss: { model.clearActionError() }
                )
                .padding([.horizontal, .top])
            }
            content()
        }
    }

    @ViewBuilder
    private func mobileSectionContainer(_ tab: AppSection) -> some View {
        if tab != .overview && tab != .settings {
            withShellErrorBanner {
                mobileTabContent(tab)
            }
        } else {
            mobileTabContent(tab)
        }
    }

    private var workspaceTabView: some View {
        WorkspaceView(
            workspace: model.workspace,
            activeProfileID: model.activeProfileID,
            syncConfig: model.syncConfig,
            syncStatusSummary: model.syncStatusSummary,
            syncConflictSummary: model.syncConflictSummary,
            focusSearchTrigger: model.searchFocusTrigger,
            shouldAutoFocusSearch: model.pendingSearchFocusSection == .workspace,
            onConsumeSearchFocus: { model.consumeSearchFocus(for: .workspace) },
            onSelectProfile: { id in Task { await model.selectWorkspaceProfile(id) } },
            onDeleteProfile: { id in Task { await model.deleteWorkspaceProfile(id) } },
            onImportShareLink: { uri in Task { await model.importShareLink(uri) } },
            onRefreshWorkspace: { Task { await model.loadWorkspaceState() } },
            onCompactDatabase: { Task { await model.compactDatabase() } }
        )
    }

    private var logsTabView: some View {
        LogsPane(
            logs: model.logs,
            logLevel: $model.logLevel,
            logDomainFilter: $model.logDomainFilter,
            logSearch: $model.logSearch,
            isStreaming: model.isLogStreaming,
            isPaused: model.isLogPaused,
            focusSearchTrigger: model.searchFocusTrigger,
            shouldAutoFocusSearch: model.pendingSearchFocusSection == .logs,
            onConsumeSearchFocus: { model.consumeSearchFocus(for: .logs) },
            onApplyLevel: { lvl in Task { await model.applyLogLevel(lvl) } },
            onRefresh: { Task { await model.refreshLogs() } },
            onClear: { model.clearLogs() },
            onTogglePause: { model.toggleLogPause() }
        )
    }

    @ViewBuilder
    private func mobileTabContent(_ tab: AppSection) -> some View {
        switch tab {
        case .overview:
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    OverviewHeaderControls(
                        activeProfileName: model.activeProfileDisplayName,
                        activeProfileKind: model.activeProfileKindBadge,
                        isRunning: model.isRunning,
                        statusSummary: model.statusSummary,
                        workspaceSummary: model.workspaceSummaryText,
                        outboundMode: model.outboundMode,
                        cacheActionMessage: model.cacheActionMessage,
                        actionErrorMessage: model.actionErrorMessage,
                        showPrimaryRefreshActions: false,
                        onSelectMode: { mode in Task { await model.setOutboundMode(mode) } },
                        onFlushFakeIp: { Task { await model.flushFakeIpCache() } },
                        onClearAllCache: { Task { await model.clearCache(scope: "all") } },
                        onDismissError: { model.clearActionError() },
                        onRetryError: {
                            Task {
                                await model.refreshStatus()
                                await model.refreshGroupsAndMetrics()
                            }
                        }
                    )
                    if let group = model.primaryGroup {
                        QuickGroupSwitcherCard(
                            group: group,
                            isRunning: model.isRunning,
                            activeRttMs: model.activeGroupRttMs,
                            onSelectMember: { member in Task { await model.selectMember(group: group.tag, member: member) } },
                            onProbeGroup: { Task { await model.probeGroup(group: group.tag) } }
                        )
                    }
                    OverviewMetricsSection(
                        metrics: model.metrics,
                        diagnostics: model.diagnostics,
                        network: model.network,
                        isRunning: model.isRunning,
                        residentMemoryMiB: model.residentMemoryMiB,
                        coreMemoryMiB: model.coreMemoryMiB,
                        workers: max(model.statusSnapshot.workers, model.hostConfig.workers),
                        rxHistory: model.rxHistory,
                        txHistory: model.txHistory,
                        rxRateBytesPerSec: model.rxRateBytesPerSec,
                        txRateBytesPerSec: model.txRateBytesPerSec
                    )
                    if sizeClass != .regular {
                        HStack(spacing: 10) {
                            NavigationLink {
                                withShellErrorBanner { workspaceTabView }
                                    .navigationTitle(AppSection.workspace.rawValue)
                            } label: {
                                Label("工作区", systemImage: AppSection.workspace.systemImage)
                                    .frame(maxWidth: .infinity, minHeight: 44)
                            }
                            .buttonStyle(.bordered)
                            NavigationLink {
                                withShellErrorBanner { logsTabView }
                                    .navigationTitle(AppSection.logs.rawValue)
                            } label: {
                                Label("实时日志", systemImage: AppSection.logs.systemImage)
                                    .frame(maxWidth: .infinity, minHeight: 44)
                            }
                            .buttonStyle(.bordered)
                        }
                    }
                }
                .padding()
            }
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    Button {
                        Task {
                            await model.refreshStatus()
                            await model.refreshGroupsAndMetrics()
                        }
                    } label: {
                        Label("刷新", systemImage: "arrow.clockwise")
                    }
                    Button {
                        Task { await model.reloadConfig() }
                    } label: {
                        Label("热重载", systemImage: "arrow.triangle.2.circlepath")
                    }
                    .disabled(!model.isRunning)
                }
            }
        case .proxies:
            ProxiesGroupsView(
                groups: model.groups,
                probingOutbounds: model.probingOutbounds,
                lastProbeBanner: model.lastProbeBanner,
                focusSearchTrigger: model.searchFocusTrigger,
                shouldAutoFocusSearch: model.pendingSearchFocusSection == .proxies,
                onConsumeSearchFocus: { model.consumeSearchFocus(for: .proxies) },
                onSelectMember: { g, m in Task { await model.selectMember(group: g, member: m) } },
                onProbeGroup: { g in Task { await model.probeGroup(group: g) } },
                onProbeOutbound: { tag in Task { await model.probeOutbound(tag: tag) } },
                onResetGroupAuto: { g in Task { await model.resetGroupAuto(group: g) } },
                onRefresh: { Task { await model.refreshGroupsAndMetrics() } }
            )
        case .workspace:
            workspaceTabView
        case .rulesDns:
            RulesDnsView(
                rules: model.rules,
                dnsResponse: model.dnsResponse,
                dnsError: model.dnsError,
                isQueryingDns: model.isQueryingDns,
                cacheActionMessage: model.cacheActionMessage,
                focusSearchTrigger: model.searchFocusTrigger,
                shouldAutoFocusSearch: model.pendingSearchFocusSection == .rulesDns,
                onConsumeSearchFocus: { model.consumeSearchFocus(for: .rulesDns) },
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
                focusSearchTrigger: model.searchFocusTrigger,
                shouldAutoFocusSearch: model.pendingSearchFocusSection == .connections,
                onConsumeSearchFocus: { model.consumeSearchFocus(for: .connections) },
                onRefresh: { Task { await model.refreshGroupsAndMetrics() } },
                onInspect: { id in Task { await model.inspectConnection(id: id) } },
                onDismissDetail: { model.selectedConnectionDetail = nil },
                onClose: { id in Task { await model.closeConnection(id: id) } },
                onCloseAll: { Task { await model.closeAllConnections() } }
            )
        case .logs:
            logsTabView
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
