#if os(macOS)
import Foundation
import SwiftUI
import NexusCoreBridge
import NexusSharedUI

/// Primary macOS Dashboard built with `NavigationSplitView` sidebar and narrow-input detail panes.
struct DashboardView: View {
    @Bindable var model: NexusAppModel

    private var sidebarSelection: Binding<AppSection?> {
        Binding(
            get: { model.selectedSection },
            set: { if let section = $0 { model.selectedSection = section } }
        )
    }

    var body: some View {
        NavigationSplitView {
            List(AppSection.allCases, selection: sidebarSelection) { section in
                Label(section.rawValue, systemImage: section.systemImage)
                    .tag(section)
            }
            .navigationSplitViewColumnWidth(min: 175, ideal: 195, max: 230)
            .safeAreaInset(edge: .bottom) {
                SidebarStatusFooter(model: model)
            }
        } detail: {
            VStack(spacing: 0) {
                if model.selectedSection != .overview,
                   model.selectedSection != .settings,
                   let err = model.actionErrorMessage,
                   !err.isEmpty {
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
                detailContent(for: model.selectedSection)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
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
                .help("刷新内核运行状态、策略组与遥测指标")

                Button {
                    Task { await model.reloadConfig() }
                } label: {
                    Label("热重载", systemImage: "arrow.triangle.2.circlepath")
                }
                .disabled(!model.isRunning)
                .help("热重载当前生效配置")
            }
        }
        .task {
            await model.refreshStatus()
            await model.refreshGroupsAndMetrics()
        }
    }

    @ViewBuilder
    private func detailContent(for section: AppSection) -> some View {
        switch section {
        case .overview:
            OverviewPane(model: model)
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
                onQueryDns: { name, type, srv in Task { await model.runDnsQuery(name: name, type: type, server: srv) } },
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
        case .settings:
            SettingsView(model: model)
        }
    }
}

/// Isolated sidebar footer leaf so 1Hz memory updates do not invalidate sidebar navigation rows.
private struct SidebarStatusFooter: View {
    var model: NexusAppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                StatusBadgeView(isOnline: model.isRunning, label: model.isRunning ? "内核在线" : "离线")
                Spacer()
                Text(NexusDisplayCopy.outboundModeTitle(model.outboundMode))
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
            }
            Text(String(format: "应用内存 %.1f MiB", model.residentMemoryMiB))
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.secondary)
        }
        .padding(10)
        .background(.bar)
    }
}

struct OverviewPane: View {
    var model: NexusAppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
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
                OverviewLiveMetricsLeaf(model: model)
            }
            .padding()
        }
    }
}

/// Isolated 1Hz observation leaf so frequent metrics/throughput ticks only re-diff this subtree.
private struct OverviewLiveMetricsLeaf: View {
    var model: NexusAppModel

    var body: some View {
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
    }
}
#endif
