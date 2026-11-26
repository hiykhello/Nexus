#if os(macOS)
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
                SidebarStatusFooter(
                    isRunning: model.isRunning,
                    mode: model.outboundMode,
                    memoryMiB: model.residentMemoryMiB
                )
            }
        } detail: {
            detailContent(for: model.selectedSection)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
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
                .accessibilityHint("刷新核心运行状态、策略组与遥测指标")

                Button {
                    Task { await model.reloadConfig() }
                } label: {
                    Label("热重载", systemImage: "arrow.triangle.2.circlepath")
                }
                .disabled(!model.isRunning)
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
                onQueryDns: { name, type, srv in Task { await model.runDnsQuery(name: name, type: type, server: srv) } },
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

private struct SidebarStatusFooter: View {
    let isRunning: Bool
    let mode: String
    let memoryMiB: Double

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                StatusBadgeView(isOnline: isRunning, label: isRunning ? "核心在线" : "离线")
                Spacer()
                Text(mode.uppercased())
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
            }
            Text(String(format: "内存 %.1f MiB", memoryMiB))
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.secondary)
        }
        .padding(10)
        .background(.bar)
    }
}

struct OverviewPane: View {
    @Bindable var model: NexusAppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                heroStatusCard
                if let group = model.primaryGroup {
                    quickGroupSwitcherCard(group)
                }
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
            }
            .padding()
        }
    }

    private var heroStatusCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text(model.activeProfileDisplayName)
                            .font(.title2.weight(.bold))
                        Text(model.activeProfileKindBadge)
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 7)
                            .padding(.vertical, 3)
                            .background(NexusPalette.subtleSurface, in: Capsule())
                        StatusBadgeView(isOnline: model.isRunning, label: model.isRunning ? "在线" : "离线")
                    }
                    Text("\(model.statusSummary) · \(model.workspaceSummaryText)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Picker("模式", selection: Binding(
                    get: { model.outboundMode },
                    set: { mode in Task { await model.setOutboundMode(mode) } }
                )) {
                    Text("Rule").tag("rule")
                    Text("Global").tag("global")
                    Text("Direct").tag("direct")
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 210)
            }

            HStack(spacing: 8) {
                Button {
                    Task {
                        await model.refreshStatus()
                        await model.refreshGroupsAndMetrics()
                    }
                } label: {
                    Label("刷新状态", systemImage: "arrow.clockwise")
                }
                .buttonStyle(.borderedProminent)

                Button {
                    Task { await model.reloadConfig() }
                } label: {
                    Label("热重载", systemImage: "bolt.circle")
                }
                .buttonStyle(.bordered)
                .disabled(!model.isRunning)

                Button {
                    Task { await model.flushFakeIpCache() }
                } label: {
                    Label("刷新 FakeIP", systemImage: "sparkles")
                }
                .buttonStyle(.bordered)
                .disabled(!model.isRunning)

                Button {
                    Task { await model.clearCache(scope: "all") }
                } label: {
                    Label("清缓存", systemImage: "trash")
                }
                .buttonStyle(.bordered)
                .disabled(!model.isRunning)

                Spacer()
                if let msg = model.cacheActionMessage, !msg.isEmpty {
                    Text(msg)
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
            }
        }
        .bentoCard(padding: 16)
    }

    private func quickGroupSwitcherCard(_ group: OutboundGroupSnapshot) -> some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("快速切换 · \(group.tag)")
                    .font(.subheadline.weight(.semibold))
                Text("模式 \(group.mode) · 当前 \(group.active)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            RttPillView(latencyMs: model.activeGroupRttMs, state: model.isRunning ? "up" : "idle")
            Picker("出站成员", selection: Binding(
                get: { group.active },
                set: { member in Task { await model.selectMember(group: group.tag, member: member) } }
            )) {
                ForEach(group.members) { member in
                    Text(member.name).tag(member.name)
                }
            }
            .labelsHidden()
            .frame(maxWidth: 220)
            .disabled(!group.supportsManualSelection)
            Button("测速") {
                Task { await model.probeGroup(group: group.tag) }
            }
            .buttonStyle(.bordered)
        }
        .bentoCard(padding: 12)
    }
}
#endif
