#if os(macOS)
import SwiftUI
import NexusCoreBridge
import NexusSharedUI

struct DashboardView: View {
    let model: NexusAppModel
    @State private var selection: SidebarTab = .overview

    enum SidebarTab: String, CaseIterable, Identifiable {
        case overview = "概览"
        case groups = "策略组"
        case connections = "活跃连接"
        case config = "KDL 配置"
        case logs = "日志与诊断"

        var id: String { rawValue }

        var systemImage: String {
            switch self {
            case .overview: "gauge.with.dots.needle.50percent"
            case .groups: "arrow.triangle.branch"
            case .connections: "network"
            case .config: "doc.text"
            case .logs: "text.alignleft"
            }
        }
    }

    var body: some View {
        NavigationSplitView {
            List(SidebarTab.allCases, selection: $selection) { tab in
                Label(tab.rawValue, systemImage: tab.systemImage).tag(tab)
            }
            .navigationSplitViewColumnWidth(min: 160, ideal: 180)
        } detail: {
            switch selection {
            case .overview:
                OverviewPane(model: model)
            case .groups:
                GroupsPane(model: model)
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
                ConfigPane(model: model)
            case .logs:
                LogsPane(
                    logs: model.logs,
                    logLevel: Bindable(model).logLevel,
                    logDomainFilter: Bindable(model).logDomainFilter,
                    logSearch: Bindable(model).logSearch,
                    onApplyLevel: { lvl in Task { await model.applyLogLevel(lvl) } },
                    onRefresh: { Task { await model.refreshLogs() } },
                    onClear: { model.clearLogs() }
                )
            }
        }
        .task {
            await model.refreshStatus()
            await model.refreshGroupsAndMetrics()
        }
    }
}

private struct OverviewPane: View {
    @Bindable var model: NexusAppModel

    var body: some View {
        Form {
            Section("运行状态") {
                LabeledContent("状态", value: model.isRunning ? "在线" : "离线")
                LabeledContent("详情", value: model.statusSummary)
                LabeledContent("Daemon 状态", value: model.daemonState.rawValue)
                Picker("接管形态", selection: $model.backend) {
                    ForEach(AppleTunnelBackend.allCases, id: \.self) { mode in
                        Text(mode.rawValue).tag(mode)
                    }
                }
                HStack {
                    Button("查询状态") {
                        Task {
                            await model.refreshStatus()
                            await model.refreshGroupsAndMetrics()
                        }
                    }
                    Button("热重载") {
                        Task { await model.reloadConfig() }
                    }
                    .disabled(!model.isRunning)
                    Button("清缓存") {
                        Task { await model.clearCache() }
                    }
                    .disabled(!model.isRunning)
                }
            }
            Section("工作区与 E2EE 同步") {
                LabeledContent("当前配置") {
                    HStack(spacing: 6) {
                        Text(model.activeProfileDisplayName)
                        Text(model.activeProfileKindBadge)
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(.quaternary, in: Capsule())
                    }
                }
                LabeledContent("工作区快照", value: model.workspaceSummaryText)
                LabeledContent("E2EE WebDAV 同步", value: model.syncStatusSummary)
                if model.syncConfig.lastSyncedRevision > 0 {
                    LabeledContent("远端已同步代次", value: "r\(model.syncConfig.lastSyncedRevision)")
                }
                if let conflict = model.syncConflictSummary {
                    Text("同步冲突: \(conflict)")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
            OverviewMetricsSection(
                metrics: model.metrics,
                diagnostics: model.diagnostics,
                network: model.network,
                residentMemoryMiB: model.residentMemoryMiB
            )
        }
        .formStyle(.grouped)
        .padding()
    }
}

private struct GroupsPane: View {
    let model: NexusAppModel

    var body: some View {
        Form {
            Section {
                HStack {
                    Text("出站策略组").font(.headline)
                    Spacer()
                    Button("刷新") { Task { await model.refreshGroupsAndMetrics() } }
                }
            }
            ForEach(model.groups) { group in
                Section("\(group.tag) (\(group.mode) · 当前: \(group.active))") {
                    HStack {
                        if group.mode == "url-test" || group.mode == "fallback" {
                            Button("立即测速") {
                                Task { await model.probeGroup(group: group.tag) }
                            }
                        }
                        if group.manualOverride {
                            Button("恢复自动选优 (--auto)") {
                                Task { await model.resetGroupAuto(group: group.tag) }
                            }
                        }
                    }
                    ForEach(group.members) { member in
                        HStack {
                            Text(member.name)
                            Spacer()
                            Text(member.latencyMs >= 0 ? "\(member.state) · \(member.latencyMs) ms" : member.state)
                                .foregroundStyle(.secondary)
                            Button(member.name == group.active ? "当前" : "切换") {
                                Task { await model.selectMember(group: group.tag, member: member.name) }
                            }
                            .disabled(member.name == group.active)
                        }
                    }
                }
            }
        }
        .formStyle(.grouped)
        .padding()
    }
}

private struct ConfigPane: View {
    @Bindable var model: NexusAppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("KDL 2.0 配置（后续可直插 CodeEditSourceEditor + tree-sitter-kdl）")
                    .font(.headline)
                Spacer()
                Button("热重载") {
                    Task { await model.reloadConfig() }
                }
                .disabled(!model.isRunning)
            }
            TextEditor(text: $model.kdlText)
                .font(.system(.body, design: .monospaced))
                .border(Color.secondary.opacity(0.25))
        }
        .padding()
    }
}
#endif
