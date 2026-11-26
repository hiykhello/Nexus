#if canImport(SwiftUI)
import SwiftUI
import NexusCoreBridge

/// Cross-platform Workspace & Subscriptions management screen wired to SQLite `WorkspaceStore`.
public struct WorkspaceView: View {
    public let workspace: WorkspaceDocument
    public let activeProfileID: String
    public let syncConfig: WebDavSyncConfig
    public let syncStatusSummary: String
    public let syncConflictSummary: String?
    public let onSelectProfile: (String) -> Void
    public let onDeleteProfile: (String) -> Void
    public let onImportShareLink: (String) -> Void
    public let onRefreshWorkspace: () -> Void
    public let onCompactDatabase: () -> Void

    @State private var section: WorkspaceSection = .nodes
    @State private var searchText: String = ""
    @State private var shareLinkInput: String = ""
    @State private var showImportSheet: Bool = false

    private enum WorkspaceSection: String, CaseIterable, Identifiable {
        case nodes = "节点配置"
        case subscriptions = "订阅源"
        case routingDns = "路由与 DNS"
        var id: String { rawValue }
    }

    public init(
        workspace: WorkspaceDocument,
        activeProfileID: String,
        syncConfig: WebDavSyncConfig,
        syncStatusSummary: String,
        syncConflictSummary: String?,
        onSelectProfile: @escaping (String) -> Void,
        onDeleteProfile: @escaping (String) -> Void,
        onImportShareLink: @escaping (String) -> Void,
        onRefreshWorkspace: @escaping () -> Void,
        onCompactDatabase: @escaping () -> Void
    ) {
        self.workspace = workspace
        self.activeProfileID = activeProfileID
        self.syncConfig = syncConfig
        self.syncStatusSummary = syncStatusSummary
        self.syncConflictSummary = syncConflictSummary
        self.onSelectProfile = onSelectProfile
        self.onDeleteProfile = onDeleteProfile
        self.onImportShareLink = onImportShareLink
        self.onRefreshWorkspace = onRefreshWorkspace
        self.onCompactDatabase = onCompactDatabase
    }

    private var filteredProfiles: [WorkspaceProfileItem] {
        let q = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return workspace.profiles }
        return workspace.profiles.filter {
            $0.remarks.lowercased().contains(q)
                || $0.id.lowercased().contains(q)
                || ($0.node?.server.lowercased().contains(q) ?? false)
                || ($0.node?.protocolName.lowercased().contains(q) ?? false)
        }
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            summaryBanner
            HStack(spacing: 10) {
                Picker("工作区视图", selection: $section) {
                    ForEach(WorkspaceSection.allCases) { tab in
                        Text(tab.rawValue).tag(tab)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                Spacer()
                Button {
                    showImportSheet = true
                } label: {
                    Label("导入分享链接", systemImage: "link.badge.plus")
                }
                .buttonStyle(.borderedProminent)
                Button(action: onRefreshWorkspace) {
                    Label("刷新", systemImage: "arrow.clockwise")
                }
            }
            switch section {
            case .nodes:
                nodesPane
            case .subscriptions:
                subscriptionsPane
            case .routingDns:
                routingDnsPane
            }
        }
        .padding()
        .sheet(isPresented: $showImportSheet) {
            ShareLinkImportSheet(
                shareLinkInput: $shareLinkInput,
                onCancel: { showImportSheet = false },
                onImport: { uri in
                    onImportShareLink(uri)
                    shareLinkInput = ""
                    showImportSheet = false
                }
            )
        }
    }

    private var summaryBanner: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text("SQLite 工作区 · r\(workspace.revision)")
                    .font(.headline.monospacedDigit())
                Text("\(workspace.profiles.count) 配置 · \(workspace.subscriptions.count) 订阅 · \(workspace.routingProfiles.count) 路由方案")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 3) {
                Text(syncStatusSummary)
                    .font(.caption.weight(.medium))
                if let conflict = syncConflictSummary, !conflict.isEmpty {
                    Text("冲突: \(conflict)")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                } else if syncConfig.lastSyncedRevision > 0 {
                    Text("远端 r\(syncConfig.lastSyncedRevision)")
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
            }
            Button("回收内存", action: onCompactDatabase)
                .buttonStyle(.bordered)
                .accessibilityHint("执行 SQLite shrink_memory 与 WAL 检查点")
        }
        .bentoCard(padding: 12)
    }

    private var nodesPane: some View {
        VStack(alignment: .leading, spacing: 8) {
            TextField("搜索配置名 / 协议 / 服务器...", text: $searchText)
                .textFieldStyle(.roundedBorder)
            if filteredProfiles.isEmpty {
                ContentUnavailableView(
                    "暂无配置节点",
                    systemImage: "tray",
                    description: Text("点击右上角“导入分享链接”或同步工作区以添加节点。")
                )
            } else {
                List(filteredProfiles) { item in
                    WorkspaceProfileRow(
                        item: item,
                        isActive: item.id == activeProfileID,
                        onSelect: { onSelectProfile(item.id) },
                        onDelete: { onDeleteProfile(item.id) }
                    )
                }
            }
        }
    }

    private var subscriptionsPane: some View {
        Group {
            if workspace.subscriptions.isEmpty {
                ContentUnavailableView(
                    "暂无订阅源",
                    systemImage: "antenna.radiowaves.left.and.right",
                    description: Text("订阅更新元数据将持久化在 nexus-client.db 的 subscriptions 表。")
                )
            } else {
                List(workspace.subscriptions) { sub in
                    WorkspaceSubscriptionRow(subscription: sub)
                }
            }
        }
    }

    private var routingDnsPane: some View {
        let activeRoute = workspace.activeRoutingProfile()
        return ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("当前路由方案: \(activeRoute.name)")
                        .font(.headline)
                    Text("域名策略: \(activeRoute.domainStrategy) · 默认出站: \(activeRoute.defaultOutbound) · 规则数: \(activeRoute.rules.count)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .bentoCard(padding: 12)

                VStack(alignment: .leading, spacing: 6) {
                    Text("DNS 配置 (\(workspace.dns.mode))")
                        .font(.headline)
                    let simple = workspace.dns.simple
                    Text("FakeIP: \(simple.fakeIpEnabled ? "已开启 (\(simple.fakeIpV4Pool))" : "已关闭") · 策略: \(simple.strategy)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                    Text("直连 DNS: \(simple.directDns.isEmpty ? "默认" : simple.directDns.joined(separator: ", "))")
                        .font(.caption)
                    Text("远端 DNS: \(simple.remoteDns.isEmpty ? "默认" : simple.remoteDns.joined(separator: ", "))")
                        .font(.caption)
                    Text("静态 Hosts: \(simple.hosts.count) 条 · 规则集资产: \(workspace.ruleSetAssets.count) 项")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .bentoCard(padding: 12)
            }
        }
    }
}

private struct WorkspaceProfileRow: View {
    let item: WorkspaceProfileItem
    let isActive: Bool
    let onSelect: () -> Void
    let onDelete: () -> Void

    private var endpointText: String {
        if let node = item.node, !node.server.isEmpty {
            return "\(node.protocolName.uppercased()) · \(node.server):\(node.port)"
        }
        return item.id
    }

    var body: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(item.remarks.isEmpty ? item.id : item.remarks)
                        .font(.subheadline.weight(.semibold))
                    Text(item.kind.badgeTitle)
                        .font(.caption2.weight(.medium))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(NexusPalette.subtleSurface, in: Capsule())
                }
                Text(endpointText)
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button(isActive ? "当前" : "启用", action: onSelect)
                .buttonStyle(.bordered)
                .disabled(isActive)
            Button("删除", role: .destructive, action: onDelete)
                .buttonStyle(.borderless)
        }
    }
}

private struct WorkspaceSubscriptionRow: View {
    let subscription: WorkspaceSubscriptionItem

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(subscription.remarks.isEmpty ? subscription.id : subscription.remarks)
                    .font(.subheadline.weight(.semibold))
                Spacer()
                Text(subscription.enabled ? "已启用" : "已停用")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(subscription.enabled ? .green : .secondary)
            }
            if !subscription.url.isEmpty {
                Text(subscription.url)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            if subscription.usage.hasQuota {
                let used = UInt64(max(0, subscription.usage.usedBytes))
                let total = UInt64(max(1, subscription.usage.totalBytes))
                ProgressView(value: min(1.0, Double(used) / Double(total)))
                Text("已用 \(NexusByteFormat.bytes(used)) / 总量 \(NexusByteFormat.bytes(total))")
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}

private struct ShareLinkImportSheet: View {
    @Binding var shareLinkInput: String
    let onCancel: () -> Void
    let onImport: (String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("导入节点分享链接")
                .font(.headline)
            Text("支持 vless://、trojan://、anytls://、hy2://、tuic://、snell://、ss://、ssh://、naive+https://。")
                .font(.caption)
                .foregroundStyle(.secondary)
            TextField("粘贴分享链接...", text: $shareLinkInput)
                .textFieldStyle(.roundedBorder)
            HStack {
                Spacer()
                Button("取消", action: onCancel)
                Button("解析并保存") {
                    onImport(shareLinkInput)
                }
                .buttonStyle(.borderedProminent)
                .disabled(shareLinkInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding()
        #if os(macOS)
        .frame(minWidth: 420)
        #endif
    }
}
#endif
