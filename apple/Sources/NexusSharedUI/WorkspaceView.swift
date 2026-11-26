#if canImport(SwiftUI)
import Foundation
import SwiftUI
import NexusCoreBridge

/// Cross-platform Workspace & Subscriptions management screen backed by the app-managed local store.
public struct WorkspaceView: View {
    public let workspace: WorkspaceDocument
    public let activeProfileID: String
    public let syncConfig: WebDavSyncConfig
    public let syncStatusSummary: String
    public let syncConflictSummary: String?
    public let focusSearchTrigger: Int
    public let shouldAutoFocusSearch: Bool
    public let onConsumeSearchFocus: () -> Void
    public let onSelectProfile: (String) -> Void
    public let onDeleteProfile: (String) -> Void
    public let onImportShareLink: (String) -> Void
    public let onRefreshWorkspace: () -> Void
    public let onCompactDatabase: () -> Void

    @State private var section: WorkspaceSection = .nodes
    @State private var searchText: String = ""
    @State private var shareLinkInput: String = ""
    @State private var showImportSheet: Bool = false
    @State private var pendingDeleteProfile: WorkspaceProfileItem?
    @FocusState private var isSearchFocused: Bool
    @Environment(\.nexusTheme) private var theme

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
        focusSearchTrigger: Int = 0,
        shouldAutoFocusSearch: Bool = false,
        onConsumeSearchFocus: @escaping () -> Void = {},
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
        self.focusSearchTrigger = focusSearchTrigger
        self.shouldAutoFocusSearch = shouldAutoFocusSearch
        self.onConsumeSearchFocus = onConsumeSearchFocus
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

    private var pendingDeleteName: String {
        guard let item = pendingDeleteProfile else { return "" }
        return item.remarks.isEmpty ? item.id : item.remarks
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            summaryBanner
            sectionControlBar
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
        .confirmationDialog(
            "确认删除配置“\(pendingDeleteName)”？",
            isPresented: Binding(
                get: { pendingDeleteProfile != nil },
                set: { if !$0 { pendingDeleteProfile = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("删除配置", role: .destructive) {
                if let target = pendingDeleteProfile {
                    onDeleteProfile(target.id)
                }
                pendingDeleteProfile = nil
            }
            Button("取消", role: .cancel) { pendingDeleteProfile = nil }
        } message: {
            Text("删除后将从本地工作区移除该配置。")
        }
        .onAppear {
            consumePendingSearchFocusIfNeeded()
        }
        .onChange(of: focusSearchTrigger) { _, _ in
            consumePendingSearchFocusIfNeeded()
        }
    }

    private func consumePendingSearchFocusIfNeeded() {
        if shouldAutoFocusSearch {
            section = .nodes
            isSearchFocused = true
            onConsumeSearchFocus()
        }
    }

    private var sectionControlBar: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 10) {
                sectionPicker
                Spacer(minLength: 8)
                importButton
                refreshButton
            }
            VStack(alignment: .leading, spacing: 8) {
                sectionPicker
                HStack(spacing: 8) {
                    importButton
                    Spacer()
                    refreshButton
                }
            }
        }
    }

    private var sectionPicker: some View {
        Picker("工作区视图", selection: $section) {
            ForEach(WorkspaceSection.allCases) { tab in
                Text(tab.rawValue).tag(tab)
            }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
    }

    private var importButton: some View {
        Button {
            showImportSheet = true
        } label: {
            Label("导入分享链接", systemImage: "link.badge.plus")
        }
        .buttonStyle(NexusProminentButtonStyle())
    }

    private var refreshButton: some View {
        Button(action: onRefreshWorkspace) {
            Label("刷新", systemImage: "arrow.clockwise")
        }
        #if os(iOS)
        .frame(minHeight: 44)
        #endif
    }

    private var summaryBanner: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 12) {
                bannerMeta
                Spacer(minLength: 8)
                syncMeta
                compactButton
            }
            VStack(alignment: .leading, spacing: 8) {
                bannerMeta
                HStack {
                    syncMeta
                    Spacer()
                    compactButton
                }
            }
        }
        .bentoCard(padding: 12, cornerRadius: 14)
    }

    private var bannerMeta: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text("本地工作区")
                .font(.headline)
            Text("\(workspace.profiles.count) 配置 · \(workspace.subscriptions.count) 订阅 · \(workspace.routingProfiles.count) 路由方案")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
        }
    }

    private var syncMeta: some View {
        VStack(alignment: .trailing, spacing: 3) {
            Text(syncStatusSummary)
                .font(.caption.weight(.medium))
            if let conflict = syncConflictSummary, !conflict.isEmpty {
                Text("同步冲突：\(conflict)")
                    .font(.caption2)
                    .foregroundStyle(theme.warning)
            } else if syncConfig.lastSyncedRevision > 0 {
                Text("已同步（版本 \(syncConfig.lastSyncedRevision)）")
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var compactButton: some View {
        Button("回收内存", action: onCompactDatabase)
            .buttonStyle(.bordered)
            .accessibilityHint("回收本地缓存与存储占用的内存")
            #if os(iOS)
            .frame(minHeight: 44)
            #endif
    }

    private var nodesPane: some View {
        VStack(alignment: .leading, spacing: 8) {
            TextField("搜索配置名 / 协议 / 服务器…", text: $searchText)
                .textFieldStyle(.roundedBorder)
                .focused($isSearchFocused)
                .accessibilityLabel("搜索工作区配置")
            if workspace.profiles.isEmpty {
                ContentUnavailableView {
                    Label("暂无配置节点", systemImage: "tray")
                } description: {
                    Text("导入分享链接或同步工作区后，节点将自动保存在本地。")
                } actions: {
                    Button("导入分享链接") { showImportSheet = true }
                        .buttonStyle(NexusProminentButtonStyle())
                }
            } else if filteredProfiles.isEmpty {
                ContentUnavailableView {
                    Label("未找到“\(searchText)”", systemImage: "magnifyingglass")
                } description: {
                    Text("请尝试其他关键词或重置筛选条件。")
                } actions: {
                    Button("重置筛选") { searchText = "" }
                        .buttonStyle(.bordered)
                }
            } else {
                List(filteredProfiles) { item in
                    WorkspaceProfileRow(
                        item: item,
                        isActive: item.id == activeProfileID,
                        onSelect: { onSelectProfile(item.id) }
                    )
                    .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                        Button("删除", role: .destructive) {
                            pendingDeleteProfile = item
                        }
                    }
                    .contextMenu {
                        if item.id != activeProfileID {
                            Button("启用此配置") { onSelectProfile(item.id) }
                        }
                        Button("删除配置", role: .destructive) {
                            pendingDeleteProfile = item
                        }
                    }
                }
                .scrollContentBackground(.hidden)
            }
        }
    }

    private var subscriptionsPane: some View {
        Group {
            if workspace.subscriptions.isEmpty {
                ContentUnavailableView {
                    Label("暂无订阅源", systemImage: "antenna.radiowaves.left.and.right")
                } description: {
                    Text("添加订阅源后，节点与流量配额信息将自动保存在应用本地。")
                } actions: {
                    Button("刷新工作区", action: onRefreshWorkspace)
                        .buttonStyle(.bordered)
                }
            } else {
                List(workspace.subscriptions) { sub in
                    WorkspaceSubscriptionRow(subscription: sub)
                }
                .scrollContentBackground(.hidden)
            }
        }
    }

    private var routingDnsPane: some View {
        let activeRoute = workspace.activeRoutingProfile()
        return ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("当前路由方案：\(activeRoute.name)")
                        .font(.headline)
                    Text("域名策略：\(activeRoute.domainStrategy) · 默认出站：\(activeRoute.defaultOutbound) · 规则数：\(activeRoute.rules.count)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .bentoCard(padding: 12, cornerRadius: 14)

                VStack(alignment: .leading, spacing: 6) {
                    Text("DNS 配置（\(workspace.dns.displayModeTitle)）")
                        .font(.headline)
                    let simple = workspace.dns.simple
                    Text("FakeIP：\(simple.fakeIpEnabled ? "已开启 (\(simple.fakeIpV4Pool))" : "已关闭") · 策略：\(simple.strategy)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                    Text("直连 DNS：\(simple.directDns.isEmpty ? "默认" : simple.directDns.joined(separator: ", "))")
                        .font(.caption)
                    Text("远端 DNS：\(simple.remoteDns.isEmpty ? "默认" : simple.remoteDns.joined(separator: ", "))")
                        .font(.caption)
                    Text("静态 Hosts：\(simple.hosts.count) 条 · 规则集资产：\(workspace.ruleSetAssets.count) 项")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .bentoCard(padding: 12, cornerRadius: 14)
            }
        }
    }
}

private struct WorkspaceProfileRow: View {
    let item: WorkspaceProfileItem
    let isActive: Bool
    let onSelect: () -> Void
    @Environment(\.nexusTheme) private var theme

    private var endpointText: String {
        if let node = item.node, !node.server.isEmpty {
            let proto = node.protocolName.uppercased()
            let secTag: String
            if !node.tls.realityPublicKey.isEmpty {
                secTag = " · REALITY"
            } else if node.tls.enabled {
                secTag = " · TLS"
            } else {
                secTag = ""
            }
            return "\(proto)\(secTag) · \(node.server):\(node.port)"
        }
        return item.id
    }

    var body: some View {
        HStack(spacing: 10) {
            RoundedRectangle(cornerRadius: 1.5)
                .fill(isActive ? theme.signalEmeraldFill : Color.clear)
                .frame(width: 3, height: 28)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(item.remarks.isEmpty ? item.id : item.remarks)
                        .font(.subheadline.weight(.semibold))
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .nexusTooltip(item.remarks.isEmpty ? item.id : item.remarks)
                    Text("· \(item.kind.badgeTitle)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Text(endpointText)
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .nexusTooltip(endpointText)
            }
            Spacer(minLength: 6)
            Button(isActive ? "当前" : "启用", action: onSelect)
                .buttonStyle(.bordered)
                .disabled(isActive)
                #if os(iOS)
                .frame(minHeight: 44)
                #endif
        }
    }
}

private struct WorkspaceSubscriptionRow: View {
    let subscription: WorkspaceSubscriptionItem
    @Environment(\.nexusTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(subscription.remarks.isEmpty ? subscription.id : subscription.remarks)
                    .font(.subheadline.weight(.semibold))
                    .lineLimit(1)
                Spacer()
                Text(subscription.enabled ? "已启用" : "已停用")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(subscription.enabled ? theme.signalEmerald : .secondary)
            }
            if !subscription.url.isEmpty {
                Text(subscription.url)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .nexusTooltip(subscription.url)
            }
            if subscription.usage.hasQuota {
                let used = UInt64(max(0, subscription.usage.usedBytes))
                let total = UInt64(max(1, subscription.usage.totalBytes))
                let fraction = min(1.0, Double(used) / Double(total))
                let quotaTint = fraction >= 0.90
                    ? theme.danger
                    : (fraction >= 0.75 ? theme.warning : theme.signalEmeraldFill)
                ProgressView(value: fraction)
                    .tint(quotaTint)
                Text("已用 \(NexusByteFormat.bytes(used)) / 总量 \(NexusByteFormat.bytes(total))")
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}
#endif
