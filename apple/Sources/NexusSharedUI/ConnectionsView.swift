#if canImport(SwiftUI)
import Foundation
import SwiftUI
import NexusCoreBridge

/// Cross-platform active connections browser:
/// - macOS: native sortable `Table` + `.contextMenu` + dismissible `.inspector`
/// - iOS/iPadOS: adaptive `List` + `.swipeActions` + dismissible `.sheet`
public struct ConnectionsView: View {
    public let connections: [ActiveConnectionSnapshot]
    public let selectedDetail: ActiveConnectionSnapshot?
    public let focusSearchTrigger: Int
    public let shouldAutoFocusSearch: Bool
    public let onConsumeSearchFocus: () -> Void
    public let onRefresh: () -> Void
    public let onInspect: (String) -> Void
    public let onDismissDetail: () -> Void
    public let onDiagnoseDomain: ((String) -> Void)?
    public let onClose: (String) -> Void
    public let onCloseAll: () -> Void

    @State private var filterText: String = ""
    @State private var pathFilter: PathFilter = .all
    @State private var showCloseAllConfirm: Bool = false
    @State private var selectedRowID: ActiveConnectionSnapshot.ID?
    #if os(macOS)
    @State private var sortOrder: [KeyPathComparator<ActiveConnectionSnapshot>] = [
        KeyPathComparator(\ActiveConnectionSnapshot.downloadBytes, order: .reverse),
    ]
    #endif
    @FocusState private var isFilterFocused: Bool
    #if os(iOS)
    @Environment(\.horizontalSizeClass) private var sizeClass
    #endif

    private enum PathFilter: String, CaseIterable, Identifiable {
        case all = "全部"
        case proxy = "代理"
        case direct = "直连"
        var id: String { rawValue }
    }

    public init(
        connections: [ActiveConnectionSnapshot],
        selectedDetail: ActiveConnectionSnapshot?,
        focusSearchTrigger: Int = 0,
        shouldAutoFocusSearch: Bool = false,
        onConsumeSearchFocus: @escaping () -> Void = {},
        onRefresh: @escaping () -> Void,
        onInspect: @escaping (String) -> Void,
        onDismissDetail: @escaping () -> Void = {},
        onDiagnoseDomain: ((String) -> Void)? = nil,
        onClose: @escaping (String) -> Void,
        onCloseAll: @escaping () -> Void
    ) {
        self.connections = connections
        self.selectedDetail = selectedDetail
        self.focusSearchTrigger = focusSearchTrigger
        self.shouldAutoFocusSearch = shouldAutoFocusSearch
        self.onConsumeSearchFocus = onConsumeSearchFocus
        self.onRefresh = onRefresh
        self.onInspect = onInspect
        self.onDismissDetail = onDismissDetail
        self.onDiagnoseDomain = onDiagnoseDomain
        self.onClose = onClose
        self.onCloseAll = onCloseAll
    }

    private var filtered: [ActiveConnectionSnapshot] {
        let q = filterText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return connections.filter { conn in
            switch pathFilter {
            case .all: break
            case .direct:
                if conn.path.lowercased() != "direct" && conn.outbound.lowercased() != "direct" { return false }
            case .proxy:
                if conn.path.lowercased() == "direct" || conn.outbound.lowercased() == "direct" { return false }
            }
            guard !q.isEmpty else { return true }
            return conn.protocolName.lowercased().contains(q)
                || conn.path.lowercased().contains(q)
                || conn.outbound.lowercased().contains(q)
                || conn.inbound.lowercased().contains(q)
                || conn.target.lowercased().contains(q)
                || conn.processPath.lowercased().contains(q)
                || String(conn.destinationPort).contains(q)
        }
    }

    #if os(macOS)
    private var sortedConnections: [ActiveConnectionSnapshot] {
        filtered.sorted(using: sortOrder)
    }
    #endif

    private var totalUpload: UInt64 {
        filtered.reduce(0) { $0 &+ $1.uploadBytes }
    }

    private var totalDownload: UInt64 {
        filtered.reduce(0) { $0 &+ $1.downloadBytes }
    }

    private var maxConnectionTrafficBytes: UInt64 {
        filtered.map { $0.uploadBytes &+ $0.downloadBytes }.max() ?? 1
    }

    private var detailPresentedBinding: Binding<Bool> {
        Binding(
            get: { selectedDetail != nil },
            set: { isPresented in
                if !isPresented {
                    selectedRowID = nil
                    onDismissDetail()
                }
            }
        )
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            filterToolbar
            summaryHeader
            mainContent
        }
        .padding()
        #if os(macOS)
        .inspector(isPresented: detailPresentedBinding) {
            if let detail = selectedDetail {
                ScrollView {
                    ConnectionDetailCard(
                        detail: detail,
                        maxTotalBytes: maxConnectionTrafficBytes,
                        onDiagnoseDomain: onDiagnoseDomain,
                        onDismiss: {
                            selectedRowID = nil
                            onDismissDetail()
                        }
                    )
                    .padding()
                }
                .inspectorColumnWidth(min: 260, ideal: 310, max: 420)
            }
        }
        #else
        .sheet(isPresented: detailPresentedBinding) {
            if let detail = selectedDetail {
                NavigationStack {
                    ScrollView {
                        ConnectionDetailCard(
                            detail: detail,
                            maxTotalBytes: maxConnectionTrafficBytes,
                            onDiagnoseDomain: onDiagnoseDomain,
                            onDismiss: nil
                        )
                        .padding()
                    }
                    .navigationTitle("连接 #\(detail.id)")
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button("完成") {
                                selectedRowID = nil
                                onDismissDetail()
                            }
                        }
                    }
                }
            }
        }
        #endif
        .confirmationDialog(
            "确认断开全部 \(connections.count) 个活跃连接？",
            isPresented: $showCloseAllConfirm,
            titleVisibility: .visible
        ) {
            Button("断开全部", role: .destructive, action: onCloseAll)
            Button("取消", role: .cancel) {}
        }
        .onAppear {
            consumePendingSearchFocusIfNeeded()
        }
        .onChange(of: focusSearchTrigger) { _, _ in
            consumePendingSearchFocusIfNeeded()
        }
        .onChange(of: selectedRowID) { _, newID in
            if let newID {
                if selectedDetail?.id != newID { onInspect(newID) }
            } else {
                onDismissDetail()
            }
        }
    }

    private func consumePendingSearchFocusIfNeeded() {
        if shouldAutoFocusSearch {
            isFilterFocused = true
            onConsumeSearchFocus()
        }
    }

    private var isCompactLayout: Bool {
        #if os(iOS)
        return sizeClass == .compact
        #else
        return false
        #endif
    }

    private func triggerInspect(_ id: String) {
        if selectedRowID == id {
            if selectedDetail?.id != id { onInspect(id) }
        } else {
            selectedRowID = id
        }
    }

    @ViewBuilder
    private var filterToolbar: some View {
        if isCompactLayout {
            VStack(alignment: .leading, spacing: 8) {
                searchField
                HStack(spacing: 8) {
                    pathPicker
                    disconnectAllButton
                    refreshButton
                }
            }
        } else {
            HStack(spacing: 8) {
                searchField
                pathPicker
                    .frame(minWidth: 150, idealWidth: 170, maxWidth: 210)
                disconnectAllButton
                refreshButton
            }
        }
    }

    private var searchField: some View {
        TextField("过滤协议 / 出站 / 目标 / 进程 / 端口…", text: $filterText)
            .textFieldStyle(.roundedBorder)
            .focused($isFilterFocused)
            .accessibilityLabel("搜索活跃连接")
    }

    private var pathPicker: some View {
        Picker("转发方式", selection: $pathFilter) {
            ForEach(PathFilter.allCases) { f in
                Text(f.rawValue).tag(f)
            }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
    }

    private var disconnectAllButton: some View {
        Button("断开全部", role: .destructive) {
            showCloseAllConfirm = true
        }
        .disabled(connections.isEmpty)
        .accessibilityHint("关闭当前全部活跃连接（会弹出确认）")
        #if os(iOS)
        .frame(minHeight: 44)
        #endif
    }

    private var refreshButton: some View {
        Button(action: onRefresh) {
            Label("刷新", systemImage: "arrow.clockwise")
        }
        #if os(iOS)
        .frame(minHeight: 44)
        #endif
    }

    private var summaryHeader: some View {
        HStack(spacing: 12) {
            Text("连接数 \(filtered.count) / \(connections.count)")
                .font(.caption.weight(.medium).monospacedDigit())
            Spacer(minLength: 6)
            LiveRateLabel(text: NexusByteFormat.bytes(totalUpload), systemImage: "arrow.up", tint: .secondary)
            LiveRateLabel(text: NexusByteFormat.bytes(totalDownload), systemImage: "arrow.down", tint: .secondary)
        }
        .padding(.horizontal, 4)
    }

    @ViewBuilder
    private var mainContent: some View {
        if connections.isEmpty {
            ContentUnavailableView {
                Label("暂无活跃连接", systemImage: "network")
            } description: {
                Text("Nexus 代理转发期间，活跃连接将实时显示在此处。")
            } actions: {
                Button("刷新", action: onRefresh)
                    .buttonStyle(NexusProminentButtonStyle())
            }
        } else if filtered.isEmpty {
            let trimmed = filterText.trimmingCharacters(in: .whitespacesAndNewlines)
            ContentUnavailableView {
                Label(
                    trimmed.isEmpty ? "当前转发方式暂无连接" : "未找到“\(trimmed)”",
                    systemImage: trimmed.isEmpty ? "line.3.horizontal.decrease.circle" : "magnifyingglass"
                )
            } description: {
                Text(trimmed.isEmpty ? "切换筛选条件以查看其他活跃连接。" : "请尝试其他关键词或重置筛选条件。")
            } actions: {
                Button("重置筛选") {
                    filterText = ""
                    pathFilter = .all
                }
                .buttonStyle(.bordered)
            }
        } else {
            #if os(macOS)
            macConnectionsTable
            #else
            mobileConnectionsList
            #endif
        }
    }

    #if os(macOS)
    private var macConnectionsTable: some View {
        Table(sortedConnections, selection: $selectedRowID, sortOrder: $sortOrder) {
            TableColumn("目标", value: \.target) { conn in
                let label = conn.target.isEmpty ? ":\(conn.destinationPort)" : conn.target
                Text(label)
                    .font(.caption.monospaced())
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(label)
            }
            .width(min: 150, ideal: 240)

            TableColumn("出站", value: \.outbound) { conn in
                let out = conn.outbound.isEmpty ? conn.path : conn.outbound
                Text(out)
                    .font(.caption)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(out)
            }
            .width(min: 80, ideal: 115)

            TableColumn("协议", value: \.protocolName) { conn in
                Text(conn.protocolName)
                    .font(.caption.monospaced())
                    .lineLimit(1)
            }
            .width(min: 54, ideal: 68)

            TableColumn("上传", value: \.uploadBytes) { conn in
                Text(NexusByteFormat.bytes(conn.uploadBytes))
                    .font(.caption.monospacedDigit())
                    .frame(maxWidth: .infinity, alignment: .trailing)
            }
            .width(min: 72, ideal: 86)

            TableColumn("下载", value: \.downloadBytes) { conn in
                Text(NexusByteFormat.bytes(conn.downloadBytes))
                    .font(.caption.monospacedDigit())
                    .frame(maxWidth: .infinity, alignment: .trailing)
            }
            .width(min: 72, ideal: 86)

            TableColumn("时长", value: \.durationMs) { conn in
                Text("\(conn.durationMs) ms")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .trailing)
            }
            .width(min: 64, ideal: 78)
        }
        .contextMenu(forSelectionType: ActiveConnectionSnapshot.ID.self) { ids in
            if let first = ids.first {
                Button("查看详情") { triggerInspect(first) }
                if let onDiagnoseDomain,
                   let match = connections.first(where: { $0.id == first }),
                   !match.target.isEmpty {
                    Button("诊断此域名") { onDiagnoseDomain(match.target) }
                }
                Button("断开连接", role: .destructive) {
                    for id in ids { onClose(id) }
                }
            }
        }
    }
    #endif

    #if !os(macOS)
    private var mobileConnectionsList: some View {
        let maxBytes = maxConnectionTrafficBytes
        return List(filtered) { conn in
            Button {
                triggerInspect(conn.id)
            } label: {
                ConnectionRowView(conn: conn, maxTotalBytes: maxBytes)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                Button("断开", role: .destructive) { onClose(conn.id) }
            }
            .contextMenu {
                Button("查看详情") { triggerInspect(conn.id) }
                if let onDiagnoseDomain, !conn.target.isEmpty {
                    Button("诊断此域名") { onDiagnoseDomain(conn.target) }
                }
                Button("断开连接", role: .destructive) { onClose(conn.id) }
            }
        }
        .scrollContentBackground(.hidden)
    }
    #endif
}

#if !os(macOS)
private struct ConnectionRowView: View {
    let conn: ActiveConnectionSnapshot
    let maxTotalBytes: UInt64

    private var targetText: String {
        conn.target.isEmpty ? ":\(conn.destinationPort)" : conn.target
    }

    private var inboundText: String {
        NexusDisplayCopy.connectionInboundLabel(inbound: conn.inbound, listener: conn.listener)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("\(conn.outbound.isEmpty ? conn.path : conn.outbound) → \(targetText)")
                        .font(.subheadline.weight(.semibold))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text("\(conn.protocolName.uppercased()) · \(inboundText) · \(conn.durationMs) ms\(conn.routeRule.isEmpty ? "" : " · \(conn.routeRule)")")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer(minLength: 6)
                VStack(alignment: .trailing, spacing: 2) {
                    Text("↓ \(NexusByteFormat.bytes(conn.downloadBytes))")
                        .font(.caption.monospacedDigit())
                    Text("↑ \(NexusByteFormat.bytes(conn.uploadBytes))")
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
            }
            TrafficShareMicroBar(
                uploadBytes: conn.uploadBytes,
                downloadBytes: conn.downloadBytes,
                maxTotalBytes: maxTotalBytes
            )
        }
        .padding(.vertical, 2)
    }
}
#endif
#endif
