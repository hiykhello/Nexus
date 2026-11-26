#if canImport(SwiftUI)
import SwiftUI
import NexusCoreBridge

/// Cross-platform (macOS + iOS/iPadOS) active connections browser with filter pills,
/// search, detail inspector card, and confirmed bulk disconnect.
public struct ConnectionsView: View {
    public let connections: [ActiveConnectionSnapshot]
    public let selectedDetail: ActiveConnectionSnapshot?
    public let onRefresh: () -> Void
    public let onInspect: (String) -> Void
    public let onClose: (String) -> Void
    public let onCloseAll: () -> Void

    @State private var filterText: String = ""
    @State private var pathFilter: PathFilter = .all
    @State private var showCloseAllConfirm: Bool = false

    private enum PathFilter: String, CaseIterable, Identifiable {
        case all = "全部"
        case proxy = "代理"
        case direct = "直连"
        var id: String { rawValue }
    }

    public init(
        connections: [ActiveConnectionSnapshot],
        selectedDetail: ActiveConnectionSnapshot?,
        onRefresh: @escaping () -> Void,
        onInspect: @escaping (String) -> Void,
        onClose: @escaping (String) -> Void,
        onCloseAll: @escaping () -> Void
    ) {
        self.connections = connections
        self.selectedDetail = selectedDetail
        self.onRefresh = onRefresh
        self.onInspect = onInspect
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

    private var totalUpload: UInt64 {
        filtered.reduce(0) { $0 &+ $1.uploadBytes }
    }

    private var totalDownload: UInt64 {
        filtered.reduce(0) { $0 &+ $1.downloadBytes }
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                TextField("过滤协议 / 出站 / 目标 / 进程 / 端口...", text: $filterText)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel("搜索活跃连接")
                Picker("路径过滤", selection: $pathFilter) {
                    ForEach(PathFilter.allCases) { f in
                        Text(f.rawValue).tag(f)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 170)
                Button("断开全部", role: .destructive) {
                    showCloseAllConfirm = true
                }
                .disabled(connections.isEmpty)
                .accessibilityHint("关闭当前全部活跃连接（会弹出确认）")
                Button(action: onRefresh) {
                    Label("刷新", systemImage: "arrow.clockwise")
                }
            }

            HStack(spacing: 14) {
                Text("连接数 \(filtered.count) / \(connections.count)")
                    .font(.caption.weight(.medium).monospacedDigit())
                Spacer()
                Text("↑ \(NexusByteFormat.bytes(totalUpload))  ·  ↓ \(NexusByteFormat.bytes(totalDownload))")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 4)

            if let detail = selectedDetail {
                ConnectionDetailCard(detail: detail)
            }

            if filtered.isEmpty {
                ContentUnavailableView(
                    "暂无活跃连接",
                    systemImage: "network",
                    description: Text("Nexus 代理转发期间活跃连接将实时显示在此处。")
                )
            } else {
                List(filtered) { conn in
                    ConnectionRowView(
                        conn: conn,
                        onInspect: { onInspect(conn.id) },
                        onClose: { onClose(conn.id) }
                    )
                }
            }
        }
        .padding()
        .confirmationDialog(
            "确认断开全部 \(connections.count) 个活跃连接？",
            isPresented: $showCloseAllConfirm,
            titleVisibility: .visible
        ) {
            Button("断开全部", role: .destructive, action: onCloseAll)
            Button("取消", role: .cancel) {}
        }
    }
}

private struct ConnectionRowView: View {
    let conn: ActiveConnectionSnapshot
    let onInspect: () -> Void
    let onClose: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text("#\(conn.id) · \(conn.protocolName) (\(conn.outbound.isEmpty ? conn.path : conn.outbound)) → \(conn.target.isEmpty ? ":\(conn.destinationPort)" : conn.target)")
                    .font(.subheadline.weight(.semibold).monospacedDigit())
                    .lineLimit(1)
                Text("入站 \(conn.inbound.isEmpty ? "listener \(conn.listener)" : conn.inbound) · \(conn.durationMs) ms\(conn.routeRule.isEmpty ? "" : " · 规则 \(conn.routeRule)")")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            Text("↑ \(NexusByteFormat.bytes(conn.uploadBytes))  ↓ \(NexusByteFormat.bytes(conn.downloadBytes))")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
            Button("详情", action: onInspect)
                .buttonStyle(.borderless)
            Button("断开", role: .destructive, action: onClose)
                .buttonStyle(.borderless)
                .accessibilityLabel("断开连接 \(conn.id)")
        }
    }
}

public struct ConnectionDetailCard: View {
    public let detail: ActiveConnectionSnapshot

    public init(detail: ActiveConnectionSnapshot) {
        self.detail = detail
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("连接 #\(detail.id) 链路详情")
                    .font(.subheadline.weight(.semibold).monospacedDigit())
                Spacer()
                Text("\(detail.durationMs) ms")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            VStack(alignment: .leading, spacing: 3) {
                Text("入站: \(detail.inbound.isEmpty ? detail.protocolName : detail.inbound)  ·  出站: \(detail.outbound.isEmpty ? detail.path : detail.outbound)")
                Text("来源: \(detail.source.isEmpty ? "-" : detail.source)  →  目标: \(detail.target.isEmpty ? ":\(detail.destinationPort)" : detail.target)")
                Text("路由: \(detail.routeMode.isEmpty ? "-" : detail.routeMode) \(detail.routeRule)  ·  流量: ↑ \(NexusByteFormat.bytes(detail.uploadBytes)) / ↓ \(NexusByteFormat.bytes(detail.downloadBytes))")
                Text("进程: \(detail.processPath.isEmpty ? "-" : detail.processPath)  ·  UID: \(detail.sourceUid.map(String.init) ?? "-")")
            }
            .font(.caption.monospaced())
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .bentoCard(padding: 12)
    }
}
#endif
