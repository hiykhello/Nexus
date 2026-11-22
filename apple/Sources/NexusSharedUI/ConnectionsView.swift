#if canImport(SwiftUI)
import SwiftUI
import NexusCoreBridge

/// Cross-platform (macOS + iOS/iPadOS) active connections browser with search and detail drawer.
public struct ConnectionsView: View {
    public let connections: [ActiveConnectionSnapshot]
    public let selectedDetail: ActiveConnectionSnapshot?
    public let onRefresh: () -> Void
    public let onInspect: (String) -> Void
    public let onClose: (String) -> Void
    public let onCloseAll: () -> Void

    @State private var filterText: String = ""

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
        guard !q.isEmpty else { return connections }
        return connections.filter {
            $0.protocolName.lowercased().contains(q)
                || $0.path.lowercased().contains(q)
                || $0.outbound.lowercased().contains(q)
                || $0.inbound.lowercased().contains(q)
                || $0.target.lowercased().contains(q)
                || String($0.destinationPort).contains(q)
        }
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                TextField("过滤协议 / 出站 / 目标 / 端口...", text: $filterText)
                    .textFieldStyle(.roundedBorder)
                Button("断开全部", role: .destructive, action: onCloseAll)
                    .disabled(connections.isEmpty)
                Button("刷新", action: onRefresh)
            }
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
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("#\(conn.id) · \(conn.protocolName) (\(conn.outbound.isEmpty ? conn.path : conn.outbound)) → \(conn.target.isEmpty ? ":\(conn.destinationPort)" : conn.target)")
                                .font(.headline)
                            Text("入站 \(conn.inbound.isEmpty ? "listener \(conn.listener)" : conn.inbound) · \(conn.durationMs) ms")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text("↑ \(conn.uploadBytes / 1024) KiB  ↓ \(conn.downloadBytes / 1024) KiB")
                            .font(.caption.monospacedDigit())
                        Button("详情") { onInspect(conn.id) }
                            .buttonStyle(.borderless)
                        Button("断开", role: .destructive) { onClose(conn.id) }
                            .buttonStyle(.borderless)
                    }
                }
            }
        }
        .padding()
    }
}

public struct ConnectionDetailCard: View {
    public let detail: ActiveConnectionSnapshot

    public init(detail: ActiveConnectionSnapshot) {
        self.detail = detail
    }

    public var body: some View {
        GroupBox("连接 #\(detail.id) 链路详情") {
            VStack(alignment: .leading, spacing: 4) {
                Text("入站: \(detail.inbound.isEmpty ? detail.protocolName : detail.inbound)  ·  出站: \(detail.outbound.isEmpty ? detail.path : detail.outbound)")
                Text("来源: \(detail.source.isEmpty ? "-" : detail.source)  →  目标: \(detail.target.isEmpty ? ":\(detail.destinationPort)" : detail.target)")
                Text("路由: \(detail.routeMode.isEmpty ? "-" : detail.routeMode) \(detail.routeRule)  ·  持续: \(detail.durationMs) ms")
                Text("进程: \(detail.processPath.isEmpty ? "-" : detail.processPath)  ·  UID: \(detail.sourceUid.map(String.init) ?? "-")")
            }
            .font(.caption.monospaced())
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
#endif
