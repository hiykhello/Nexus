#if canImport(SwiftUI)
import Foundation
import SwiftUI
import NexusCoreBridge

/// Dismissible detail inspector card for a selected active connection, including
/// a `2pt` dual-tone traffic share micro-bar and 1-click domain diagnostic trigger.
public struct ConnectionDetailCard: View {
    public let detail: ActiveConnectionSnapshot
    public let maxTotalBytes: UInt64
    public let onDiagnoseDomain: ((String) -> Void)?
    public let onDismiss: (() -> Void)?

    public init(
        detail: ActiveConnectionSnapshot,
        maxTotalBytes: UInt64 = 1,
        onDiagnoseDomain: ((String) -> Void)? = nil,
        onDismiss: (() -> Void)? = nil
    ) {
        self.detail = detail
        self.maxTotalBytes = max(1, maxTotalBytes)
        self.onDiagnoseDomain = onDiagnoseDomain
        self.onDismiss = onDismiss
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("连接 #\(detail.id) 链路详情")
                    .font(.subheadline.weight(.semibold).monospacedDigit())
                Spacer()
                Text("\(detail.durationMs) ms")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
                if let onDismiss {
                    Button(action: onDismiss) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.borderless)
                    .accessibilityLabel("关闭连接详情")
                    .nexusTooltip("关闭详情面板")
                }
            }
            TrafficShareMicroBar(
                uploadBytes: detail.uploadBytes,
                downloadBytes: detail.downloadBytes,
                maxTotalBytes: maxTotalBytes
            )
            Divider()
            VStack(alignment: .leading, spacing: 4) {
                Text("入站：\(NexusDisplayCopy.connectionInboundLabel(inbound: detail.inbound, listener: detail.listener))  ·  出站：\(detail.outbound.isEmpty ? detail.path : detail.outbound)")
                Text("来源：\(detail.source.isEmpty ? "—" : detail.source)  →  目标：\(detail.target.isEmpty ? ":\(detail.destinationPort)" : detail.target)")
                Text("路由：\(detail.routeMode.isEmpty ? "—" : NexusDisplayCopy.outboundModeTitle(detail.routeMode)) \(detail.routeRule)  ·  流量：↑ \(NexusByteFormat.bytes(detail.uploadBytes)) / ↓ \(NexusByteFormat.bytes(detail.downloadBytes))")
                Text("进程：\(detail.processPath.isEmpty ? "—" : detail.processPath)  ·  UID：\(detail.sourceUid.map(String.init) ?? "—")")
            }
            .font(.caption.monospaced())
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
            if let onDiagnoseDomain, !detail.target.isEmpty {
                Button {
                    onDiagnoseDomain(detail.target)
                } label: {
                    Label("诊断此域名", systemImage: "magnifyingglass")
                        .font(.caption)
                }
                .buttonStyle(.bordered)
            }
        }
        .bentoCard(padding: 12)
    }
}
#endif
