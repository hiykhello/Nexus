#if canImport(SwiftUI)
import Foundation
import SwiftUI
import NexusCoreBridge

/// Signature Move #1: Interactive 4-stage Live Route Transit Strip (`入口 → 路由引擎 → 当前出口 → 实时速率`)
/// rendered inside a single flat matte `bentoCard` (macOS/iPad 4-column bar, iPhone compact 2×2 grid).
public struct RouteTransitStripView: View {
    public let isRunning: Bool
    public let inboundLabel: String
    public let inboundDetail: String
    public let outboundMode: String
    public let rulesCount: Int
    public let fakeIpEnabled: Bool
    public let primaryGroup: OutboundGroupSnapshot?
    public let activeRttMs: Int64?
    public let rxRateBytesPerSec: Double
    public let txRateBytesPerSec: Double
    public let activeSessions: UInt64
    public let onTapInbound: () -> Void
    public let onTapRouting: () -> Void
    public let onTapProxies: () -> Void
    public let onSelectMember: (String, String) -> Void
    public let onProbeGroup: (String) -> Void
    public let onTapTraffic: () -> Void

    @Environment(\.nexusTheme) private var theme
    #if os(macOS)
    @State private var isExitHovered = false
    #elseif os(iOS)
    @Environment(\.horizontalSizeClass) private var sizeClass
    #endif

    public init(
        isRunning: Bool,
        inboundLabel: String,
        inboundDetail: String,
        outboundMode: String,
        rulesCount: Int,
        fakeIpEnabled: Bool,
        primaryGroup: OutboundGroupSnapshot?,
        activeRttMs: Int64?,
        rxRateBytesPerSec: Double,
        txRateBytesPerSec: Double,
        activeSessions: UInt64,
        onTapInbound: @escaping () -> Void,
        onTapRouting: @escaping () -> Void,
        onTapProxies: @escaping () -> Void,
        onSelectMember: @escaping (String, String) -> Void,
        onProbeGroup: @escaping (String) -> Void,
        onTapTraffic: @escaping () -> Void
    ) {
        self.isRunning = isRunning
        self.inboundLabel = inboundLabel
        self.inboundDetail = inboundDetail
        self.outboundMode = outboundMode
        self.rulesCount = rulesCount
        self.fakeIpEnabled = fakeIpEnabled
        self.primaryGroup = primaryGroup
        self.activeRttMs = activeRttMs
        self.rxRateBytesPerSec = rxRateBytesPerSec
        self.txRateBytesPerSec = txRateBytesPerSec
        self.activeSessions = activeSessions
        self.onTapInbound = onTapInbound
        self.onTapRouting = onTapRouting
        self.onTapProxies = onTapProxies
        self.onSelectMember = onSelectMember
        self.onProbeGroup = onProbeGroup
        self.onTapTraffic = onTapTraffic
    }

    private var isCompactLayout: Bool {
        #if os(iOS)
        return sizeClass == .compact
        #else
        return false
        #endif
    }

    public var body: some View {
        Group {
            if isCompactLayout {
                LazyVGrid(
                    columns: [GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8)],
                    spacing: 8
                ) {
                    inboundStage
                    routingStage
                    exitStage
                    trafficStage
                }
            } else {
                HStack(spacing: 8) {
                    inboundStage
                    stageConnector
                    routingStage
                    stageConnector
                    exitStage
                    stageConnector
                    trafficStage
                }
            }
        }
        .bentoCard(padding: 10, cornerRadius: 14)
    }

    private var stageConnector: some View {
        Image(systemName: "chevron.right")
            .font(.caption2.weight(.bold))
            .foregroundStyle(isRunning ? theme.signalEmerald : theme.hairlineBorder)
            .accessibilityHidden(true)
    }

    private var inboundStage: some View {
        Button(action: onTapInbound) {
            stageCell(
                icon: "shield.lefthalf.filled",
                iconTint: isRunning ? theme.accentText : .secondary,
                title: "入口",
                primary: inboundLabel,
                secondary: inboundDetail
            )
        }
        .buttonStyle(NexusSurfaceButtonStyle(cornerRadius: 8))
        .accessibilityHint("打开代理与虚拟网卡设置")
    }

    private var routingStage: some View {
        let modeText = NexusDisplayCopy.outboundModeTitle(outboundMode)
        let detail = fakeIpEnabled ? "\(rulesCount) 规则 · FakeIP" : "\(rulesCount) 规则"
        return Button(action: onTapRouting) {
            stageCell(
                icon: "arrow.triangle.branch",
                iconTint: theme.accentText,
                title: "路由引擎",
                primary: "\(modeText)模式",
                secondary: detail
            )
        }
        .buttonStyle(NexusSurfaceButtonStyle(cornerRadius: 8))
        .accessibilityHint("打开规则与 DNS 诊断")
    }

    @ViewBuilder
    private var exitStage: some View {
        if let group = primaryGroup {
            let activeName = group.active.isEmpty ? "未选择" : group.active
            let rttText = activeRttMs.map { "\($0) ms" } ?? (isRunning ? "未测速" : "离线")
            Menu {
                if group.supportsManualSelection {
                    ForEach(group.members) { member in
                        Button {
                            onSelectMember(group.tag, member.name)
                        } label: {
                            if member.name == group.active {
                                Label(member.name, systemImage: "checkmark")
                            } else {
                                Text(member.latencyMs >= 0 ? "\(member.name) (\(member.latencyMs) ms)" : member.name)
                            }
                        }
                    }
                    Divider()
                }
                Button("测速策略组") { onProbeGroup(group.tag) }
                Button("打开代理与策略组", action: onTapProxies)
            } label: {
                stageCell(
                    icon: "circle.fill",
                    iconTint: isRunning ? theme.signalEmerald : .secondary,
                    title: "当前出口 · \(group.tag)",
                    primary: activeName,
                    secondary: rttText,
                    highlighted: isExitMenuHighlighted
                )
            }
            .buttonStyle(.plain)
            #if os(macOS)
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .onHover { isExitHovered = $0 }
            #elseif os(iOS)
            .sensoryFeedback(.selection, trigger: group.active)
            #endif
            .nexusTooltip("\(group.tag) → \(activeName) (\(rttText))")
        } else {
            Button(action: onTapProxies) {
                stageCell(
                    icon: "circle.fill",
                    iconTint: .secondary,
                    title: "当前出口",
                    primary: isRunning ? "默认出站" : "未连接",
                    secondary: "点击查看策略组"
                )
            }
            .buttonStyle(NexusSurfaceButtonStyle(cornerRadius: 8))
        }
    }

    private var isExitMenuHighlighted: Bool {
        #if os(macOS)
        return isExitHovered
        #else
        return false
        #endif
    }

    private var trafficStage: some View {
        Button(action: onTapTraffic) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 4) {
                    Image(systemName: "waveform.path.ecg")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(theme.rxLine)
                        .accessibilityHidden(true)
                    Text("实时速率")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    Spacer(minLength: 2)
                    Text("\(activeSessions) 连接")
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                HStack(spacing: 4) {
                    Image(systemName: "arrow.down")
                        .font(.caption2.weight(.bold))
                        .imageScale(.small)
                        .foregroundStyle(theme.rxLine)
                        .accessibilityHidden(true)
                    Text(NexusByteFormat.rate(rxRateBytesPerSec))
                        .font(.caption.weight(.semibold).monospacedDigit())
                        .foregroundStyle(theme.rxLine)
                        .lineLimit(1)
                        .minimumScaleFactor(0.85)
                }
                HStack(spacing: 4) {
                    Image(systemName: "arrow.up")
                        .font(.caption2.weight(.bold))
                        .imageScale(.small)
                        .foregroundStyle(theme.txLine)
                        .accessibilityHidden(true)
                    Text(NexusByteFormat.rate(txRateBytesPerSec))
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(theme.txLine)
                        .lineLimit(1)
                        .minimumScaleFactor(0.85)
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .frame(maxWidth: .infinity, minHeight: isCompactLayout ? 52 : 44, alignment: .leading)
            .background(theme.wellSurface, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .contentShape(Rectangle())
        }
        .buttonStyle(NexusSurfaceButtonStyle(cornerRadius: 8))
        .accessibilityHint("打开活跃连接列表")
    }

    private func stageCell(
        icon: String,
        iconTint: Color,
        title: String,
        primary: String,
        secondary: String,
        highlighted: Bool = false
    ) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 4) {
                Image(systemName: icon)
                    .font(.caption2.weight(.semibold))
                    .imageScale(.small)
                    .foregroundStyle(iconTint)
                    .accessibilityHidden(true)
                Text(title)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Text(primary)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.primary)
                .lineLimit(1)
                .truncationMode(.middle)
                .nexusTooltip(primary)
            Text(secondary)
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .frame(maxWidth: .infinity, minHeight: isCompactLayout ? 52 : 44, alignment: .leading)
        .background(highlighted ? theme.hoverSurface : theme.wellSurface, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .contentShape(Rectangle())
    }
}

/// Compact 1-line transit summary for `MenuBarPopoverView` (`:7890 › 规则 › HK-01 · 38 ms`).
public struct MiniTransitStrip: View {
    public let isRunning: Bool
    public let inboundLabel: String
    public let outboundMode: String
    public let activeExit: String
    public let activeRttMs: Int64?
    @Environment(\.nexusTheme) private var theme

    public init(
        isRunning: Bool,
        inboundLabel: String,
        outboundMode: String,
        activeExit: String,
        activeRttMs: Int64?
    ) {
        self.isRunning = isRunning
        self.inboundLabel = inboundLabel
        self.outboundMode = outboundMode
        self.activeExit = activeExit
        self.activeRttMs = activeRttMs
    }

    public var body: some View {
        let modeTitle = NexusDisplayCopy.outboundModeTitle(outboundMode)
        let rttLabel = activeRttMs.map { "\($0) ms" } ?? (isRunning ? "—" : "离线")
        let fullSummary = "\(inboundLabel) › \(modeTitle) › \(activeExit) (\(rttLabel))"
        HStack(spacing: 5) {
            Circle()
                .fill(isRunning ? theme.signalEmerald : Color.secondary)
                .frame(width: 6, height: 6)
                .accessibilityHidden(true)
            Text(inboundLabel)
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.secondary)
                .lineLimit(1)
            Image(systemName: "chevron.right")
                .font(.caption2.weight(.bold))
                .imageScale(.small)
                .foregroundStyle(isRunning ? theme.signalEmerald : .secondary)
                .accessibilityHidden(true)
            Text(modeTitle)
                .font(.caption2.weight(.medium))
                .foregroundStyle(theme.accentText)
                .lineLimit(1)
            Image(systemName: "chevron.right")
                .font(.caption2.weight(.bold))
                .imageScale(.small)
                .foregroundStyle(isRunning ? theme.signalEmerald : .secondary)
                .accessibilityHidden(true)
            Text(activeExit)
                .font(.caption2.weight(.semibold))
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 4)
            Text(rttLabel)
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .background(theme.wellSurface, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .nexusTooltip(fullSummary)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("当前链路：\(fullSummary)")
    }
}
#endif
