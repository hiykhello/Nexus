#if canImport(SwiftUI)
import Foundation
import SwiftUI
import NexusCoreBridge

/// Matte Bento KPI telemetry section shared between macOS Dashboard and iOS/iPadOS views.
/// Strictly separates Core runtime state/memory from UI host App memory (`gui-design-system.md` §2.2/§3.3).
public struct OverviewMetricsSection: View {
    public let metrics: MetricsSnapshot
    public let diagnostics: DiagnosticsSnapshot
    public let network: AppleNetworkSnapshot
    public let isRunning: Bool
    public let residentMemoryMiB: Double?
    public let coreMemoryMiB: Double?
    public let memoryBudgetMiB: Int
    public let workers: Int
    public let rxHistory: [Double]
    public let txHistory: [Double]
    public let onsetMarkers: [SparklineOnsetMarker]
    public let rxRateBytesPerSec: Double
    public let txRateBytesPerSec: Double
    @Environment(\.nexusTheme) private var theme

    public init(
        metrics: MetricsSnapshot,
        diagnostics: DiagnosticsSnapshot,
        network: AppleNetworkSnapshot,
        isRunning: Bool = true,
        residentMemoryMiB: Double? = nil,
        coreMemoryMiB: Double? = nil,
        memoryBudgetMiB: Int = 50,
        workers: Int = 1,
        rxHistory: [Double] = [],
        txHistory: [Double] = [],
        onsetMarkers: [SparklineOnsetMarker] = [],
        rxRateBytesPerSec: Double = 0,
        txRateBytesPerSec: Double = 0
    ) {
        self.metrics = metrics
        self.diagnostics = diagnostics
        self.network = network
        self.isRunning = isRunning
        self.residentMemoryMiB = residentMemoryMiB
        self.coreMemoryMiB = coreMemoryMiB
        self.memoryBudgetMiB = memoryBudgetMiB
        self.workers = max(1, workers)
        self.rxHistory = rxHistory
        self.txHistory = txHistory
        self.onsetMarkers = onsetMarkers
        self.rxRateBytesPerSec = rxRateBytesPerSec
        self.txRateBytesPerSec = txRateBytesPerSec
    }

    private var columns: [GridItem] {
        #if os(iOS)
        [GridItem(.adaptive(minimum: 148, maximum: 280), spacing: 10)]
        #else
        [GridItem(.adaptive(minimum: 175, maximum: 280), spacing: 12)]
        #endif
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            LazyVGrid(columns: columns, spacing: 12) {
                BentoKpiTile(
                    title: "活跃连接",
                    value: "\(max(Int(metrics.activeSessions), diagnostics.activeConnections))",
                    subtitle: "监听端口 \(diagnostics.listeners)",
                    systemImage: "network",
                    tint: theme.accentText
                )
                BentoKpiTile(
                    title: "累计流量",
                    value: "↓ \(NexusByteFormat.bytes(metrics.downloadBytes))",
                    subtitle: "↑ \(NexusByteFormat.bytes(metrics.uploadBytes))",
                    systemImage: "arrow.up.arrow.down.circle",
                    tint: theme.rxLine
                )
                BentoKpiTile(
                    title: "内核状态",
                    value: isRunning ? "\(workers) 线程" : "未运行",
                    subtitle: coreMemorySubtitle,
                    systemImage: "cpu",
                    tint: isRunning ? theme.signalEmerald : theme.secondaryInk
                )
                if let appMem = residentMemoryMiB {
                    appMemoryTile(appMem)
                }
            }

            ThroughputCard(
                rxRateBytesPerSec: rxRateBytesPerSec,
                txRateBytesPerSec: txRateBytesPerSec,
                rxHistory: rxHistory,
                txHistory: txHistory,
                onsetMarkers: onsetMarkers
            )

            NetworkDiagnosticsStrip(network: network)
        }
    }

    private var coreMemorySubtitle: String {
        if let coreMem = coreMemoryMiB {
            return String(format: "内核内存 %.1f MiB", coreMem)
        }
        return isRunning ? "内核内存：未上报" : "等待启动"
    }

    private func appMemoryTile(_ mem: Double) -> some View {
        #if os(iOS)
        let ok = mem < Double(memoryBudgetMiB)
        return BentoKpiTile(
            title: "应用内存",
            value: String(format: "%.1f MiB", mem),
            subtitle: ok ? "扩展预算 < \(memoryBudgetMiB) MiB" : "接近扩展上限 (\(memoryBudgetMiB) MiB)",
            systemImage: "memorychip",
            tint: ok ? theme.signalEmerald : theme.danger
        )
        #else
        return BentoKpiTile(
            title: "应用内存",
            value: String(format: "%.1f MiB", mem),
            subtitle: "界面进程私有占用",
            systemImage: "memorychip",
            tint: theme.signalEmerald
        )
        #endif
    }
}

private struct BentoKpiTile: View {
    let title: String
    let value: String
    let subtitle: String
    let systemImage: String
    let tint: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: systemImage)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(tint)
                    .accessibilityHidden(true)
                Text(title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Text(value)
                .font(.title3.weight(.semibold).monospacedDigit())
                .lineLimit(1)
                .minimumScaleFactor(0.8)
            Text(subtitle)
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .minimumScaleFactor(0.85)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .bentoCard(padding: 12, cornerRadius: 14)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title)：\(value)，\(subtitle)")
    }
}

private struct ThroughputCard: View {
    let rxRateBytesPerSec: Double
    let txRateBytesPerSec: Double
    let rxHistory: [Double]
    let txHistory: [Double]
    let onsetMarkers: [SparklineOnsetMarker]
    @Environment(\.nexusTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 12) {
                    Text("实时吞吐")
                        .font(.subheadline.weight(.semibold))
                    Spacer(minLength: 8)
                    rateSlots
                }
                VStack(alignment: .leading, spacing: 6) {
                    Text("实时吞吐")
                        .font(.subheadline.weight(.semibold))
                    rateSlots
                }
            }
            ThroughputSparklineView(rxSamples: rxHistory, txSamples: txHistory, onsetMarkers: onsetMarkers)
        }
        .bentoCard(padding: 12, cornerRadius: 14)
    }

    private var rateSlots: some View {
        HStack(spacing: 12) {
            LiveRateLabel(text: NexusByteFormat.rate(rxRateBytesPerSec), systemImage: "arrow.down", tint: theme.rxLine)
            LiveRateLabel(text: NexusByteFormat.rate(txRateBytesPerSec), systemImage: "arrow.up", tint: theme.txLine)
        }
    }
}

private struct NetworkDiagnosticsStrip: View {
    let network: AppleNetworkSnapshot
    @Environment(\.nexusTheme) private var theme

    private var connectivitySymbol: String {
        guard network.hasConnectivity else { return "wifi.slash" }
        if network.isExpensive { return "antenna.radiowaves.left.and.right" }
        if let name = network.interfaceName?.lowercased(), name.hasPrefix("en") {
            return "wifi"
        }
        return "network"
    }

    private var interfaceTitle: String {
        guard network.hasConnectivity else { return "网络未连接" }
        return network.interfaceName ?? "可用网络"
    }

    var body: some View {
        HStack(spacing: 10) {
            Label(interfaceTitle, systemImage: connectivitySymbol)
                .font(.caption.weight(.medium))
                .foregroundStyle(network.hasConnectivity ? .primary : .secondary)
            if network.isExpensive {
                Label("计费网络", systemImage: "cellularbars")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(theme.warning)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 3)
                    .background(theme.warning.opacity(0.14), in: Capsule())
            }
            if network.isConstrained {
                Label("低数据模式", systemImage: "tortoise.fill")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(theme.warning)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 3)
                    .background(theme.warning.opacity(0.14), in: Capsule())
            }
            Spacer(minLength: 4)
            Text(network.hasConnectivity ? "物理链路正常" : "等待网络恢复")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .bentoCard(padding: 10, cornerRadius: 14)
        .accessibilityElement(children: .combine)
    }
}
#endif
