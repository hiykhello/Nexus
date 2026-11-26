#if canImport(SwiftUI)
import SwiftUI
import NexusCoreBridge

/// Matte Bento KPI telemetry section shared between macOS Dashboard and iOS/iPadOS views.
public struct OverviewMetricsSection: View {
    public let metrics: MetricsSnapshot
    public let diagnostics: DiagnosticsSnapshot
    public let network: AppleNetworkSnapshot
    public let residentMemoryMiB: Double?
    public let memoryBudgetMiB: Int
    public let workers: Int
    public let rxHistory: [Double]
    public let txHistory: [Double]
    public let rxRateBytesPerSec: Double
    public let txRateBytesPerSec: Double

    public init(
        metrics: MetricsSnapshot,
        diagnostics: DiagnosticsSnapshot,
        network: AppleNetworkSnapshot,
        residentMemoryMiB: Double? = nil,
        memoryBudgetMiB: Int = 50,
        workers: Int = 1,
        rxHistory: [Double] = [],
        txHistory: [Double] = [],
        rxRateBytesPerSec: Double = 0,
        txRateBytesPerSec: Double = 0
    ) {
        self.metrics = metrics
        self.diagnostics = diagnostics
        self.network = network
        self.residentMemoryMiB = residentMemoryMiB
        self.memoryBudgetMiB = memoryBudgetMiB
        self.workers = max(1, workers)
        self.rxHistory = rxHistory
        self.txHistory = txHistory
        self.rxRateBytesPerSec = rxRateBytesPerSec
        self.txRateBytesPerSec = txRateBytesPerSec
    }

    private let columns = [
        GridItem(.adaptive(minimum: 155, maximum: 260), spacing: 12),
    ]

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            LazyVGrid(columns: columns, spacing: 12) {
                BentoKpiTile(
                    title: "活跃连接",
                    value: "\(max(Int(metrics.activeSessions), diagnostics.activeConnections))",
                    subtitle: "监听端口 \(diagnostics.listeners)",
                    systemImage: "network",
                    tint: .blue
                )
                BentoKpiTile(
                    title: "累计下行 / 上行",
                    value: NexusByteFormat.bytes(metrics.downloadBytes),
                    subtitle: "↑ \(NexusByteFormat.bytes(metrics.uploadBytes))",
                    systemImage: "arrow.up.arrow.down.circle",
                    tint: .teal
                )
                if let mem = residentMemoryMiB {
                    let ok = mem < Double(memoryBudgetMiB)
                    BentoKpiTile(
                        title: "常驻内存",
                        value: String(format: "%.1f MiB", mem),
                        subtitle: ok ? "预算 < \(memoryBudgetMiB) MiB" : "超限预警 (\(memoryBudgetMiB) MiB)",
                        systemImage: "memorychip",
                        tint: ok ? .green : .red
                    )
                }
                BentoKpiTile(
                    title: "核心并发",
                    value: "\(workers) 线程",
                    subtitle: "控制代次 #\(metrics.controlGeneration)",
                    systemImage: "cpu",
                    tint: .indigo
                )
            }

            ThroughputCard(
                rxRateBytesPerSec: rxRateBytesPerSec,
                txRateBytesPerSec: txRateBytesPerSec,
                rxHistory: rxHistory,
                txHistory: txHistory
            )

            NetworkDiagnosticsStrip(network: network, diagnostics: diagnostics)
        }
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
            }
            Text(value)
                .font(.title3.weight(.semibold).monospacedDigit())
                .lineLimit(1)
                .minimumScaleFactor(0.85)
            Text(subtitle)
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .bentoCard(padding: 12)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title): \(value), \(subtitle)")
    }
}

private struct ThroughputCard: View {
    let rxRateBytesPerSec: Double
    let txRateBytesPerSec: Double
    let rxHistory: [Double]
    let txHistory: [Double]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("实时吞吐")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                HStack(spacing: 12) {
                    Label(NexusByteFormat.rate(rxRateBytesPerSec), systemImage: "arrow.down")
                        .font(.caption.weight(.medium).monospacedDigit())
                        .foregroundStyle(.blue)
                    Label(NexusByteFormat.rate(txRateBytesPerSec), systemImage: "arrow.up")
                        .font(.caption.weight(.medium).monospacedDigit())
                        .foregroundStyle(.green)
                }
            }
            ThroughputSparklineView(rxSamples: rxHistory, txSamples: txHistory)
        }
        .bentoCard(padding: 12)
    }
}

private struct NetworkDiagnosticsStrip: View {
    let network: AppleNetworkSnapshot
    let diagnostics: DiagnosticsSnapshot

    var body: some View {
        HStack(spacing: 14) {
            Label(network.interfaceName ?? "无物理网口", systemImage: "wifi")
                .font(.caption.weight(.medium))
            if network.isExpensive {
                Text("计费")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.orange)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.orange.opacity(0.12), in: Capsule())
            }
            if network.isConstrained {
                Text("低数据")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.yellow)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.yellow.opacity(0.14), in: Capsule())
            }
            Spacer()
            Text("鉴权 \(diagnostics.authorizedRequests) / 拒绝 \(diagnostics.unauthorizedRequests)")
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.secondary)
        }
        .bentoCard(padding: 10)
        .accessibilityElement(children: .combine)
    }
}
#endif
