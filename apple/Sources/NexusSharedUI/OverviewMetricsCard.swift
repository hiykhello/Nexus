#if canImport(SwiftUI)
import SwiftUI
import NexusCoreBridge

/// Cross-platform telemetry summary section shared between macOS Dashboard and iOS/iPadOS views.
public struct OverviewMetricsSection: View {
    public let metrics: MetricsSnapshot
    public let diagnostics: DiagnosticsSnapshot
    public let network: AppleNetworkSnapshot
    public let residentMemoryMiB: Double?
    public let memoryBudgetMiB: Int

    public init(
        metrics: MetricsSnapshot,
        diagnostics: DiagnosticsSnapshot,
        network: AppleNetworkSnapshot,
        residentMemoryMiB: Double? = nil,
        memoryBudgetMiB: Int = 50
    ) {
        self.metrics = metrics
        self.diagnostics = diagnostics
        self.network = network
        self.residentMemoryMiB = residentMemoryMiB
        self.memoryBudgetMiB = memoryBudgetMiB
    }

    public var body: some View {
        Group {
            Section("实时遥测 (/metrics & /v1/diagnostics)") {
                LabeledContent("控制代次", value: "\(metrics.controlGeneration)")
                LabeledContent("活跃会话", value: "\(metrics.activeSessions)")
                LabeledContent("上行 / 下行", value: "\(metrics.uploadBytes / 1024) KiB / \(metrics.downloadBytes / 1024) KiB")
                LabeledContent("授权 / 拒绝请求", value: "\(diagnostics.authorizedRequests) / \(diagnostics.unauthorizedRequests)")
                if let mem = residentMemoryMiB {
                    LabeledContent("扩展内存水位") {
                        Text(String(format: "%.1f / %d MiB%@", mem, memoryBudgetMiB, mem < Double(memoryBudgetMiB) ? " (< 50 MiB OK)" : " (超限预警)"))
                            .foregroundStyle(mem < Double(memoryBudgetMiB) ? Color.green : Color.red)
                    }
                }
            }
            Section("底层物理网络 (NWPathMonitor)") {
                LabeledContent("主网口", value: network.interfaceName ?? "无")
                LabeledContent("计费网络", value: network.isExpensive ? "是" : "否")
                LabeledContent("低数据模式", value: network.isConstrained ? "是" : "否")
            }
        }
    }
}
#endif
