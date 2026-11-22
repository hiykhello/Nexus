#if canImport(SwiftUI)
import SwiftUI
import NexusCoreBridge

/// Formats ring-buffer log entries as plain-text snapshot lines for clipboard or file export.
public func formatLogsSnapshot(_ entries: [LogRingEntry]) -> String {
    entries.map { "#\($0.seq) [\($0.level)] (\($0.domain)) \($0.message)" }.joined(separator: "\n")
}

/// Cross-platform (macOS + iOS/iPadOS) ring-buffer log viewer with search, domain, level & export.
public struct LogsPane: View {
    public let logs: [LogRingEntry]
    @Binding public var logLevel: String
    @Binding public var logDomainFilter: String
    @Binding public var logSearch: String
    public let onApplyLevel: (String) -> Void
    public let onRefresh: () -> Void
    public let onClear: () -> Void
    public let onExport: ((String) -> Void)?

    public init(
        logs: [LogRingEntry],
        logLevel: Binding<String>,
        logDomainFilter: Binding<String>,
        logSearch: Binding<String>,
        onApplyLevel: @escaping (String) -> Void,
        onRefresh: @escaping () -> Void,
        onClear: @escaping () -> Void,
        onExport: ((String) -> Void)? = nil
    ) {
        self.logs = logs
        self._logLevel = logLevel
        self._logDomainFilter = logDomainFilter
        self._logSearch = logSearch
        self.onApplyLevel = onApplyLevel
        self.onRefresh = onRefresh
        self.onClear = onClear
        self.onExport = onExport
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                TextField("搜索日志关键字...", text: $logSearch)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(onRefresh)
                Picker("域", selection: $logDomainFilter) {
                    ForEach(["all", "core", "proxy", "route", "dns", "tun", "quic", "control"], id: \.self) { dom in
                        Text(dom).tag(dom)
                    }
                }
                .frame(width: 110)
                Picker("级别", selection: Binding(
                    get: { logLevel },
                    set: { level in onApplyLevel(level) }
                )) {
                    ForEach(["error", "warn", "info", "debug", "trace"], id: \.self) { level in
                        Text(level).tag(level)
                    }
                }
                .frame(width: 100)
                Button("刷新", action: onRefresh)
                if let onExport {
                    Button("导出") { onExport(formatLogsSnapshot(logs)) }
                        .disabled(logs.isEmpty)
                }
                Button("清空", action: onClear)
            }
            if logs.isEmpty {
                ContentUnavailableView(
                    "暂无日志",
                    systemImage: "text.alignleft",
                    description: Text("点击刷新从核心内存日志环 (/v1/logs) 拉取历史与实时日志。")
                )
            } else {
                List(logs) { entry in
                    HStack(alignment: .top, spacing: 8) {
                        Text("[\(entry.level)]")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .frame(width: 56, alignment: .leading)
                        Text(entry.domain)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .frame(width: 64, alignment: .leading)
                        Text(entry.message)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                    }
                }
            }
        }
        .padding()
        .task { onRefresh() }
    }
}
#endif
