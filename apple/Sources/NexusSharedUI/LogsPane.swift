#if canImport(SwiftUI)
import SwiftUI
import NexusCoreBridge

/// Formats ring-buffer log entries as plain-text snapshot lines for clipboard or file export.
public func formatLogsSnapshot(_ entries: [LogRingEntry]) -> String {
    entries.map { "#\($0.seq) [\($0.level)] (\($0.domain)) \($0.message)" }.joined(separator: "\n")
}

/// Cross-platform (macOS + iOS/iPadOS) live SSE + ring-buffer log viewer with level pills,
/// Core `setLogLevel` picker, search, pause/resume, copy, and export.
public struct LogsPane: View {
    public let logs: [LogRingEntry]
    @Binding public var logLevel: String
    @Binding public var logDomainFilter: String
    @Binding public var logSearch: String
    public let isStreaming: Bool
    public let isPaused: Bool
    public let onApplyLevel: (String) -> Void
    public let onRefresh: () -> Void
    public let onClear: () -> Void
    public let onTogglePause: (() -> Void)?
    public let onExport: ((String) -> Void)?

    @State private var selectedLevelFilter: String = "all"
    @State private var copiedFeedback: Bool = false

    private let levelFilters = ["all", "error", "warn", "info", "debug", "trace"]
    private let domains = ["all", "core", "proxy", "route", "dns", "tun", "net", "tls", "quic", "state", "control"]

    public init(
        logs: [LogRingEntry],
        logLevel: Binding<String>,
        logDomainFilter: Binding<String>,
        logSearch: Binding<String>,
        isStreaming: Bool = false,
        isPaused: Bool = false,
        onApplyLevel: @escaping (String) -> Void,
        onRefresh: @escaping () -> Void,
        onClear: @escaping () -> Void,
        onTogglePause: (() -> Void)? = nil,
        onExport: ((String) -> Void)? = nil
    ) {
        self.logs = logs
        self._logLevel = logLevel
        self._logDomainFilter = logDomainFilter
        self._logSearch = logSearch
        self.isStreaming = isStreaming
        self.isPaused = isPaused
        self.onApplyLevel = onApplyLevel
        self.onRefresh = onRefresh
        self.onClear = onClear
        self.onTogglePause = onTogglePause
        self.onExport = onExport
    }

    private var visibleLogs: [LogRingEntry] {
        let q = logSearch.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return logs.filter { entry in
            if selectedLevelFilter != "all" && entry.level.lowercased() != selectedLevelFilter {
                return false
            }
            if logDomainFilter != "all" && !logDomainFilter.isEmpty && entry.domain.lowercased() != logDomainFilter.lowercased() {
                return false
            }
            guard !q.isEmpty else { return true }
            return entry.message.lowercased().contains(q) || entry.domain.lowercased().contains(q)
        }
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            toolbarRow
            levelPillsRow
            if visibleLogs.isEmpty {
                ContentUnavailableView(
                    "暂无日志",
                    systemImage: "text.alignleft",
                    description: Text("连接核心后将通过 SSE /v1/logs?stream=1 实时流式输出日志。")
                )
            } else {
                List(visibleLogs) { entry in
                    LogRowView(entry: entry)
                }
            }
        }
        .padding()
        .task { onRefresh() }
        .task(id: copiedFeedback) {
            guard copiedFeedback else { return }
            try? await Task.sleep(for: .milliseconds(1500))
            if !Task.isCancelled { copiedFeedback = false }
        }
    }

    private var toolbarRow: some View {
        HStack(spacing: 8) {
            TextField("搜索日志关键字...", text: $logSearch)
                .textFieldStyle(.roundedBorder)
                .onSubmit(onRefresh)
                .accessibilityLabel("搜索日志")
            Picker("域", selection: $logDomainFilter) {
                ForEach(domains, id: \.self) { dom in
                    Text(dom).tag(dom)
                }
            }
            .frame(width: 105)
            Picker("核心级别", selection: Binding(
                get: { logLevel },
                set: { level in onApplyLevel(level) }
            )) {
                ForEach(["error", "warn", "info", "debug", "trace"], id: \.self) { level in
                    Text(level).tag(level)
                }
            }
            .frame(width: 100)
            .accessibilityLabel("动态设置核心日志级别")

            if let onTogglePause {
                Button(action: onTogglePause) {
                    Label(isPaused ? "继续" : "暂停", systemImage: isPaused ? "play.fill" : "pause.fill")
                }
                .buttonStyle(.bordered)
                .accessibilityHint(isPaused ? "恢复实时日志流" : "暂停实时日志滚动")
            }

            Button(action: onRefresh) {
                Label("刷新", systemImage: "arrow.clockwise")
            }

            Button {
                NexusByteFormat.copyToClipboard(formatLogsSnapshot(visibleLogs))
                copiedFeedback = true
            } label: {
                Label(copiedFeedback ? "已复制" : "复制", systemImage: "doc.on.doc")
            }
            .disabled(visibleLogs.isEmpty)

            if let onExport {
                Button("导出") { onExport(formatLogsSnapshot(visibleLogs)) }
                    .disabled(visibleLogs.isEmpty)
            }
            Button("清空", role: .destructive, action: onClear)
                .disabled(logs.isEmpty)
        }
    }

    private var levelPillsRow: some View {
        HStack(spacing: 6) {
            StatusBadgeView(isOnline: isStreaming && !isPaused, label: isPaused ? "已暂停" : (isStreaming ? "SSE 实时" : "轮询"))
            ForEach(levelFilters, id: \.self) { level in
                let active = selectedLevelFilter == level
                Button {
                    selectedLevelFilter = level
                } label: {
                    Text(level.uppercased())
                        .font(.caption2.weight(.semibold))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(
                            active ? NexusPalette.logLevelColor(level).opacity(0.18) : NexusPalette.subtleSurface,
                            in: Capsule()
                        )
                        .foregroundStyle(active ? NexusPalette.logLevelColor(level) : .secondary)
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(active ? .isSelected : [])
            }
            Spacer()
            Text("\(visibleLogs.count) 条")
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.secondary)
        }
    }
}

private struct LogRowView: View {
    let entry: LogRingEntry

    var body: some View {
        let tint = NexusPalette.logLevelColor(entry.level)
        HStack(alignment: .top, spacing: 8) {
            Text("#\(entry.seq)")
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.tertiary)
                .frame(width: 44, alignment: .trailing)
            Text(entry.level.uppercased())
                .font(.caption2.weight(.semibold).monospaced())
                .foregroundStyle(tint)
                .frame(width: 48, alignment: .leading)
            Text(entry.domain)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .frame(width: 60, alignment: .leading)
            Text(entry.message)
                .font(.caption.monospaced())
                .textSelection(.enabled)
        }
    }
}
#endif
