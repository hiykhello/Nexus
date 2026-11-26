#if canImport(SwiftUI)
import Foundation
import SwiftUI
import NexusCoreBridge

/// Formats ring-buffer log entries as plain-text snapshot lines for clipboard or file export.
public func formatLogsSnapshot(_ entries: [LogRingEntry]) -> String {
    entries.map { "#\($0.seq) [\($0.level)] (\($0.domain)) \($0.message)" }.joined(separator: "\n")
}

/// Cross-platform (macOS + iOS/iPadOS) live streaming & ring-buffer log viewer with
/// tactile level pills, stable non-flipping search toolbar, explicit auto-follow toggle, copy, and export.
public struct LogsPane: View {
    public let logs: [LogRingEntry]
    @Binding public var logLevel: String
    @Binding public var logDomainFilter: String
    @Binding public var logSearch: String
    public let isStreaming: Bool
    public let isPaused: Bool
    public let focusSearchTrigger: Int
    public let shouldAutoFocusSearch: Bool
    public let onConsumeSearchFocus: () -> Void
    public let onApplyLevel: (String) -> Void
    public let onRefresh: () -> Void
    public let onClear: () -> Void
    public let onTogglePause: (() -> Void)?
    public let onExport: ((String) -> Void)?

    @State private var selectedLevelFilter: String = "all"
    @State private var copiedFeedback: Bool = false
    @State private var autoFollow: Bool = true
    @State private var jumpToBottomTrigger: Int = 0
    @FocusState private var isSearchFocused: Bool
    @Environment(\.nexusTheme) private var theme
    @ScaledMetric(relativeTo: .body) private var pickerWidth: CGFloat = 104
    #if os(iOS)
    @Environment(\.horizontalSizeClass) private var sizeClass
    #endif

    private let levelFilters = ["all", "error", "warn", "info", "debug", "trace"]
    private let domains = ["all", "core", "proxy", "route", "dns", "tun", "net", "tls", "quic", "state", "control"]

    public init(
        logs: [LogRingEntry],
        logLevel: Binding<String>,
        logDomainFilter: Binding<String>,
        logSearch: Binding<String>,
        isStreaming: Bool = false,
        isPaused: Bool = false,
        focusSearchTrigger: Int = 0,
        shouldAutoFocusSearch: Bool = false,
        onConsumeSearchFocus: @escaping () -> Void = {},
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
        self.focusSearchTrigger = focusSearchTrigger
        self.shouldAutoFocusSearch = shouldAutoFocusSearch
        self.onConsumeSearchFocus = onConsumeSearchFocus
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

    private var hasActiveFilters: Bool {
        selectedLevelFilter != "all"
            || (logDomainFilter != "all" && !logDomainFilter.isEmpty)
            || !logSearch.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private var isCompactLayout: Bool {
        #if os(iOS)
        return sizeClass == .compact
        #else
        return false
        #endif
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            toolbarRow
            levelPillsRow
            logListContent
        }
        .padding()
        .task { onRefresh() }
        .task(id: copiedFeedback) {
            guard copiedFeedback else { return }
            try? await Task.sleep(for: .milliseconds(1500))
            guard !Task.isCancelled else { return }
            copiedFeedback = false
        }
        .onAppear {
            consumePendingSearchFocusIfNeeded()
        }
        .onChange(of: focusSearchTrigger) { _, _ in
            consumePendingSearchFocusIfNeeded()
        }
    }

    private func consumePendingSearchFocusIfNeeded() {
        if shouldAutoFocusSearch {
            isSearchFocused = true
            onConsumeSearchFocus()
        }
    }

    @ViewBuilder
    private var logListContent: some View {
        if logs.isEmpty {
            ContentUnavailableView {
                Label("暂无日志", systemImage: "text.alignleft")
            } description: {
                Text("连接内核后将实时流式输出运行日志。")
            } actions: {
                Button("刷新日志", action: onRefresh)
                    .buttonStyle(NexusProminentButtonStyle())
            }
        } else if visibleLogs.isEmpty {
            let trimmed = logSearch.trimmingCharacters(in: .whitespacesAndNewlines)
            ContentUnavailableView {
                Label(
                    trimmed.isEmpty ? "当前筛选无日志" : "未找到“\(trimmed)”",
                    systemImage: trimmed.isEmpty ? "line.3.horizontal.decrease.circle" : "magnifyingglass"
                )
            } description: {
                Text(trimmed.isEmpty ? "调整日志级别或模块过滤条件以查看更多记录。" : "请尝试其他关键词或重置筛选条件。")
            } actions: {
                if hasActiveFilters {
                    Button("重置筛选") {
                        logSearch = ""
                        selectedLevelFilter = "all"
                        logDomainFilter = "all"
                    }
                    .buttonStyle(.bordered)
                }
            }
        } else {
            ScrollViewReader { proxy in
                List(visibleLogs) { entry in
                    LogRowView(entry: entry)
                        .contextMenu {
                            Button("复制此条日志") {
                                NexusByteFormat.copyToClipboard(formatLogsSnapshot([entry]))
                            }
                        }
                }
                .scrollContentBackground(.hidden)
                .onAppear {
                    if autoFollow, let lastID = visibleLogs.last?.id {
                        proxy.scrollTo(lastID, anchor: .bottom)
                    }
                }
                .onChange(of: visibleLogs.last?.id) { _, lastID in
                    if autoFollow && !isPaused, let lastID {
                        proxy.scrollTo(lastID, anchor: .bottom)
                    }
                }
                .onChange(of: jumpToBottomTrigger) { _, _ in
                    if let lastID = visibleLogs.last?.id {
                        proxy.scrollTo(lastID, anchor: .bottom)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var toolbarRow: some View {
        if isCompactLayout {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 8) {
                    searchField
                    overflowMenu
                }
                HStack(spacing: 8) {
                    domainPicker
                    coreLevelPicker
                    Spacer(minLength: 4)
                    pauseButton
                }
            }
        } else {
            HStack(spacing: 8) {
                searchField
                domainPicker
                    .frame(minWidth: pickerWidth, maxWidth: pickerWidth + 24)
                coreLevelPicker
                    .frame(minWidth: pickerWidth, maxWidth: pickerWidth + 24)
                pauseButton
                refreshButton
                copyButton
                exportButton
                clearButton
            }
        }
    }

    private var searchField: some View {
        TextField("搜索日志关键字…", text: $logSearch)
            .textFieldStyle(.roundedBorder)
            .focused($isSearchFocused)
            .onSubmit(onRefresh)
            .accessibilityLabel("搜索日志")
    }

    private var domainPicker: some View {
        Picker("模块", selection: $logDomainFilter) {
            ForEach(domains, id: \.self) { dom in
                Text(dom).tag(dom)
            }
        }
    }

    private var coreLevelPicker: some View {
        Picker("级别", selection: Binding(
            get: { logLevel },
            set: { level in onApplyLevel(level) }
        )) {
            ForEach(["error", "warn", "info", "debug", "trace"], id: \.self) { level in
                Text(level).tag(level)
            }
        }
        .accessibilityLabel("动态设置内核日志级别")
    }

    @ViewBuilder
    private var pauseButton: some View {
        if let onTogglePause {
            Button(action: onTogglePause) {
                Label(isPaused ? "继续" : "暂停", systemImage: isPaused ? "play.fill" : "pause.fill")
            }
            .buttonStyle(.bordered)
            .accessibilityHint(isPaused ? "恢复实时日志流" : "暂停实时日志滚动")
            #if os(iOS)
            .frame(minHeight: 44)
            #endif
        }
    }

    private var refreshButton: some View {
        Button(action: onRefresh) {
            Label("刷新", systemImage: "arrow.clockwise")
        }
    }

    private var copyButton: some View {
        Button {
            NexusByteFormat.copyToClipboard(formatLogsSnapshot(visibleLogs))
            copiedFeedback = true
        } label: {
            Label(copiedFeedback ? "已复制" : "复制", systemImage: "doc.on.doc")
        }
        .disabled(visibleLogs.isEmpty)
    }

    @ViewBuilder
    private var exportButton: some View {
        if let onExport {
            Button("导出") { onExport(formatLogsSnapshot(visibleLogs)) }
                .disabled(visibleLogs.isEmpty)
        }
    }

    private var clearButton: some View {
        Button("清空", role: .destructive, action: onClear)
            .disabled(logs.isEmpty)
    }

    private var overflowMenu: some View {
        Menu {
            Button(action: onRefresh) {
                Label("刷新", systemImage: "arrow.clockwise")
            }
            Button {
                NexusByteFormat.copyToClipboard(formatLogsSnapshot(visibleLogs))
                copiedFeedback = true
            } label: {
                Label(copiedFeedback ? "已复制" : "复制日志", systemImage: "doc.on.doc")
            }
            .disabled(visibleLogs.isEmpty)
            if let onExport {
                Button("导出日志") { onExport(formatLogsSnapshot(visibleLogs)) }
                    .disabled(visibleLogs.isEmpty)
            }
            Divider()
            Button("清空日志", role: .destructive, action: onClear)
                .disabled(logs.isEmpty)
        } label: {
            Image(systemName: "ellipsis.circle")
                .font(.title3)
        }
        .accessibilityLabel("更多日志操作")
        #if os(iOS)
        .frame(minWidth: 44, minHeight: 44)
        #endif
    }

    private var levelPillsRow: some View {
        HStack(spacing: 8) {
            StatusBadgeView(isOnline: isStreaming && !isPaused, label: isPaused ? "已暂停" : (isStreaming ? "实时流" : "轮询"))
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 6) {
                    ForEach(levelFilters, id: \.self) { level in
                        let active = selectedLevelFilter == level
                        let pillTint = level == "all" ? theme.accentText : theme.logLevelColor(level)
                        Button {
                            selectedLevelFilter = level
                        } label: {
                            Text(level.uppercased())
                                .font(.caption2.weight(.semibold))
                                .padding(.horizontal, 9)
                                .padding(.vertical, 4)
                                .background(
                                    active ? pillTint.opacity(0.18) : theme.wellSurface,
                                    in: Capsule()
                                )
                                .foregroundStyle(active ? pillTint : .secondary)
                        }
                        .buttonStyle(NexusPillButtonStyle())
                        .accessibilityAddTraits(active ? .isSelected : [])
                    }
                    Button {
                        autoFollow.toggle()
                        if autoFollow { jumpToBottomTrigger &+= 1 }
                    } label: {
                        Label("自动跟随", systemImage: autoFollow ? "arrow.down.circle.fill" : "arrow.down.circle")
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 9)
                            .padding(.vertical, 4)
                            .background(
                                autoFollow ? theme.accentFill.opacity(0.16) : theme.wellSurface,
                                in: Capsule()
                            )
                            .foregroundStyle(autoFollow ? theme.accentText : .secondary)
                    }
                    .buttonStyle(NexusPillButtonStyle())
                    .accessibilityAddTraits(autoFollow ? .isSelected : [])
                    if !visibleLogs.isEmpty {
                        Button {
                            jumpToBottomTrigger &+= 1
                        } label: {
                            Label("到底部", systemImage: "arrow.down.to.line")
                                .font(.caption2.weight(.medium))
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .background(theme.wellSurface, in: Capsule())
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(NexusPillButtonStyle())
                        .accessibilityLabel("滚动到最新日志")
                    }
                }
            }
            Text("\(visibleLogs.count) 条")
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.secondary)
        }
    }
}

private struct LogRowView: View {
    let entry: LogRingEntry
    @Environment(\.nexusTheme) private var theme
    @ScaledMetric(relativeTo: .caption2) private var seqWidth: CGFloat = 44
    @ScaledMetric(relativeTo: .caption2) private var levelWidth: CGFloat = 48
    @ScaledMetric(relativeTo: .caption) private var domainWidth: CGFloat = 56

    private var railColor: Color {
        switch entry.level.lowercased() {
        case "error", "fatal": return theme.danger
        case "warn", "warning": return theme.warning
        case "info": return theme.rxLine
        case "debug": return theme.txLine
        default: return .clear
        }
    }

    var body: some View {
        let tint = theme.logLevelColor(entry.level)
        HStack(alignment: .top, spacing: 8) {
            Text("#\(entry.seq)")
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.tertiary)
                .frame(minWidth: seqWidth, alignment: .trailing)
            Text(entry.level.uppercased())
                .font(.caption2.weight(.semibold).monospaced())
                .foregroundStyle(tint)
                .frame(minWidth: levelWidth, alignment: .leading)
            Text(entry.domain)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .frame(minWidth: domainWidth, alignment: .leading)
            Text(entry.message)
                .font(.caption.monospaced())
                .textSelection(.enabled)
        }
        .padding(.leading, 8)
        .overlay(alignment: .leading) {
            if railColor != .clear {
                RoundedRectangle(cornerRadius: 1)
                    .fill(railColor)
                    .frame(width: 2)
                    .accessibilityHidden(true)
            }
        }
    }
}
#endif
