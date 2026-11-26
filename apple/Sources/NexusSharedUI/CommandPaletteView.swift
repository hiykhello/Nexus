#if canImport(SwiftUI)
import Foundation
import SwiftUI
import NexusCoreBridge

/// Typed quick action exposed inside `CommandPaletteView`.
public struct CommandPaletteAction: Identifiable, Equatable, Sendable {
    public let id: String
    public let title: String
    public let subtitle: String
    public let systemImage: String
    public let shortcutHint: String

    public init(id: String, title: String, subtitle: String, systemImage: String, shortcutHint: String = "") {
        self.id = id
        self.title = title
        self.subtitle = subtitle
        self.systemImage = systemImage
        self.shortcutHint = shortcutHint
    }
}

/// Signature Move #2: Global `⌘K` Command & Inline Domain Diagnostic Palette (`gui-flagship-spec.md` §3).
/// 0ms instant open/filter, fuzzy node switch, `>` quick commands, and cancellation-safe inline
/// `DomainRouteExplainer` + live DNS probe.
public struct CommandPaletteView: View {
    public let initialQuery: String
    public let isRunning: Bool
    public let outboundMode: String
    public let groups: [OutboundGroupSnapshot]
    public let rules: [RuleMetric]
    public let quickActions: [CommandPaletteAction]
    public let onSelectNode: (String, String) -> Void
    public let onRunAction: (String) -> Void
    public let onQueryDns: @MainActor (String) async -> Result<DnsQueryResponse, Error>
    public let onFlushFakeIp: () -> Void
    public let onDismiss: () -> Void

    @State private var query: String
    @State private var highlightedIndex: Int = 0
    @State private var liveDnsResult: DnsQueryResponse?
    @State private var liveDnsError: String?
    @State private var isQueryingDns: Bool = false
    @State private var manualDnsTrigger: Int = 0
    @State private var lastManualDnsDomain: String?
    @FocusState private var isQueryFocused: Bool
    @Environment(\.nexusTheme) private var theme

    private enum PaletteEntry: Identifiable, Equatable {
        case node(group: String, member: OutboundMemberSnapshot, isActive: Bool, canSelect: Bool)
        case action(CommandPaletteAction)

        var id: String {
            switch self {
            case .node(let group, let member, _, _): return "node:\(group):\(member.name)"
            case .action(let action): return "action:\(action.id)"
            }
        }
    }

    public init(
        initialQuery: String = "",
        isRunning: Bool,
        outboundMode: String,
        groups: [OutboundGroupSnapshot],
        rules: [RuleMetric],
        quickActions: [CommandPaletteAction],
        onSelectNode: @escaping (String, String) -> Void,
        onRunAction: @escaping (String) -> Void,
        onQueryDns: @escaping @MainActor (String) async -> Result<DnsQueryResponse, Error>,
        onFlushFakeIp: @escaping () -> Void,
        onDismiss: @escaping () -> Void
    ) {
        self.initialQuery = initialQuery
        self.isRunning = isRunning
        self.outboundMode = outboundMode
        self.groups = groups
        self.rules = rules
        self.quickActions = quickActions
        self.onSelectNode = onSelectNode
        self.onRunAction = onRunAction
        self.onQueryDns = onQueryDns
        self.onFlushFakeIp = onFlushFakeIp
        self.onDismiss = onDismiss
        self._query = State(initialValue: initialQuery)
    }

    private var trimmedQuery: String {
        query.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var isCommandOnlyMode: Bool {
        trimmedQuery.hasPrefix(">")
    }

    private var normalizedDomain: String? {
        guard DomainRouteExplainer.looksLikeDomainQuery(trimmedQuery) else { return nil }
        return DomainRouteExplainer.normalizeHost(trimmedQuery)
    }

    private var domainExplanation: DomainRouteExplanation? {
        guard let host = normalizedDomain else { return nil }
        return DomainRouteExplainer.explain(
            domain: host,
            outboundMode: outboundMode,
            rules: rules,
            groups: groups
        )
    }

    private var filteredEntries: [PaletteEntry] {
        let q = isCommandOnlyMode
            ? String(trimmedQuery.dropFirst()).trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            : trimmedQuery.lowercased()

        var entries: [PaletteEntry] = []

        if !isCommandOnlyMode {
            for group in groups {
                for member in group.members {
                    if q.isEmpty
                        || member.name.lowercased().contains(q)
                        || group.tag.lowercased().contains(q) {
                        entries.append(.node(
                            group: group.tag,
                            member: member,
                            isActive: member.name == group.active,
                            canSelect: group.supportsManualSelection
                        ))
                    }
                    if q.isEmpty && entries.count >= 6 { break }
                }
                if q.isEmpty && entries.count >= 6 { break }
            }
        }

        for action in quickActions {
            if q.isEmpty
                || action.title.lowercased().contains(q)
                || action.subtitle.lowercased().contains(q)
                || action.id.lowercased().contains(q) {
                entries.append(.action(action))
            }
        }
        return entries
    }

    public var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 10) {
                searchHeader
                if let explanation = domainExplanation {
                    domainDiagnosticCard(explanation)
                }
                resultsList
            }
            .padding()
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(theme.canvasBackground)
            .navigationTitle("命令与域名诊断")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭", action: onDismiss)
                        .keyboardShortcut(.cancelAction)
                }
            }
            .onAppear {
                isQueryFocused = true
            }
            .onChange(of: trimmedQuery) { _, _ in
                highlightedIndex = 0
                if normalizedDomain == nil {
                    liveDnsResult = nil
                    liveDnsError = nil
                    isQueryingDns = false
                }
            }
            .task(id: "\(normalizedDomain ?? "")#\(manualDnsTrigger)") {
                guard let host = normalizedDomain else { return }
                liveDnsResult = nil
                liveDnsError = nil
                guard isRunning else { return }
                let isManualForHost = manualDnsTrigger > 0 && lastManualDnsDomain == host
                if !isManualForHost {
                    try? await Task.sleep(for: .milliseconds(200))
                    guard !Task.isCancelled else { return }
                }
                isQueryingDns = true
                defer { isQueryingDns = false }
                let result = await onQueryDns(host)
                guard !Task.isCancelled else { return }
                switch result {
                case .success(let resp):
                    liveDnsResult = resp
                    liveDnsError = nil
                case .failure(let err):
                    liveDnsResult = nil
                    liveDnsError = NexusDisplayCopy.friendlyErrorMessage(err)
                }
            }
            .onKeyPress(.upArrow) {
                moveHighlight(by: -1)
                return .handled
            }
            .onKeyPress(.downArrow) {
                moveHighlight(by: 1)
                return .handled
            }
            .onKeyPress(.escape) {
                onDismiss()
                return .handled
            }
        }
        #if os(macOS)
        .frame(minWidth: 540, idealWidth: 600, minHeight: 420, idealHeight: 480)
        #endif
    }

    private var searchHeader: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            TextField("搜索节点、输入域名诊断，或输入 > 执行快捷命令…", text: $query)
                .textFieldStyle(.plain)
                .focused($isQueryFocused)
                .onSubmit { executePrimaryAction() }
                .accessibilityLabel("命令与域名诊断输入框")
            if !query.isEmpty {
                Button {
                    query = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("清空输入")
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(theme.wellSurface, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(theme.hairlineBorder, lineWidth: 1)
        )
    }

    private func domainDiagnosticCard(_ exp: DomainRouteExplanation) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "point.topleft.down.curvedto.point.bottomright.up")
                    .foregroundStyle(theme.accentText)
                    .accessibilityHidden(true)
                Text(exp.domain)
                    .font(.subheadline.weight(.semibold).monospaced())
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(exp.estimateNote)
                    .font(.caption2.weight(.medium))
                    .foregroundStyle(.secondary)
                Spacer(minLength: 4)
                DeferredSpinnerView(isActive: isQueryingDns)
                Button("实时 DNS 探测") {
                    triggerManualDnsProbe()
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .disabled(!isRunning || isQueryingDns)
            }

            HStack(spacing: 6) {
                let ruleLabel = exp.matchedRuleIndex.map { "规则 #\($0) · \(exp.matchedRuleSummary)" } ?? exp.matchedRuleSummary
                Text(ruleLabel)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Image(systemName: "arrow.right")
                    .font(.caption2)
                    .foregroundStyle(theme.signalEmerald)
                    .accessibilityHidden(true)
                let targetSummary = exp.targetTag.caseInsensitiveCompare(exp.resolvedOutbound) == .orderedSame
                    ? exp.resolvedOutbound
                    : "\(exp.targetTag) → \(exp.resolvedOutbound)"
                Text(targetSummary)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(theme.signalEmerald)
                    .lineLimit(1)
                    .truncationMode(.middle)
                if let rtt = exp.activeLatencyMs {
                    Text("\(rtt) ms")
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
            }

            if !isRunning {
                Text("内核未运行 · 仅显示本地规则预估")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            } else if let err = liveDnsError, !err.isEmpty {
                Text("DNS 探测失败：\(err)")
                    .font(.caption2)
                    .foregroundStyle(theme.danger)
            } else if let resp = liveDnsResult {
                Divider()
                HStack(spacing: 8) {
                    Text(resp.rcodeName.isEmpty ? "RCODE \(resp.rcode)" : resp.rcodeName)
                        .font(.caption2.weight(.semibold).monospacedDigit())
                        .foregroundStyle(resp.rcode == 0 ? theme.signalEmerald : theme.warning)
                    let ansText = resp.answers.prefix(2).map(\.data).joined(separator: ", ")
                    Text(ansText.isEmpty ? "无应答记录" : ansText)
                        .font(.caption.monospaced())
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                    Spacer(minLength: 4)
                    Text("TTL \(resp.ttl)s · \(resp.elapsedMs) ms")
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(.secondary)
                    Button("刷新 FakeIP") {
                        onFlushFakeIp()
                    }
                    .buttonStyle(.borderless)
                    .font(.caption2.weight(.medium))
                }
            }
        }
        .bentoCard(padding: 10, cornerRadius: 12)
    }

    private struct IndexedPaletteEntry: Identifiable {
        let index: Int
        let entry: PaletteEntry
        var id: String { entry.id }
    }

    @ViewBuilder
    private var resultsList: some View {
        let entries = filteredEntries
        if entries.isEmpty && domainExplanation == nil {
            ContentUnavailableView {
                Label("未找到“\(trimmedQuery)”", systemImage: "magnifyingglass")
            } description: {
                Text("尝试搜索其他节点、输入域名诊断，或输入 > 查看快捷命令。")
            } actions: {
                Button("重置筛选") { query = "" }
                    .buttonStyle(.bordered)
            }
        } else {
            let rows = entries.enumerated().map { IndexedPaletteEntry(index: $0.offset, entry: $0.element) }
            ScrollViewReader { proxy in
                List(rows) { row in
                    let isHighlighted = row.index == highlightedIndex
                    Button {
                        triggerEntry(row.entry)
                    } label: {
                        entryRow(row.entry, isHighlighted: isHighlighted)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .id(row.id)
                    .listRowBackground(
                        isHighlighted
                            ? theme.accentFill.opacity(0.14)
                            : Color.clear
                    )
                }
                .scrollContentBackground(.hidden)
                .onChange(of: highlightedIndex) { _, nextIdx in
                    guard nextIdx >= 0, nextIdx < rows.count else { return }
                    proxy.scrollTo(rows[nextIdx].id)
                }
            }
        }
    }

    @ViewBuilder
    private func entryRow(_ entry: PaletteEntry, isHighlighted: Bool) -> some View {
        switch entry {
        case .node(let group, let member, let isActive, let canSelect):
            HStack(spacing: 8) {
                Image(systemName: isActive ? "checkmark.circle.fill" : "arrow.triangle.branch")
                    .foregroundStyle(isActive ? theme.signalEmerald : .secondary)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(member.name)
                        .font(.subheadline.weight(.semibold))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(canSelect ? "策略组 \(group) · 点击切换" : "策略组 \(group) · 自动调度")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 4)
                RttPillView(latencyMs: GroupLatencySummary.effectiveLatency(member), state: member.state)
            }
            .padding(.vertical, 2)
        case .action(let action):
            HStack(spacing: 8) {
                Image(systemName: action.systemImage)
                    .foregroundStyle(isHighlighted ? theme.accentText : .secondary)
                    .frame(width: 18)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(action.title)
                        .font(.subheadline.weight(.medium))
                    Text(action.subtitle)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 4)
                if !action.shortcutHint.isEmpty {
                    Text(action.shortcutHint)
                        .font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.vertical, 2)
        }
    }

    private func moveHighlight(by delta: Int) {
        let count = filteredEntries.count
        guard count > 0 else { return }
        highlightedIndex = (highlightedIndex + delta + count) % count
    }

    private func triggerManualDnsProbe() {
        guard let host = normalizedDomain else { return }
        lastManualDnsDomain = host
        manualDnsTrigger &+= 1
    }

    private func executePrimaryAction() {
        if normalizedDomain != nil && filteredEntries.isEmpty {
            triggerManualDnsProbe()
            return
        }
        let entries = filteredEntries
        guard !entries.isEmpty else { return }
        let idx = min(max(0, highlightedIndex), entries.count - 1)
        triggerEntry(entries[idx])
    }

    private func triggerEntry(_ entry: PaletteEntry) {
        switch entry {
        case .node(let group, let member, _, let canSelect):
            if canSelect { onSelectNode(group, member.name) }
            onDismiss()
        case .action(let action):
            onRunAction(action.id)
            onDismiss()
        }
    }
}
#endif
