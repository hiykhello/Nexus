#if canImport(SwiftUI)
import Foundation
import SwiftUI
import NexusCoreBridge

/// Live searchable Rules + interactive Live DNS Query + FakeIP/DNS cache controls shared across macOS and iOS.
public struct RulesDnsView: View {
    public let rules: [RuleMetric]
    public let outboundMode: String
    public let groups: [OutboundGroupSnapshot]
    public let dnsResponse: DnsQueryResponse?
    public let dnsError: String?
    public let isQueryingDns: Bool
    public let cacheActionMessage: String?
    public let focusSearchTrigger: Int
    public let shouldAutoFocusSearch: Bool
    public let onConsumeSearchFocus: () -> Void
    public let onRefreshRules: () -> Void
    public let onQueryDns: (String, String, String?) -> Void
    public let onFlushFakeIp: () -> Void
    public let onClearDnsCache: () -> Void
    public let onClearAllCache: () -> Void

    @State private var ruleSearch: String = ""
    @State private var domainInput: String = "example.com"
    @State private var recordType: String = "A"
    @State private var serverInput: String = ""
    @State private var showClearAllConfirm: Bool = false
    @FocusState private var isRuleSearchFocused: Bool
    @Environment(\.nexusTheme) private var theme
    @ScaledMetric(relativeTo: .body) private var recordPickerWidth: CGFloat = 92
    @ScaledMetric(relativeTo: .body) private var serverFieldWidth: CGFloat = 170
    #if os(iOS)
    @Environment(\.horizontalSizeClass) private var sizeClass
    #endif

    private let recordTypes = ["A", "AAAA", "CNAME", "HTTPS", "SVCB", "TXT", "MX", "NS", "SRV"]

    public init(
        rules: [RuleMetric],
        outboundMode: String = "rule",
        groups: [OutboundGroupSnapshot] = [],
        dnsResponse: DnsQueryResponse?,
        dnsError: String?,
        isQueryingDns: Bool,
        cacheActionMessage: String?,
        focusSearchTrigger: Int = 0,
        shouldAutoFocusSearch: Bool = false,
        onConsumeSearchFocus: @escaping () -> Void = {},
        onRefreshRules: @escaping () -> Void,
        onQueryDns: @escaping (String, String, String?) -> Void,
        onFlushFakeIp: @escaping () -> Void,
        onClearDnsCache: @escaping () -> Void,
        onClearAllCache: @escaping () -> Void
    ) {
        self.rules = rules
        self.outboundMode = outboundMode
        self.groups = groups
        self.dnsResponse = dnsResponse
        self.dnsError = dnsError
        self.isQueryingDns = isQueryingDns
        self.cacheActionMessage = cacheActionMessage
        self.focusSearchTrigger = focusSearchTrigger
        self.shouldAutoFocusSearch = shouldAutoFocusSearch
        self.onConsumeSearchFocus = onConsumeSearchFocus
        self.onRefreshRules = onRefreshRules
        self.onQueryDns = onQueryDns
        self.onFlushFakeIp = onFlushFakeIp
        self.onClearDnsCache = onClearDnsCache
        self.onClearAllCache = onClearAllCache
    }

    private var filteredRules: [RuleMetric] {
        let q = ruleSearch.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return rules }
        return rules.filter {
            $0.type.lowercased().contains(q)
                || $0.action.lowercased().contains(q)
                || $0.target.lowercased().contains(q)
                || $0.summary.lowercased().contains(q)
                || String($0.index).contains(q)
        }
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            dnsInspectorCard
            cacheControlsBar
            rulesSection
        }
        .padding()
        .task {
            if rules.isEmpty { onRefreshRules() }
        }
        .onAppear {
            consumePendingSearchFocusIfNeeded()
        }
        .onChange(of: focusSearchTrigger) { _, _ in
            consumePendingSearchFocusIfNeeded()
        }
        .confirmationDialog(
            "确认清空全部缓存？",
            isPresented: $showClearAllConfirm,
            titleVisibility: .visible
        ) {
            Button("清空全部缓存", role: .destructive, action: onClearAllCache)
            Button("取消", role: .cancel) {}
        } message: {
            Text("将清理 DNS 与路由运行时缓存，不会删除本地配置。")
        }
    }

    private func consumePendingSearchFocusIfNeeded() {
        if shouldAutoFocusSearch {
            isRuleSearchFocused = true
            onConsumeSearchFocus()
        }
    }

    private var isCompactLayout: Bool {
        #if os(iOS)
        return sizeClass == .compact
        #else
        return false
        #endif
    }

    private var dnsInspectorCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label("实时 DNS 探测", systemImage: "magnifyingglass.circle")
                    .font(.headline)
                Spacer()
                DeferredSpinnerView(isActive: isQueryingDns)
            }

            if isCompactLayout {
                VStack(alignment: .leading, spacing: 8) {
                    domainField
                    HStack(spacing: 8) {
                        recordTypePicker
                        serverField
                        queryButton
                    }
                }
            } else {
                HStack(spacing: 8) {
                    domainField
                        .frame(minWidth: 140)
                    recordTypePicker
                        .frame(minWidth: recordPickerWidth, maxWidth: recordPickerWidth + 24)
                    serverField
                        .frame(minWidth: 120, idealWidth: serverFieldWidth, maxWidth: 220)
                    queryButton
                }
            }

            if let err = dnsError, !err.isEmpty {
                Text("查询失败：\(err)")
                    .font(.caption)
                    .foregroundStyle(theme.danger)
            }

            if let resp = dnsResponse {
                Divider()
                DnsResponseSummarySection(response: resp)
            }
        }
        .bentoCard(padding: 12, cornerRadius: 14)
    }

    private var domainField: some View {
        TextField("域名（例如 example.com）", text: $domainInput)
            .textFieldStyle(.roundedBorder)
            .onSubmit { triggerDnsQuery() }
            .accessibilityLabel("DNS 查询域名")
    }

    private var recordTypePicker: some View {
        Picker("记录类型", selection: $recordType) {
            ForEach(recordTypes, id: \.self) { t in
                Text(t).tag(t)
            }
        }
        .labelsHidden()
    }

    private var serverField: some View {
        TextField("上游服务器（可选）", text: $serverInput)
            .textFieldStyle(.roundedBorder)
            .onSubmit { triggerDnsQuery() }
            .accessibilityLabel("上游 DNS 服务器")
    }

    private var queryButton: some View {
        Button("查询", action: triggerDnsQuery)
            .buttonStyle(NexusProminentButtonStyle())
            .disabled(isQueryingDns || domainInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
    }

    private var cacheControlsBar: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 8) {
                cacheButtons
                Spacer(minLength: 4)
                cacheStatusLabel
            }
            VStack(alignment: .leading, spacing: 6) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        cacheButtons
                    }
                }
                cacheStatusLabel
            }
        }
    }

    @ViewBuilder
    private var cacheButtons: some View {
        Button(action: onFlushFakeIp) {
            Label("刷新 FakeIP", systemImage: "sparkles")
        }
        .buttonStyle(.bordered)
        .accessibilityHint("清理未固定的 FakeIP 映射缓存")
        #if os(iOS)
        .frame(minHeight: 44)
        #endif

        Button(action: onClearDnsCache) {
            Label("清空 DNS 缓存", systemImage: "trash")
        }
        .buttonStyle(.bordered)
        #if os(iOS)
        .frame(minHeight: 44)
        #endif

        Button {
            showClearAllConfirm = true
        } label: {
            Label("清空全部缓存", systemImage: "xmark.bin")
        }
        .buttonStyle(.bordered)
        #if os(iOS)
        .frame(minHeight: 44)
        #endif
    }

    @ViewBuilder
    private var cacheStatusLabel: some View {
        if let msg = cacheActionMessage, !msg.isEmpty {
            Text(msg)
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
        }
    }

    private var rulesSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            if isCompactLayout {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        rulesHeading
                        Spacer()
                        refreshRulesButton
                    }
                    ruleSearchField
                }
            } else {
                HStack(spacing: 8) {
                    rulesHeading
                    Spacer(minLength: 8)
                    ruleSearchField
                        .frame(minWidth: 160, idealWidth: 240, maxWidth: 280)
                    refreshRulesButton
                }
            }

            if rules.isEmpty {
                ContentUnavailableView {
                    Label("暂无生效规则", systemImage: "list.bullet.rectangle")
                } description: {
                    Text("连接内核后点击刷新即可查看当前生效路由规则。")
                } actions: {
                    Button("刷新规则", action: onRefreshRules)
                        .buttonStyle(NexusProminentButtonStyle())
                }
            } else if filteredRules.isEmpty {
                ContentUnavailableView {
                    Label("未找到“\(ruleSearch)”", systemImage: "magnifyingglass")
                } description: {
                    Text("请尝试其他关键词或重置筛选条件。")
                } actions: {
                    Button("重置筛选") { ruleSearch = "" }
                        .buttonStyle(.bordered)
                }
            } else {
                let activeIndex = matchedRuleIndex
                List(filteredRules) { rule in
                    let queryable = DomainRouteExplainer.firstQueryableDomain(in: rule.summary)
                    RuleRowView(rule: rule, isMatched: activeIndex == rule.index)
                        .contentShape(Rectangle())
                        .onTapGesture {
                            if let queryable { prefillAndQuery(queryable) }
                        }
                        .contextMenu {
                            if let queryable {
                                Button {
                                    prefillAndQuery(queryable)
                                } label: {
                                    Label("探测此规则域名", systemImage: "magnifyingglass")
                                }
                            }
                            Button {
                                NexusByteFormat.copyToClipboard(rule.summary)
                            } label: {
                                Label("复制规则条件", systemImage: "doc.on.doc")
                            }
                        }
                        .accessibilityAction(named: Text("探测此规则域名")) {
                            if let queryable { prefillAndQuery(queryable) }
                        }
                }
                .scrollContentBackground(.hidden)
            }
        }
    }

    private var rulesHeading: some View {
        HStack(spacing: 8) {
            Text("生效路由规则")
                .font(.headline)
            Text("\(filteredRules.count) / \(rules.count) 条")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
        }
    }

    private var ruleSearchField: some View {
        TextField("过滤类型 / 目标 / 条件…", text: $ruleSearch)
            .textFieldStyle(.roundedBorder)
            .focused($isRuleSearchFocused)
            .accessibilityLabel("过滤路由规则")
    }

    private var refreshRulesButton: some View {
        Button(action: onRefreshRules) {
            Label("刷新", systemImage: "arrow.clockwise")
        }
        #if os(iOS)
        .frame(minHeight: 44)
        #endif
    }

    private var matchedRuleIndex: Int? {
        guard DomainRouteExplainer.looksLikeDomainQuery(domainInput) else { return nil }
        return DomainRouteExplainer.explain(
            domain: domainInput,
            outboundMode: outboundMode,
            rules: rules,
            groups: groups
        ).matchedRuleIndex
    }

    private func prefillAndQuery(_ domain: String) {
        domainInput = domain
        triggerDnsQuery()
    }

    private func triggerDnsQuery() {
        let domain = domainInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !domain.isEmpty else { return }
        let server = serverInput.trimmingCharacters(in: .whitespacesAndNewlines)
        onQueryDns(domain, recordType, server.isEmpty ? nil : server)
    }
}

private struct DnsResponseSummarySection: View {
    let response: DnsQueryResponse
    @Environment(\.nexusTheme) private var theme
    @ScaledMetric(relativeTo: .caption2) private var recordTypeColWidth: CGFloat = 48

    private var rcodeTint: Color {
        response.rcode == 0 ? theme.signalEmerald : (response.rcode == 3 ? theme.warning : theme.danger)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text(response.rcodeName.isEmpty ? "RCODE \(response.rcode)" : response.rcodeName)
                    .font(.caption.weight(.semibold).monospacedDigit())
                    .foregroundStyle(rcodeTint)
                Text("\(response.name) · \(response.type)")
                    .font(.caption.weight(.semibold).monospaced())
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .nexusTooltip("\(response.name) (\(response.type))")
                Spacer()
                Text("TTL \(response.ttl)s · \(response.elapsedMs) ms")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }

            if response.answers.isEmpty {
                Text(response.state == "pending" ? "查询排队中…" : "无应答记录")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(response.answers) { ans in
                    HStack(spacing: 8) {
                        Text(ans.type)
                            .font(.caption2.weight(.semibold).monospaced())
                            .foregroundStyle(theme.rxLine)
                            .frame(minWidth: recordTypeColWidth, alignment: .leading)
                        Text(ans.data)
                            .font(.caption.monospaced())
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .textSelection(.enabled)
                            .nexusTooltip(ans.data)
                        Spacer(minLength: 4)
                        Text("\(ans.ttl)s")
                            .font(.caption2.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }
}

private struct RuleRowView: View {
    let rule: RuleMetric
    let isMatched: Bool
    @Environment(\.nexusTheme) private var theme
    @ScaledMetric(relativeTo: .caption) private var indexColWidth: CGFloat = 40
    @ScaledMetric(relativeTo: .caption) private var typeColWidth: CGFloat = 104

    private var targetTint: Color {
        switch rule.target.lowercased() {
        case "direct": return theme.signalEmerald
        case "block", "reject": return theme.danger
        default: return theme.accentText
        }
    }

    var body: some View {
        HStack(spacing: 10) {
            RoundedRectangle(cornerRadius: 1)
                .fill(isMatched ? theme.accentFill : Color.clear)
                .frame(width: 2, height: 16)
                .accessibilityHidden(true)
            Text("#\(rule.index)")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
                .frame(minWidth: indexColWidth, alignment: .trailing)
            Text(rule.type)
                .font(.caption.weight(.medium).monospaced())
                .frame(minWidth: typeColWidth, alignment: .leading)
                .lineLimit(1)
            Text(rule.summary)
                .font(.caption.monospaced())
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
                .nexusTooltip(rule.summary)
            Spacer(minLength: 6)
            Text(rule.target.isEmpty ? rule.action : rule.target)
                .font(.caption.weight(.semibold))
                .foregroundStyle(targetTint)
                .lineLimit(1)
        }
        .accessibilityElement(children: .combine)
    }
}
#endif
