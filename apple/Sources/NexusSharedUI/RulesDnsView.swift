#if canImport(SwiftUI)
import SwiftUI
import NexusCoreBridge

/// Live searchable Rules (`/v1/rules`) + interactive Live DNS Query (`/v1/dns/query`)
/// + FakeIP/DNS cache flush controls shared across macOS and iOS.
public struct RulesDnsView: View {
    public let rules: [RuleMetric]
    public let dnsResponse: DnsQueryResponse?
    public let dnsError: String?
    public let isQueryingDns: Bool
    public let cacheActionMessage: String?
    public let onRefreshRules: () -> Void
    public let onQueryDns: (String, String, String?) -> Void
    public let onFlushFakeIp: () -> Void
    public let onClearDnsCache: () -> Void
    public let onClearAllCache: () -> Void

    @State private var ruleSearch: String = ""
    @State private var domainInput: String = "example.com"
    @State private var recordType: String = "A"
    @State private var serverInput: String = ""

    private let recordTypes = ["A", "AAAA", "CNAME", "HTTPS", "SVCB", "TXT", "MX", "NS", "SRV"]

    public init(
        rules: [RuleMetric],
        dnsResponse: DnsQueryResponse?,
        dnsError: String?,
        isQueryingDns: Bool,
        cacheActionMessage: String?,
        onRefreshRules: @escaping () -> Void,
        onQueryDns: @escaping (String, String, String?) -> Void,
        onFlushFakeIp: @escaping () -> Void,
        onClearDnsCache: @escaping () -> Void,
        onClearAllCache: @escaping () -> Void
    ) {
        self.rules = rules
        self.dnsResponse = dnsResponse
        self.dnsError = dnsError
        self.isQueryingDns = isQueryingDns
        self.cacheActionMessage = cacheActionMessage
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
    }

    private var dnsInspectorCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label("实时 DNS 探测 (/v1/dns/query)", systemImage: "magnifyingglass.circle")
                    .font(.headline)
                Spacer()
                if isQueryingDns {
                    ProgressView().controlSize(.small)
                }
            }

            HStack(spacing: 8) {
                TextField("域名 (例如 example.com)", text: $domainInput)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { triggerDnsQuery() }
                    .accessibilityLabel("DNS 查询域名")
                Picker("记录类型", selection: $recordType) {
                    ForEach(recordTypes, id: \.self) { t in
                        Text(t).tag(t)
                    }
                }
                .labelsHidden()
                .frame(width: 96)
                TextField("上游服务器 (可选)", text: $serverInput)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 180)
                    .onSubmit { triggerDnsQuery() }
                Button("查询", action: triggerDnsQuery)
                    .buttonStyle(.borderedProminent)
                    .disabled(isQueryingDns || domainInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }

            if let err = dnsError, !err.isEmpty {
                Text("查询失败: \(err)")
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            if let resp = dnsResponse {
                DnsResponseSummaryCard(response: resp)
            }
        }
        .bentoCard(padding: 12)
    }

    private var cacheControlsBar: some View {
        HStack(spacing: 8) {
            Button(action: onFlushFakeIp) {
                Label("刷新 FakeIP", systemImage: "sparkles")
            }
            .buttonStyle(.bordered)
            .accessibilityHint("调用 POST /v1/cache/fakeip/flush 清理未固定 FakeIP 映射")

            Button(action: onClearDnsCache) {
                Label("清空 DNS 缓存", systemImage: "trash")
            }
            .buttonStyle(.bordered)

            Button(action: onClearAllCache) {
                Label("清空全部缓存", systemImage: "xmark.bin")
            }
            .buttonStyle(.bordered)

            Spacer()

            if let msg = cacheActionMessage, !msg.isEmpty {
                Text(msg)
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var rulesSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Text("生效路由规则 (/v1/rules)")
                    .font(.headline)
                Text("\(filteredRules.count) / \(rules.count)")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 2)
                    .background(NexusPalette.subtleSurface, in: Capsule())
                Spacer()
                TextField("过滤类型 / 目标 / 条件...", text: $ruleSearch)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 260)
                Button(action: onRefreshRules) {
                    Label("刷新", systemImage: "arrow.clockwise")
                }
            }

            if filteredRules.isEmpty {
                ContentUnavailableView(
                    "暂无匹配规则",
                    systemImage: "list.bullet.rectangle",
                    description: Text("连接核心控制面后点击刷新以加载当前已编译路由规则。")
                )
            } else {
                List(filteredRules) { rule in
                    RuleRowView(rule: rule)
                }
            }
        }
    }

    private func triggerDnsQuery() {
        let domain = domainInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !domain.isEmpty else { return }
        let server = serverInput.trimmingCharacters(in: .whitespacesAndNewlines)
        onQueryDns(domain, recordType, server.isEmpty ? nil : server)
    }
}

private struct DnsResponseSummaryCard: View {
    let response: DnsQueryResponse

    private var rcodeTint: Color {
        response.rcode == 0 ? .green : (response.rcode == 3 ? .orange : .red)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text(response.rcodeName.isEmpty ? "RCODE \(response.rcode)" : response.rcodeName)
                    .font(.caption.weight(.semibold).monospacedDigit())
                    .foregroundStyle(rcodeTint)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .background(rcodeTint.opacity(0.12), in: Capsule())
                Text("\(response.name) · \(response.type)")
                    .font(.caption.weight(.semibold).monospaced())
                Spacer()
                Text("TTL \(response.ttl)s · \(response.elapsedMs) ms")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }

            if response.answers.isEmpty {
                Text(response.state == "pending" ? "查询排队中..." : "无应答记录")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(response.answers) { ans in
                    HStack(spacing: 8) {
                        Text(ans.type)
                            .font(.caption2.weight(.semibold).monospaced())
                            .foregroundStyle(.blue)
                            .frame(width: 48, alignment: .leading)
                        Text(ans.data)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                        Spacer()
                        Text("\(ans.ttl)s")
                            .font(.caption2.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .padding(10)
        .background(NexusPalette.subtleSurface, in: RoundedRectangle(cornerRadius: 8))
    }
}

private struct RuleRowView: View {
    let rule: RuleMetric

    private var targetTint: Color {
        switch rule.target.lowercased() {
        case "direct": return .green
        case "block", "reject": return .red
        default: return .blue
        }
    }

    var body: some View {
        HStack(spacing: 10) {
            Text("#\(rule.index)")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
                .frame(width: 42, alignment: .trailing)
            Text(rule.type)
                .font(.caption.weight(.medium).monospaced())
                .frame(width: 112, alignment: .leading)
                .lineLimit(1)
            Text(rule.summary)
                .font(.caption.monospaced())
                .lineLimit(1)
                .textSelection(.enabled)
            Spacer()
            Text(rule.target.isEmpty ? rule.action : rule.target)
                .font(.caption2.weight(.semibold))
                .foregroundStyle(targetTint)
                .padding(.horizontal, 8)
                .padding(.vertical, 3)
                .background(targetTint.opacity(0.12), in: Capsule())
        }
        .accessibilityElement(children: .combine)
    }
}
#endif
