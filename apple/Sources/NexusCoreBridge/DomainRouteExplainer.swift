import Foundation

/// Pure local route explanation result used by the Command & Inline Domain Diagnostic Palette
/// and Rules & DNS Inspector (`gui-flagship-spec.md` §3.2).
public struct DomainRouteExplanation: Sendable, Equatable {
    public let domain: String
    public let matchedRuleIndex: Int?
    public let matchedRuleType: String
    public let matchedRuleSummary: String
    public let targetTag: String
    public let resolvedOutbound: String
    public let activeLatencyMs: Int64?
    public let isEstimate: Bool
    public let estimateNote: String

    public init(
        domain: String,
        matchedRuleIndex: Int? = nil,
        matchedRuleType: String = "",
        matchedRuleSummary: String = "",
        targetTag: String,
        resolvedOutbound: String,
        activeLatencyMs: Int64? = nil,
        isEstimate: Bool = true,
        estimateNote: String = "规则预估"
    ) {
        self.domain = domain
        self.matchedRuleIndex = matchedRuleIndex
        self.matchedRuleType = matchedRuleType
        self.matchedRuleSummary = matchedRuleSummary
        self.targetTag = targetTag
        self.resolvedOutbound = resolvedOutbound
        self.activeLatencyMs = activeLatencyMs
        self.isEstimate = isEstimate
        self.estimateNote = estimateNote
    }
}

/// Evaluates ordered `RuleMetric` entries and outbound policy groups against a domain query.
/// Honestly marks local ordered-rule results as `"规则预估"` when opaque `rule-set`/CIDR rules exist.
public enum DomainRouteExplainer {
    public static func looksLikeDomainQuery(_ raw: String) -> Bool {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.hasPrefix(">"), !trimmed.contains(" ") else {
            return false
        }
        let host = normalizeHost(trimmed)
        guard host.contains("."), host.count >= 3, host.count <= 253 else {
            return false
        }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2 else { return false }
        for label in labels {
            guard !label.isEmpty, label.count <= 63 else { return false }
            for scalar in label.unicodeScalars {
                let ok = (scalar.value >= 0x30 && scalar.value <= 0x39)
                    || (scalar.value >= 0x61 && scalar.value <= 0x7A)
                    || scalar == "-"
                    || scalar == "_"
                if !ok { return false }
            }
        }
        return true
    }

    /// Extracts the first concrete queryable domain from a rule summary such as
    /// `"domain-suffix: github.com, google.com"` or `".example.com"`, returning `nil` for CIDR/IP/regex/opaque rules.
    public static func firstQueryableDomain(in summary: String) -> String? {
        for pattern in extractPatterns(from: summary) {
            if pattern.contains("/") || pattern.contains("*") || pattern.contains("^") || pattern.contains("$") {
                continue
            }
            let stripped = pattern.hasPrefix(".") ? String(pattern.dropFirst()) : pattern
            let host = normalizeHost(stripped)
            guard looksLikeDomainQuery(host) else { continue }
            let tld = host.split(separator: ".").last ?? ""
            if tld.unicodeScalars.contains(where: { $0.value >= 0x61 && $0.value <= 0x7A }) {
                return host
            }
        }
        return nil
    }

    public static func normalizeHost(_ raw: String) -> String {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if let schemeRange = s.range(of: "://") {
            s = String(s[schemeRange.upperBound...])
        }
        if let slash = s.firstIndex(of: "/") {
            s = String(s[..<slash])
        }
        if let question = s.firstIndex(of: "?") {
            s = String(s[..<question])
        }
        if s.hasPrefix("["), let close = s.firstIndex(of: "]") {
            s = String(s[s.index(after: s.startIndex)..<close])
        } else if let colon = s.firstIndex(of: ":") {
            s = String(s[..<colon])
        }
        while s.hasPrefix(".") { s.removeFirst() }
        while s.hasSuffix(".") { s.removeLast() }
        return s
    }

    public static func explain(
        domain rawDomain: String,
        outboundMode: String,
        rules: [RuleMetric],
        groups: [OutboundGroupSnapshot]
    ) -> DomainRouteExplanation {
        let host = normalizeHost(rawDomain)
        let mode = outboundMode.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

        if mode == "direct" {
            return DomainRouteExplanation(
                domain: host,
                matchedRuleType: "mode",
                matchedRuleSummary: "直连模式",
                targetTag: "direct",
                resolvedOutbound: "direct",
                activeLatencyMs: nil,
                isEstimate: false,
                estimateNote: "直连模式直达"
            )
        }

        if mode == "global" {
            let primary = groups.first
            let target = primary?.tag ?? "global"
            let (resolved, rtt) = resolveOutbound(tag: target, groups: groups)
            return DomainRouteExplanation(
                domain: host,
                matchedRuleType: "mode",
                matchedRuleSummary: "全局模式",
                targetTag: target,
                resolvedOutbound: resolved,
                activeLatencyMs: rtt,
                isEstimate: false,
                estimateNote: "全局模式直达"
            )
        }

        var sawOpaqueRule = false
        for rule in rules {
            let kind = rule.type.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if isOpaqueRuleType(kind) {
                sawOpaqueRule = true
                continue
            }
            if matches(host: host, ruleType: kind, summary: rule.summary) {
                let target = rule.target.isEmpty ? rule.action : rule.target
                let (resolved, rtt) = resolveOutbound(tag: target, groups: groups)
                let note = sawOpaqueRule ? "规则预估（前置规则集/IP 规则由内核实判）" : "规则预估"
                return DomainRouteExplanation(
                    domain: host,
                    matchedRuleIndex: rule.index,
                    matchedRuleType: rule.type,
                    matchedRuleSummary: rule.summary.isEmpty ? rule.type : rule.summary,
                    targetTag: target,
                    resolvedOutbound: resolved,
                    activeLatencyMs: rtt,
                    isEstimate: true,
                    estimateNote: note
                )
            }
        }

        let fallbackTarget = groups.first?.tag ?? "proxy"
        let (resolved, rtt) = resolveOutbound(tag: fallbackTarget, groups: groups)
        let fallbackNote = rules.isEmpty
            ? "规则预估（尚未加载规则表）"
            : (sawOpaqueRule ? "规则预估（含规则集/IP 规则，以内核实判为准）" : "规则预估（默认出站）")
        return DomainRouteExplanation(
            domain: host,
            matchedRuleType: "default",
            matchedRuleSummary: "默认路由",
            targetTag: fallbackTarget,
            resolvedOutbound: resolved,
            activeLatencyMs: rtt,
            isEstimate: true,
            estimateNote: fallbackNote
        )
    }

    private static func isOpaqueRuleType(_ kind: String) -> Bool {
        kind.contains("rule-set")
            || kind.contains("rule_set")
            || kind.contains("ruleset")
            || kind.contains("geosite")
            || kind.contains("geoip")
            || kind.contains("ip-cidr")
            || kind.contains("ip_cidr")
            || kind.contains("cidr")
            || kind.contains("process")
            || kind.contains("port")
    }

    private static func matches(host: String, ruleType: String, summary: String) -> Bool {
        if ruleType == "final" || ruleType == "match" || ruleType == "default" {
            return true
        }
        let patterns = extractPatterns(from: summary)
        guard !patterns.isEmpty else { return false }

        switch ruleType {
        case "domain", "domain-full", "domain_full", "full":
            return patterns.contains { host == $0 }
        case "domain-suffix", "domain_suffix", "suffix":
            return patterns.contains { pat in
                let clean = pat.hasPrefix(".") ? String(pat.dropFirst()) : pat
                return !clean.isEmpty && (host == clean || host.hasSuffix(".\(clean)"))
            }
        case "domain-keyword", "domain_keyword", "keyword":
            return patterns.contains { !($0.isEmpty) && host.contains($0) }
        case "domain-regex", "domain_regex", "regex":
            return patterns.contains { pat in
                !pat.isEmpty && host.range(of: pat, options: .regularExpression) != nil
            }
        default:
            return false
        }
    }

    private static func extractPatterns(from summary: String) -> [String] {
        var raw = summary.trimmingCharacters(in: .whitespacesAndNewlines)
        if let colon = raw.firstIndex(of: ":"), !raw.contains("://") {
            let prefix = raw[..<colon].lowercased()
            if prefix.contains("domain") || prefix == "suffix" || prefix == "keyword" || prefix == "regex" {
                raw = String(raw[raw.index(after: colon)...])
            }
        }
        return raw
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
            .filter { !$0.isEmpty }
    }

    private static func resolveOutbound(
        tag: String,
        groups: [OutboundGroupSnapshot]
    ) -> (resolved: String, latencyMs: Int64?) {
        var current = tag
        var visited: Set<String> = []
        while !visited.contains(current) {
            visited.insert(current)
            guard let group = groups.first(where: { $0.tag.caseInsensitiveCompare(current) == .orderedSame }) else {
                break
            }
            if group.active.isEmpty { break }
            if let member = group.members.first(where: { $0.name == group.active }) {
                let lat = GroupLatencySummary.effectiveLatency(member)
                if !groups.contains(where: { $0.tag == member.name }) {
                    return (member.name, lat)
                }
            }
            current = group.active
        }
        for group in groups {
            if let member = group.members.first(where: { $0.name.caseInsensitiveCompare(current) == .orderedSame }) {
                return (member.name, GroupLatencySummary.effectiveLatency(member))
            }
        }
        return (current, nil)
    }
}
