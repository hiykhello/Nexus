package org.nexus.android.ui

import org.nexus.android.bridge.ipc.OutboundGroupSnapshot
import org.nexus.android.bridge.ipc.OutboundMemberSnapshot

data class RuleExplainSummary(
    val dnsPolicy: String,
    val routeRule: String,
    val action: String,
    val outbound: String,
    val isOffline: Boolean = false,
)

data class QuickNodeMatch(
    val groupTag: String,
    val member: OutboundMemberSnapshot,
)

private val IPV4_REGEX = Regex("^(\\d{1,3}\\.){3}\\d{1,3}$")
private val HOST_CHAR_REGEX = Regex("^[a-zA-Z0-9._\\-\\[\\]:]+$")
private val RULE_INDEX_REGEX = Regex("^rule:(\\d+)$", RegexOption.IGNORE_CASE)

enum class QuickCommandActionId {
    MODE_RULE,
    MODE_GLOBAL,
    MODE_DIRECT,
    PROBE_ALL,
    FLUSH_FAKEIP,
    CLEAR_CACHE,
    SPLIT_TUNNEL,
}

data class QuickCommandActionSpec(
    val id: QuickCommandActionId,
    val label: String,
    val keywords: String,
    val requiresRunning: Boolean = false,
    val selected: Boolean = false,
)

/**
 * Detects whether a command palette query looks like a domain or IP host suitable for
 * inline Rule Explain + DNS Query diagnostics (rejecting empty input, spaces, and `>` commands).
 */
fun looksLikeDomainOrHost(raw: String): Boolean {
    val q = raw.trim()
    if (q.length < 3 || q.startsWith(">") || q.any { it.isWhitespace() }) return false
    val stripped = extractDiagnosticHost(q)
    if (stripped.length < 3 || !HOST_CHAR_REGEX.matches(stripped)) return false
    if (IPV4_REGEX.matches(stripped)) {
        return stripped.split('.').all { it.toIntOrNull() in 0..255 }
    }
    if (stripped.contains(':')) {
        // IPv6 literal
        return stripped.count { it == ':' } >= 2
    }
    if (!stripped.contains('.') || stripped.startsWith('.') || stripped.endsWith('.')) return false
    val labels = stripped.split('.')
    if (labels.size < 2 || labels.any { it.isEmpty() || it.startsWith('-') || it.endsWith('-') }) return false
    val tld = labels.last()
    return tld.length >= 2 && tld.any { it.isLetter() }
}

/**
 * Extracts a clean hostname/IP (without scheme, path, brackets, or port) for DNS queries.
 */
fun extractDiagnosticHost(raw: String): String {
    var s = raw.trim()
    if (s.contains("://")) s = s.substringAfter("://")
    s = s.substringBefore('/').substringBefore('?').substringBefore('#').trim()
    if (s.startsWith("[")) {
        return s.substringAfter('[').substringBefore(']')
    }
    val firstColon = s.indexOf(':')
    val lastColon = s.lastIndexOf(':')
    if (firstColon > 0 && firstColon == lastColon) {
        val port = s.substring(lastColon + 1).toIntOrNull()
        if (port in 1..65535) return s.substring(0, lastColon)
    }
    return s
}

/**
 * Normalizes a host/domain into `host:port` authority required by Core `rule explain`.
 */
fun normalizeExplainTarget(raw: String): String {
    val s = raw.trim().substringAfter("://").substringBefore('/').substringBefore('?').trim()
    if (s.isEmpty() || s.any { it.isWhitespace() }) return ""
    if (s.startsWith("[")) {
        return if (s.contains("]:")) s else "$s:443"
    }
    val firstColon = s.indexOf(':')
    val lastColon = s.lastIndexOf(':')
    if (firstColon >= 0 && firstColon != lastColon) return "[$s]:443"
    return if (lastColon > 0 && s.substring(lastColon + 1).toIntOrNull() in 1..65535) {
        s
    } else {
        "${s.trimEnd(':')}:443"
    }
}

/**
 * Parses Core `rule explain --oneline` output (`dns=... route=... action=... outbound=...`)
 * into clean user-facing labels without exposing raw CLI syntax.
 */
fun parseExplainOneline(
    rawOutput: String,
    running: Boolean = true,
): RuleExplainSummary? {
    val line = rawOutput.lineSequence().map { it.trim() }.firstOrNull { it.contains("action=") && it.contains("outbound=") }
        ?: return null
    val tokens = mutableMapOf<String, String>()
    line.split(Regex("\\s+")).forEach { part ->
        val idx = part.indexOf('=')
        if (idx > 0) {
            tokens[part.substring(0, idx)] = part.substring(idx + 1)
        }
    }
    val rawAction = tokens["action"].orEmpty()
    val rawOutbound = tokens["outbound"].orEmpty()
    val rawRoute = tokens["route"].orEmpty()
    val rawDns = tokens["dns"].orEmpty()
    if (rawAction.isEmpty() && rawOutbound.isEmpty()) return null

    val humanAction = when (rawAction.lowercase()) {
        "reject", "block" -> "拦截"
        "route" -> if (rawOutbound.equals("direct", ignoreCase = true)) "直连" else "代理分流"
        else -> rawAction.ifEmpty { "分流" }
    }
    val ruleIndexMatch = RULE_INDEX_REGEX.matchEntire(rawRoute)
    val humanRoute = when {
        rawRoute.isEmpty() || rawRoute.equals("default", ignoreCase = true) -> "默认规则"
        ruleIndexMatch != null -> "规则 #${ruleIndexMatch.groupValues[1]}"
        else -> rawRoute
    }
    val humanDns = when {
        rawDns.isEmpty() || rawDns.equals("none", ignoreCase = true) -> "默认解析"
        rawDns.startsWith("reject", ignoreCase = true) -> "DNS 拦截"
        rawDns.startsWith("evaluate:", ignoreCase = true) -> rawDns.removePrefix("evaluate:")
        else -> rawDns
    }
    return RuleExplainSummary(
        dnsPolicy = humanDns,
        routeRule = humanRoute,
        action = humanAction,
        outbound = rawOutbound.ifEmpty { "-" },
        isOffline = !running,
    )
}

/**
 * Detects whether an IP address belongs to Nexus's FakeIP pools (`198.18.0.0/15` or `fc00::/18`).
 */
fun isFakeIpAddress(ip: String): Boolean {
    val clean = ip.trim().lowercase()
    if (clean.startsWith("198.18.") || clean.startsWith("198.19.")) return true
    if (clean.startsWith("fc")) {
        val hexPrefix = clean.substringBefore(':')
        val value = hexPrefix.toIntOrNull(16)
        if (value != null && value in 0xFC00..0xFC3F) return true
    }
    return false
}

/**
 * Instant case-insensitive fuzzy search across all cached policy groups and members.
 */
fun filterCommandNodes(
    groups: List<OutboundGroupSnapshot>,
    query: String,
    limit: Int = 12,
): List<QuickNodeMatch> {
    if (groups.isEmpty()) return emptyList()
    val q = query.trim().lowercase()
    if (q.startsWith(">")) return emptyList()
    val out = ArrayList<QuickNodeMatch>(limit)
    if (q.isEmpty()) {
        val primary = groups.first()
        primary.members.take(6).forEach { out.add(QuickNodeMatch(primary.tag, it)) }
        return out
    }
    for (group in groups) {
        val groupHit = group.tag.lowercase().contains(q)
        for (member in group.members) {
            if (groupHit || member.name.lowercase().contains(q)) {
                out.add(QuickNodeMatch(group.tag, member))
                if (out.size >= limit) return out
            }
        }
    }
    return out
}

/**
 * Filters quick command actions for empty or `>` prefixed queries.
 */
fun filterQuickCommandActions(
    query: String,
    running: Boolean,
    outboundMode: String,
): List<QuickCommandActionSpec> {
    val trimmed = query.trim()
    val all = listOf(
        QuickCommandActionSpec(QuickCommandActionId.MODE_RULE, "规则模式", "rule mode 规则 分流", selected = outboundMode == "rule"),
        QuickCommandActionSpec(QuickCommandActionId.MODE_GLOBAL, "全局模式", "global mode 全局 代理", selected = outboundMode == "global"),
        QuickCommandActionSpec(QuickCommandActionId.MODE_DIRECT, "直连模式", "direct mode 直连 绕过", selected = outboundMode == "direct"),
        QuickCommandActionSpec(QuickCommandActionId.PROBE_ALL, "全部测速", "probe speed test 测速 延迟", requiresRunning = true),
        QuickCommandActionSpec(QuickCommandActionId.FLUSH_FAKEIP, "刷新 FakeIP", "flush fakeip dns 刷新 重置", requiresRunning = true),
        QuickCommandActionSpec(QuickCommandActionId.CLEAR_CACHE, "清空缓存", "clear cache 缓存 清理", requiresRunning = true),
        QuickCommandActionSpec(QuickCommandActionId.SPLIT_TUNNEL, "分应用控制", "split tunnel app bypass 分应用 绕过"),
    ).filter { !it.requiresRunning || running }

    if (trimmed.isEmpty() || trimmed == ">") return all
    if (!trimmed.startsWith(">")) return emptyList()
    val needle = trimmed.removePrefix(">").trim().lowercase()
    if (needle.isEmpty()) return all
    return all.filter { spec ->
        spec.label.lowercase().contains(needle) || spec.keywords.contains(needle)
    }
}

/**
 * Selects the first probeable policy group (`url-test` / `fallback` / `load-balance`),
 * skipping `selector`/`select` groups that Core rejects with HTTP 409.
 */
fun findProbeableGroupTag(
    groups: List<OutboundGroupSnapshot>,
    preferredTag: String = "",
): String? {
    fun OutboundGroupSnapshot.isProbeable(): Boolean =
        !mode.equals("selector", ignoreCase = true) && !mode.equals("select", ignoreCase = true)

    if (preferredTag.isNotEmpty()) {
        groups.firstOrNull { it.tag == preferredTag && it.isProbeable() }?.let { return it.tag }
    }
    return groups.firstOrNull { it.isProbeable() }?.tag
}
