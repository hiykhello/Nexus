package org.nexus.android.bridge.model

/**
 * Pure Nexus KDL 2.0 routing & DNS rule builder and safe insertion helpers
 * powering the mobile Rules & DNS modal sheet (mirroring desktop `kdl_ops.cpp`).
 */
object AndroidRuleOps {
    private val OUTBOUND_TAG_REGEX = Regex("(?m)^\\s*outbound\\s+\"([^\"]+)\"\\s+type=\"([^\"]+)\"")
    private val DNS_SERVER_REGEX = Regex("(?m)^\\s*server\\s+\"([^\"]+)\"")

    private val ALLOWED_ROUTE_MATCH = setOf("domain-suffix", "domain", "domain-keyword", "ip-cidr")
    private val ALLOWED_DNS_MATCH = setOf("domain-suffix", "domain", "domain-keyword", "source-ip-cidr")

    fun normalizePattern(matchType: String, rawPattern: String): String {
        val trimmed = rawPattern.trim()
        if (trimmed.isEmpty()) return ""
        if (matchType == "ip-cidr" || matchType == "source-ip-cidr") {
            if (trimmed.contains('/')) return trimmed
            val bare = trimmed.removePrefix("[").removeSuffix("]")
            return when {
                AndroidKdlOps.isIpv4Literal(bare) -> "$bare/32"
                AndroidKdlOps.isIpv6Literal(bare) -> "$bare/128"
                else -> trimmed
            }
        }
        return trimmed.removePrefix(".")
    }

    fun buildCustomRouteRule(
        matchType: String,
        pattern: String,
        action: String,
        outbound: String = "proxy",
    ): Pair<Boolean, String> {
        val safeMatch = if (matchType in ALLOWED_ROUTE_MATCH) matchType else "domain-suffix"
        val normalized = normalizePattern(safeMatch, pattern)
        if (normalized.isEmpty()) return false to "请输入匹配目标"
        val escapedPattern = AndroidKdlBuilder.escapeKdlString(normalized)
        val safeAction = when (action) {
            "route", "reject", "bypass" -> action
            else -> "route"
        }
        val header = if (safeAction == "route") {
            val safeOut = AndroidKdlBuilder.escapeKdlString(outbound.ifBlank { "proxy" })
            "rule action=\"route\" outbound=\"$safeOut\""
        } else {
            "rule action=\"$safeAction\""
        }
        return true to "$header {\n    $safeMatch \"$escapedPattern\"\n}"
    }

    fun buildDnsRule(
        matchType: String,
        pattern: String,
        action: String,
        server: String = "local",
    ): Pair<Boolean, String> {
        val safeMatch = if (matchType in ALLOWED_DNS_MATCH) matchType else "domain-suffix"
        val normalized = normalizePattern(safeMatch, pattern)
        if (normalized.isEmpty()) return false to "请输入匹配目标"
        val escapedPattern = AndroidKdlBuilder.escapeKdlString(normalized)
        return if (action == "reject") {
            true to "rule $safeMatch=\"$escapedPattern\" action=\"reject\" reject-method=\"reply\""
        } else {
            val safeServer = AndroidKdlBuilder.escapeKdlString(server.ifBlank { "local" })
            true to "rule $safeMatch=\"$escapedPattern\" action=\"route\" server=\"$safeServer\""
        }
    }

    private const val DEFAULT_DNS_SERVERS =
        "    server \"local\" type=\"local\"\n" +
            "    server \"remote\" type=\"udp\" host=\"1.1.1.1\" port=53\n"

    fun insertDnsRule(kdl: String, ruleLine: String): Pair<Boolean, String> {
        val clean = ruleLine.trim()
        if (clean.isEmpty()) return false to "空 DNS 规则"
        val dnsBlock = AndroidKdlOps.findTopLevelBlock(kdl, "dns")
        if (dnsBlock != null) {
            val inner = kdl.substring(dnsBlock.first + 1, dnsBlock.second)
            val insertAt = dnsBlock.second
            val prefix = if (insertAt > 0 && kdl[insertAt - 1] != '\n') "\n" else ""
            val serverPrefix = if (DNS_SERVER_REGEX.containsMatchIn(inner)) "" else DEFAULT_DNS_SERVERS
            val indented = serverPrefix + AndroidKdlOps.indentLines(clean, "    ")
            return true to (kdl.substring(0, insertAt) + prefix + indented + kdl.substring(insertAt))
        }
        val block = "dns {\n" + DEFAULT_DNS_SERVERS + AndroidKdlOps.indentLines(clean, "    ") + "}"
        return true to AndroidKdlOps.mergeRawSnippet(kdl, block)
    }

    fun extractOutboundTargets(kdl: String): List<String> {
        val preferred = LinkedHashSet<String>()
        val proxyGroup = AndroidKdlOps.extractProxyGroupName(kdl)
        if (proxyGroup.isNotBlank()) preferred.add(proxyGroup)
        OUTBOUND_TAG_REGEX.findAll(kdl).forEach { m ->
            val tag = m.groupValues[1]
            val type = m.groupValues[2].lowercase()
            if (type != "block" && type != "reject") preferred.add(tag)
        }
        preferred.add("direct")
        return preferred.take(6)
    }

    fun extractDnsServers(kdl: String): List<String> {
        val servers = LinkedHashSet<String>()
        val dnsBlock = AndroidKdlOps.findTopLevelBlock(kdl, "dns")
        if (dnsBlock != null) {
            val inner = kdl.substring(dnsBlock.first + 1, dnsBlock.second)
            DNS_SERVER_REGEX.findAll(inner).forEach { m ->
                val tag = m.groupValues[1].trim()
                if (tag.isNotEmpty()) servers.add(tag)
            }
        }
        if (servers.isEmpty()) {
            servers.add("local")
            servers.add("remote")
        }
        return servers.take(6)
    }
}
