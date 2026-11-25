package org.nexus.android.bridge.model

/**
 * Pure KDL 2.0 inspection and safe mutation helpers shared by Android UI workflows:
 * - Outbound mode switching (`rule` / `global` / `direct`) mirroring desktop `kdl_ops.cpp`
 * - Quick route rule insertion into `routing { tcp-program sniff-timeout-ms=300 unknown="skip" { ... } }`
 * - First-run detection (whether any remote outbound exists besides `direct` / `block`)
 */
object AndroidKdlOps {
    private const val SAVED_DEFAULT_MARKER = "// nexus-saved-default-outbound: "
    private const val DEFAULT_TCP_PROGRAM_HEADER = "tcp-program sniff-timeout-ms=300 unknown=\"skip\""
    private val OUTBOUND_DECL_REGEX = Regex("(?m)^\\s*outbound\\s+\"([^\"]+)\"\\s+type=\"([^\"]+)\"")
    private val GROUP_DECL_REGEX = Regex("(?m)^\\s*outbound\\s+\"([^\"]+)\"\\s+type=\"(selector|url-test|fallback|load-balance)\"")

    fun detectOutboundMode(kdl: String): String {
        val span = findDefaultOutboundSpan(kdl) ?: return "rule"
        val saved = readSavedDefaultOutbound(kdl)
        val cur = kdl.substring(span.first, span.second)
        if (saved != null) {
            return if (cur == "direct") "direct" else "global"
        }
        return if (cur == "direct" && hasRemoteOutbound(kdl)) "direct" else "rule"
    }

    fun applyOutboundMode(
        kdl: String,
        mode: String,
        proxyGroup: String = extractProxyGroupName(kdl),
    ): Pair<Boolean, String> {
        if (mode != "rule" && mode != "global" && mode != "direct") {
            return false to "无效的出站模式: $mode"
        }
        val span = findDefaultOutboundSpan(kdl)
            ?: return false to "当前配置缺少 routing { default-outbound ... } 节点"
        val current = kdl.substring(span.first, span.second)
        val saved = readSavedDefaultOutbound(kdl)
        val safeGroup = if (isSafeKdlToken(proxyGroup)) proxyGroup else "proxy"
        val target = when (mode) {
            "direct" -> "direct"
            "global" -> safeGroup
            else -> saved ?: if (current == "direct") safeGroup else current
        }

        val sb = StringBuilder(kdl)
        sb.replace(span.first, span.second, target)
        if (mode != "rule" && saved == null && current != "direct" && isSafeKdlToken(current)) {
            if (sb.isNotEmpty() && sb[sb.length - 1] != '\n') sb.append('\n')
            sb.append(SAVED_DEFAULT_MARKER).append(current).append('\n')
        } else if (mode == "rule" && saved != null) {
            val markerIdx = sb.indexOf(SAVED_DEFAULT_MARKER)
            if (markerIdx >= 0) {
                val eol = sb.indexOf('\n', markerIdx)
                val end = if (eol >= 0) eol + 1 else sb.length
                sb.delete(markerIdx, end)
            }
        }
        return true to sb.toString()
    }

    fun buildQuickRouteRule(
        targetHost: String,
        action: String = "route",
        outbound: String = "proxy",
    ): String {
        val cleanHost = stripPortAndBrackets(targetHost)
        val escapedHost = AndroidKdlBuilder.escapeKdlString(cleanHost)
        val predicate = when {
            isIpv4Literal(cleanHost) -> "ip-cidr \"$escapedHost/32\""
            isIpv6Literal(cleanHost) -> "ip-cidr \"$escapedHost/128\""
            else -> "domain-suffix \"$escapedHost\""
        }
        val safeAction = when (action) {
            "reject", "bypass", "route" -> action
            else -> "route"
        }
        val header = if (safeAction == "route") {
            val safeOut = AndroidKdlBuilder.escapeKdlString(outbound.ifBlank { "proxy" })
            "rule action=\"route\" outbound=\"$safeOut\""
        } else {
            "rule action=\"$safeAction\""
        }
        return "$header {\n    $predicate\n}"
    }

    fun insertRouteRule(kdl: String, ruleBlock: String): Pair<Boolean, String> {
        val clean = ruleBlock.trim()
        if (clean.isEmpty()) return false to "空路由规则"
        val routing = findTopLevelBlock(kdl, "routing")
        if (routing != null) {
            val inner = kdl.substring(routing.first + 1, routing.second)
            val tcpProg = findTopLevelBlock(inner, "tcp-program")
            if (tcpProg != null) {
                val insertAt = routing.first + 1 + tcpProg.second
                val prefix = if (insertAt > 0 && kdl[insertAt - 1] != '\n') "\n" else ""
                val indented = indentLines(clean, "        ") + "    "
                return true to (kdl.substring(0, insertAt) + prefix + indented + kdl.substring(insertAt))
            }
            val insertAt = routing.second
            val prefix = if (insertAt > 0 && kdl[insertAt - 1] != '\n') "\n" else ""
            val block = "    $DEFAULT_TCP_PROGRAM_HEADER {\n" + indentLines(clean, "        ") + "    }\n"
            return true to (kdl.substring(0, insertAt) + prefix + block + kdl.substring(insertAt))
        }
        val block = "routing {\n    default-outbound \"direct\"\n    $DEFAULT_TCP_PROGRAM_HEADER {\n" +
            indentLines(clean, "        ") + "    }\n}"
        return true to mergeRawSnippet(kdl, block)
    }

    fun hasRemoteOutbound(kdl: String): Boolean =
        OUTBOUND_DECL_REGEX.findAll(kdl).any { match ->
            val type = match.groupValues[2].lowercase()
            type != "direct" && type != "block" && type != "reject"
        }

    fun extractProxyGroupName(kdl: String): String {
        GROUP_DECL_REGEX.find(kdl)?.let { return it.groupValues[1] }
        OUTBOUND_DECL_REGEX.findAll(kdl).firstOrNull {
            val t = it.groupValues[2].lowercase()
            t != "direct" && t != "block" && t != "reject"
        }?.let { return it.groupValues[1] }
        return "proxy"
    }

    /**
     * Safely normalizes 4-space KDL indentation and collapses excessive blank lines while
     * preserving strings, multiline string literals, and line/block comments untouched.
     */
    fun formatKdl(kdl: String): String {
        if (kdl.isBlank()) return ""
        val lines = kdl.replace("\r\n", "\n").replace('\r', '\n').split('\n')
        val out = ArrayList<String>(lines.size)
        var depth = 0
        var inMultilineString = false
        var blockCommentDepth = 0
        var prevBlank = true

        for (rawLine in lines) {
            if (inMultilineString) {
                out.add(rawLine)
                if (rawLine.contains("\"\"\"")) {
                    inMultilineString = false
                }
                prevBlank = false
                continue
            }

            val trimmed = rawLine.trim()
            if (trimmed.isEmpty()) {
                if (!prevBlank) {
                    out.add("")
                    prevBlank = true
                }
                continue
            }
            prevBlank = false

            if (blockCommentDepth > 0) {
                out.add("    ".repeat(depth) + trimmed)
                blockCommentDepth = updateBlockCommentDepth(trimmed, blockCommentDepth)
                continue
            }

            var leadingCloses = 0
            while (leadingCloses < trimmed.length && trimmed[leadingCloses] == '}') {
                leadingCloses++
            }
            val lineDepth = (depth - leadingCloses).coerceAtLeast(0)
            out.add("    ".repeat(lineDepth) + trimmed)

            var i = leadingCloses
            var openDelta = 0
            val n = trimmed.length
            while (i < n) {
                val ch = trimmed[i]
                when {
                    ch == '/' && i + 1 < n && trimmed[i + 1] == '/' -> break
                    ch == '/' && i + 1 < n && trimmed[i + 1] == '*' -> {
                        blockCommentDepth++
                        i += 2
                        while (i < n && blockCommentDepth > 0) {
                            if (trimmed[i] == '/' && i + 1 < n && trimmed[i + 1] == '*') {
                                blockCommentDepth++
                                i += 2
                            } else if (trimmed[i] == '*' && i + 1 < n && trimmed[i + 1] == '/') {
                                blockCommentDepth--
                                i += 2
                            } else {
                                i++
                            }
                        }
                    }
                    ch == '"' && i + 2 < n && trimmed[i + 1] == '"' && trimmed[i + 2] == '"' -> {
                        val closeIdx = trimmed.indexOf("\"\"\"", startIndex = i + 3)
                        if (closeIdx >= 0) {
                            i = closeIdx + 3
                        } else {
                            inMultilineString = true
                            break
                        }
                    }
                    ch == '"' -> i = skipQuotedString(trimmed, i)
                    ch == '{' -> {
                        openDelta++
                        i++
                    }
                    ch == '}' -> {
                        openDelta--
                        i++
                    }
                    else -> i++
                }
            }
            depth = (lineDepth + openDelta).coerceAtLeast(0)
        }

        while (out.isNotEmpty() && out.last().isEmpty()) {
            out.removeAt(out.lastIndex)
        }
        return if (out.isEmpty()) "" else out.joinToString("\n", postfix = "\n")
    }

    private fun updateBlockCommentDepth(line: String, initialDepth: Int): Int {
        var d = initialDepth
        var i = 0
        val n = line.length
        while (i < n && d > 0) {
            if (line[i] == '/' && i + 1 < n && line[i + 1] == '*') {
                d++
                i += 2
            } else if (line[i] == '*' && i + 1 < n && line[i + 1] == '/') {
                d--
                i += 2
            } else {
                i++
            }
        }
        return d
    }

    fun stripPortAndBrackets(raw: String): String {
        val t = raw.trim()
        if (t.startsWith("[")) {
            val close = t.indexOf(']')
            if (close > 1) return t.substring(1, close)
        }
        val firstColon = t.indexOf(':')
        val lastColon = t.lastIndexOf(':')
        return if (firstColon > 0 && firstColon == lastColon && t.substring(lastColon + 1).all { it.isDigit() }) {
            t.substring(0, lastColon)
        } else {
            t
        }
    }

    fun isIpv4Literal(host: String): Boolean {
        val parts = host.split('.')
        if (parts.size != 4) return false
        return parts.all { p -> p.isNotEmpty() && p.all { it.isDigit() } && (p.toIntOrNull() in 0..255) }
    }

    fun isIpv6Literal(host: String): Boolean =
        host.contains(':') && host.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' }

    private fun isSafeKdlToken(token: String): Boolean =
        token.isNotEmpty() && token.length <= 64 && token.none { it == '"' || it == '\\' || it.isISOControl() || it.isWhitespace() }

    private fun readSavedDefaultOutbound(kdl: String): String? {
        val idx = kdl.indexOf(SAVED_DEFAULT_MARKER)
        if (idx < 0) return null
        val start = idx + SAVED_DEFAULT_MARKER.length
        val eol = kdl.indexOf('\n', start)
        val value = (if (eol >= 0) kdl.substring(start, eol) else kdl.substring(start)).trim()
        return value.takeIf { isSafeKdlToken(it) }
    }

    private fun findDefaultOutboundSpan(kdl: String): Pair<Int, Int>? {
        val routing = findTopLevelBlock(kdl, "routing") ?: return null
        val inner = kdl.substring(routing.first, routing.second)
        val dpos = inner.indexOf("default-outbound")
        if (dpos < 0) return null
        val q1 = inner.indexOf('"', dpos + 16)
        if (q1 < 0) return null
        val q2 = inner.indexOf('"', q1 + 1)
        if (q2 < 0) return null
        return (routing.first + q1 + 1) to (routing.first + q2)
    }

    /**
     * Finds a top-level KDL node block `keyword [props...] { ... }` in `text`,
     * skipping `//` and `/* */` comments, quoted strings, and nested `{ ... }` scopes.
     */
    internal fun findTopLevelBlock(text: String, keyword: String): Pair<Int, Int>? {
        var i = 0
        var depth = 0
        val n = text.length
        while (i < n) {
            val ch = text[i]
            when {
                ch == '/' && i + 1 < n && text[i + 1] == '/' -> {
                    i = skipLineComment(text, i)
                }
                ch == '/' && i + 1 < n && text[i + 1] == '*' -> {
                    i = skipBlockComment(text, i)
                }
                ch == '"' -> {
                    i = skipQuotedString(text, i)
                }
                ch == '{' -> {
                    depth++
                    i++
                }
                ch == '}' -> {
                    depth = (depth - 1).coerceAtLeast(0)
                    i++
                }
                depth == 0 && matchesKeywordAt(text, i, keyword) -> {
                    val open = findStatementOpenBrace(text, i + keyword.length)
                    if (open >= 0) {
                        val close = findMatchingBrace(text, open)
                        if (close >= 0) return open to close
                    }
                    i += keyword.length
                }
                else -> i++
            }
        }
        return null
    }

    private fun matchesKeywordAt(text: String, pos: Int, keyword: String): Boolean {
        if (!text.regionMatches(pos, keyword, 0, keyword.length)) return false
        val beforeOk = pos == 0 || text[pos - 1] == '\n' || text[pos - 1] == ';' || text[pos - 1].isWhitespace()
        val end = pos + keyword.length
        val afterOk = end == text.length || text[end] == '{' || text[end].isWhitespace()
        return beforeOk && afterOk
    }

    private fun findStatementOpenBrace(text: String, start: Int): Int {
        var i = start
        val n = text.length
        while (i < n) {
            val ch = text[i]
            when {
                ch == '\n' || ch == ';' -> return -1
                ch == '/' && i + 1 < n && text[i + 1] == '/' -> return -1
                ch == '/' && i + 1 < n && text[i + 1] == '*' -> i = skipBlockComment(text, i)
                ch == '"' -> i = skipQuotedString(text, i)
                ch == '{' -> return i
                else -> i++
            }
        }
        return -1
    }

    private fun findMatchingBrace(text: String, openPos: Int): Int {
        if (openPos < 0 || openPos >= text.length || text[openPos] != '{') return -1
        var depth = 0
        var i = openPos
        val n = text.length
        while (i < n) {
            val ch = text[i]
            when {
                ch == '/' && i + 1 < n && text[i + 1] == '/' -> i = skipLineComment(text, i)
                ch == '/' && i + 1 < n && text[i + 1] == '*' -> i = skipBlockComment(text, i)
                ch == '"' -> i = skipQuotedString(text, i)
                ch == '{' -> {
                    depth++
                    i++
                }
                ch == '}' -> {
                    depth--
                    if (depth == 0) return i
                    i++
                }
                else -> i++
            }
        }
        return -1
    }

    private fun skipLineComment(text: String, start: Int): Int {
        val nl = text.indexOf('\n', start + 2)
        return if (nl < 0) text.length else nl + 1
    }

    private fun skipBlockComment(text: String, start: Int): Int {
        var i = start + 2
        var nested = 1
        val n = text.length
        while (i < n && nested > 0) {
            if (text[i] == '/' && i + 1 < n && text[i + 1] == '*') {
                nested++
                i += 2
            } else if (text[i] == '*' && i + 1 < n && text[i + 1] == '/') {
                nested--
                i += 2
            } else {
                i++
            }
        }
        return i
    }

    private fun skipQuotedString(text: String, start: Int): Int {
        var i = start + 1
        var escaped = false
        val n = text.length
        while (i < n) {
            val ch = text[i]
            if (escaped) {
                escaped = false
            } else if (ch == '\\') {
                escaped = true
            } else if (ch == '"') {
                return i + 1
            }
            i++
        }
        return n
    }

    internal fun indentLines(block: String, indent: String): String =
        block.lineSequence().joinToString("\n", postfix = "\n") { line ->
            if (line.isBlank()) "" else indent + line
        }

    internal fun mergeRawSnippet(kdl: String, snippet: String): String {
        val clean = snippet.trim()
        if (clean.isEmpty()) return kdl
        val trimmed = kdl.trimEnd()
        return if (trimmed.isEmpty()) "$clean\n" else "$trimmed\n\n$clean\n"
    }
}
