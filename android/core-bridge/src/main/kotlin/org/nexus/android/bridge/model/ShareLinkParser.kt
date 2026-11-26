package org.nexus.android.bridge.model

import java.net.URLDecoder
import java.util.Base64

enum class OutboundScheme(val kdlType: String) {
    VLESS("vless"),
    TROJAN("trojan"),
    ANYTLS("anytls"),
    HYSTERIA2("hysteria2"),
    TUIC("tuic"),
    SNELL("snell"),
    SHADOWSOCKS("shadowsocks"),
    SSH("ssh"),
    NAIVE("naive"),
    HTTP_CONNECT("http-connect"),
}

data class ParsedOutbound(
    val scheme: OutboundScheme,
    val tag: String,
    val host: String,
    val port: Int,
    val secret: String,
    val username: String = "",
    val method: String = "",
    val sni: String = "",
    val fingerprint: String = "",
    val certificateSha256: String = "",
    val flow: String = "",
    val realityPublicKey: String = "",
    val realityShortId: String = "",
    val transport: String = "",
    val path: String = "",
    val hostHeader: String = "",
    val xhttpMode: String = "",
    val snellVersion: Int = 0,
    val obfs: String = "",
    val obfsHost: String = "",
    val congestionControl: String = "",
    val udpRelayMode: String = "",
    val privateKeyFile: String = "",
    val protocolName: String = "",
    val httpVersion: String = "",
    val padding: Boolean = false,
    val udp: Boolean = false,
)

/**
 * Parses standard proxy share URIs (vless://, trojan://, anytls://, hy2://, tuic://, snell://, ss://, ssh://)
 * and renders Nexus KDL 2.0 outbound blocks referencing private secret files (never inline credentials).
 */
object ShareLinkParser {
    fun parse(rawUri: String): Result<ParsedOutbound> = runCatching {
        val trimmed = rawUri.trim()
        val sep = trimmed.indexOf("://")
        require(sep > 0) { "Missing URI scheme" }
        val schemeStr = trimmed.substring(0, sep).lowercase()
        var naiveProto = ""
        val scheme = when (schemeStr) {
            "vless" -> OutboundScheme.VLESS
            "trojan" -> OutboundScheme.TROJAN
            "anytls" -> OutboundScheme.ANYTLS
            "hy2", "hysteria2" -> OutboundScheme.HYSTERIA2
            "tuic" -> OutboundScheme.TUIC
            "snell" -> OutboundScheme.SNELL
            "ss" -> OutboundScheme.SHADOWSOCKS
            "ssh" -> OutboundScheme.SSH
            "naive+https", "naive+h2" -> {
                naiveProto = "h2"
                OutboundScheme.NAIVE
            }
            "naive+quic", "naive+h3" -> {
                naiveProto = "h3"
                OutboundScheme.NAIVE
            }
            "https" -> OutboundScheme.HTTP_CONNECT
            else -> error("Unsupported URI scheme: $schemeStr")
        }

        var rest = trimmed.substring(sep + 3)
        val fragment = rest.indexOf('#').let { idx ->
            if (idx >= 0) {
                val frag = decodePercent(rest.substring(idx + 1))
                rest = rest.substring(0, idx)
                frag
            } else ""
        }
        val query = rest.indexOf('?').let { idx ->
            if (idx >= 0) {
                val q = parseQuery(rest.substring(idx + 1))
                rest = rest.substring(0, idx)
                q
            } else emptyMap()
        }

        val at = rest.lastIndexOf('@')
        val userinfo: String
        val host: String
        val port: Int
        if (at > 0) {
            userinfo = decodePercent(rest.substring(0, at))
            val hp = splitHostPort(rest.substring(at + 1).substringBefore('/'))
            host = hp.first
            port = hp.second
        } else {
            require(scheme == OutboundScheme.HTTP_CONNECT) { "Missing userinfo@host:port" }
            userinfo = ""
            val hp = splitHostPort(rest.substringBefore('/'))
            host = hp.first
            port = hp.second
        }
        val tag = sanitizeTag(fragment, "$schemeStr-$host")

        if (scheme == OutboundScheme.SHADOWSOCKS) {
            val decoded = if (userinfo.contains(':')) userinfo else decodeBase64Url(userinfo)
            val colon = decoded.indexOf(':')
            require(colon > 0 && colon + 1 < decoded.length) { "Invalid ss:// method:key" }
            return@runCatching ParsedOutbound(
                scheme = scheme,
                tag = tag,
                host = host,
                port = port,
                secret = decoded.substring(colon + 1),
                method = decoded.substring(0, colon),
            )
        }

        if (scheme != OutboundScheme.HTTP_CONNECT) require(userinfo.isNotEmpty()) { "Empty credential in share URI" }
        var username = ""
        var secret = userinfo
        if ((scheme == OutboundScheme.TUIC || scheme == OutboundScheme.NAIVE) && userinfo.contains(':')) {
            val colon = userinfo.indexOf(':')
            username = userinfo.substring(0, colon)
            secret = userinfo.substring(colon + 1)
            require(username.isNotEmpty() && secret.isNotEmpty()) { "Invalid user:password credential" }
        } else if (scheme == OutboundScheme.NAIVE) {
            error("naive:// requires user:password")
        } else if (scheme == OutboundScheme.SSH || scheme == OutboundScheme.HTTP_CONNECT) {
            if (userinfo.isNotEmpty()) {
                if (userinfo.contains(':')) {
                    val colon = userinfo.indexOf(':')
                    username = userinfo.substring(0, colon)
                    secret = userinfo.substring(colon + 1)
                } else {
                    username = userinfo
                    secret = ""
                }
                if (scheme == OutboundScheme.SSH) require(username.isNotEmpty()) { "Invalid ssh:// username" }
            }
        }
        val rawTransport = query["type"].orEmpty().lowercase()
        val transport = when (rawTransport) {
            "ws", "websocket" -> "websocket"
            "httpupgrade" -> "httpupgrade"
            "grpc" -> "grpc"
            "xhttp", "splithttp" -> "xhttp"
            else -> rawTransport
        }
        val certPin = query["host-key-sha256"] ?: query["host_key_sha256"]
            ?: query["certificate-sha256"] ?: query["pinSHA256"] ?: query["pcs"] ?: ""
        val snellVer = if (scheme == OutboundScheme.SNELL) {
            when (val rawVer = query["version"] ?: query["v"] ?: "") {
                "", "5" -> 5
                "4" -> 4
                else -> error("Unsupported snell version: $rawVer")
            }
        } else 0
        // Reject untrusted filesystem paths from share URIs (prevents arbitrary local file disclosure via ssh://).
        val privateKeyFile = ""
        val cipher = if (scheme == OutboundScheme.SSH) query["cipher"].orEmpty() else ""
        val padRaw = query["padding"]?.lowercase().orEmpty()
        val paddingEnabled = if (scheme == OutboundScheme.NAIVE) {
            padRaw != "0" && padRaw != "false" && padRaw != "off"
        } else false
        var httpVer = ""
        var enableUdp = false
        if (scheme == OutboundScheme.HTTP_CONNECT) {
            val hv = (query["http-version"] ?: query["ver"] ?: "").lowercase()
            httpVer = when {
                hv == "h3" || hv == "3" || query["h3"] == "1" || query["h3"] == "true" -> "h3"
                hv == "h2" || hv == "2" || query["h2"] == "1" || query["h2"] == "true" -> "h2"
                hv == "h1" || hv == "1.1" -> "h1"
                else -> "auto"
            }
            enableUdp = (query["udp"] == "1" || query["udp"] == "true") && httpVer == "h3"
        }
        ParsedOutbound(
            scheme = scheme,
            tag = tag,
            host = host,
            port = port,
            secret = secret,
            username = username,
            method = cipher,
            sni = query["sni"].orEmpty().ifEmpty { query["peer"].orEmpty().ifEmpty { host } },
            fingerprint = query["fp"].orEmpty(),
            certificateSha256 = certPin,
            flow = query["flow"].orEmpty(),
            realityPublicKey = query["pbk"].orEmpty(),
            realityShortId = query["sid"].orEmpty(),
            transport = transport,
            path = query["path"] ?: query["serviceName"] ?: query["service-name"].orEmpty(),
            hostHeader = query["host"] ?: query["authority"].orEmpty(),
            xhttpMode = query["mode"].orEmpty(),
            snellVersion = if (scheme == OutboundScheme.SNELL) snellVer else 0,
            obfs = query["obfs"].orEmpty(),
            obfsHost = query["obfs-host"] ?: query["obfs_host"].orEmpty(),
            congestionControl = query["congestion_control"] ?: query["cc"].orEmpty(),
            udpRelayMode = query["udp_relay_mode"].orEmpty(),
            privateKeyFile = privateKeyFile,
            protocolName = naiveProto,
            httpVersion = httpVer,
            padding = paddingEnabled,
            udp = enableUdp,
        )
    }

    fun renderKdlOutbound(node: ParsedOutbound, secretFilePath: String): String = buildString {
        appendLine("outbound ${q(node.tag)} type=${q(node.scheme.kdlType)} {")
        if (node.scheme == OutboundScheme.NAIVE) {
            appendLine("    protocol ${q(if (node.protocolName == "h3") "h3" else "h2")}")
            appendLine("    server host=${q(node.host)} port=${node.port}")
            appendLine("    authentication username=${q(node.username)} password-file=${q(secretFilePath)}")
            appendLine("    tls {")
            appendLine("        server-name ${q(node.sni)}")
            if (node.fingerprint.isNotEmpty()) appendLine("        fingerprint ${q(node.fingerprint)}")
            if (node.certificateSha256.isNotEmpty()) appendLine("        certificate-sha256 ${q(node.certificateSha256)}")
            appendLine("        verify #true")
            appendLine("    }")
            appendLine("    padding ${if (node.padding) "#true" else "#false"}")
            appendLine("}")
            return@buildString
        }
        if (node.scheme == OutboundScheme.HTTP_CONNECT) {
            if (node.httpVersion.isNotEmpty()) appendLine("    http-version ${q(node.httpVersion)}")
            appendLine("    server host=${q(node.host)} port=${node.port}")
            if (node.username.isNotEmpty() && secretFilePath.isNotEmpty()) {
                appendLine("    authentication username=${q(node.username)} password-file=${q(secretFilePath)}")
            }
            if (node.udp) appendLine("    udp #true")
            appendLine("    tls {")
            appendLine("        server-name ${q(node.sni)}")
            if (node.fingerprint.isNotEmpty()) appendLine("        fingerprint ${q(node.fingerprint)}")
            if (node.certificateSha256.isNotEmpty()) appendLine("        certificate-sha256 ${q(node.certificateSha256)}")
            appendLine("        verify #true")
            appendLine("    }")
            appendLine("}")
            return@buildString
        }
        appendLine("    server host=${q(node.host)} port=${node.port}")
        if (node.scheme == OutboundScheme.SSH) {
            if (node.username.isNotEmpty()) appendLine("    user ${q(node.username)}")
            if (node.secret.isNotEmpty() && secretFilePath.isNotEmpty()) {
                appendLine("    password-file ${q(secretFilePath)}")
            } else if (secretFilePath.isNotEmpty()) {
                appendLine("    private-key-file ${q(secretFilePath)}")
            }
            if (node.certificateSha256.isNotEmpty()) {
                appendLine("    host-key-sha256 ${q(node.certificateSha256)}")
            }
            if (node.method.isNotEmpty()) appendLine("    cipher ${q(node.method)}")
            appendLine("}")
            return@buildString
        }
        if (node.scheme == OutboundScheme.SHADOWSOCKS) {
            appendLine("    method ${q(node.method)}")
            appendLine("    key-file ${q(secretFilePath)}")
            appendLine("}")
            return@buildString
        }
        if (node.scheme == OutboundScheme.SNELL) {
            appendLine("    version ${if (node.snellVersion == 4) 4 else 5}")
            appendLine("    psk-file ${q(secretFilePath)}")
            if (node.obfs == "http") {
                appendLine("    obfs \"http\" {")
                if (node.obfsHost.isNotEmpty()) appendLine("        host ${q(node.obfsHost)}")
                appendLine("    }")
            }
            appendLine("}")
            return@buildString
        }
        when (node.scheme) {
            OutboundScheme.VLESS -> {
                appendLine("    authentication {")
                appendLine("        uuid-file ${q(secretFilePath)}")
                appendLine("    }")
                if (node.flow.isNotEmpty()) appendLine("    flow ${q(node.flow)}")
            }
            OutboundScheme.TUIC -> {
                appendLine("    authentication {")
                if (node.username.isNotEmpty()) appendLine("        uuid ${q(node.username)}")
                appendLine("        password-file ${q(secretFilePath)}")
                appendLine("    }")
                if (node.congestionControl.isNotEmpty()) appendLine("    congestion-control ${q(node.congestionControl)}")
                if (node.udpRelayMode.isNotEmpty()) appendLine("    udp-relay-mode ${q(node.udpRelayMode)}")
            }
            else -> {
                appendLine("    authentication {")
                appendLine("        password-file ${q(secretFilePath)}")
                appendLine("    }")
            }
        }
        appendLine("    tls {")
        appendLine("        server-name ${q(node.sni)}")
        if (node.fingerprint.isNotEmpty()) appendLine("        fingerprint ${q(node.fingerprint)}")
        if (node.certificateSha256.isNotEmpty()) appendLine("        certificate-sha256 ${q(node.certificateSha256)}")
        if (node.realityPublicKey.isNotEmpty()) {
            appendLine("        reality {")
            appendLine("            public-key ${q(node.realityPublicKey)}")
            if (node.realityShortId.isNotEmpty()) appendLine("            short-id ${q(node.realityShortId)}")
            appendLine("        }")
        }
        appendLine("    }")
        val supportsTransport = node.scheme == OutboundScheme.VLESS ||
            node.scheme == OutboundScheme.TROJAN || node.scheme == OutboundScheme.ANYTLS
        if (supportsTransport && node.transport.isNotEmpty() && node.transport != "tcp" && node.transport != "raw") {
            appendLine("    transport ${q(node.transport)} {")
            if (node.transport == "grpc") {
                if (node.path.isNotEmpty()) appendLine("        service-name ${q(node.path)}")
                if (node.hostHeader.isNotEmpty()) appendLine("        authority ${q(node.hostHeader)}")
            } else {
                if (node.path.isNotEmpty()) appendLine("        path ${q(node.path)}")
                if (node.hostHeader.isNotEmpty()) appendLine("        host ${q(node.hostHeader)}")
                if (node.transport == "xhttp" && node.xhttpMode.isNotEmpty()) {
                    appendLine("        mode ${q(node.xhttpMode)}")
                }
            }
            appendLine("    }")
        }
        appendLine("}")
    }

    private fun q(v: String): String = "\"${escapeKdlString(v)}\""

    private fun escapeKdlString(raw: String): String = buildString(raw.length) {
        for (ch in raw) {
            when (ch) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\n', '\r', '\t', '\u0008', '\u000C', '\u0085', '\u2028', '\u2029' -> Unit
                else -> if (ch.code >= 0x20 && ch.code != 0x7F) append(ch)
            }
        }
    }

    private fun decodePercent(s: String): String = URLDecoder.decode(s.replace("+", "%2B"), Charsets.UTF_8.name())

    private fun decodeBase64Url(s: String): String {
        val norm = s.replace('-', '+').replace('_', '/').let {
            it + "=".repeat((4 - it.length % 4) % 4)
        }
        return String(Base64.getDecoder().decode(norm), Charsets.UTF_8)
    }

    private fun parseQuery(q: String): Map<String, String> = q.split('&')
        .mapNotNull { part ->
            val idx = part.indexOf('=')
            if (idx <= 0) null else decodePercent(part.substring(0, idx)) to decodePercent(part.substring(idx + 1))
        }
        .toMap()

    private fun splitHostPort(hp: String): Pair<String, Int> {
        val isBracketed = hp.startsWith("[")
        val (host, portStr) = if (isBracketed) {
            val end = hp.indexOf(']')
            require(end > 1 && end + 2 <= hp.length && hp[end + 1] == ':') { "Invalid IPv6 host:port" }
            hp.substring(1, end) to hp.substring(end + 2)
        } else {
            val colon = hp.lastIndexOf(':')
            require(colon > 0) { "Missing server port" }
            hp.substring(0, colon) to hp.substring(colon + 1)
        }
        require(host.isNotEmpty() && host.length <= 253) { "Invalid server host" }
        for (ch in host) {
            val valid = ch.isLetterOrDigit() || ch == '.' || ch == '-' || ch == '_' || (isBracketed && (ch == ':' || ch == '%'))
            require(valid) { "Invalid character in server host" }
        }
        val port = portStr.toIntOrNull()
        require(port != null && port in 1..65535) { "Invalid server port: $portStr" }
        return host to port
    }

    private fun filterTagChars(raw: String): String = raw
        .map { if (it.isLetterOrDigit() || it == '-' || it == '_') it else if (it == ' ' || it == '.' || it == '+') '-' else '\u0000' }
        .filter { it != '\u0000' }
        .joinToString("")
        .trimStart('-')
        .take(48)

    private fun sanitizeTag(raw: String, fallback: String): String =
        filterTagChars(raw).ifEmpty { filterTagChars(fallback).ifEmpty { "node" } }
}
