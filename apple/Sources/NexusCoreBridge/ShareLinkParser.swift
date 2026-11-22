import Foundation

public enum OutboundScheme: String, Sendable {
    case vless
    case trojan
    case anytls
    case hysteria2
    case tuic
    case snell
    case shadowsocks
    case ssh
    case naive
    case httpConnect = "http-connect"
}

public struct ParsedOutbound: Sendable, Equatable {
    public let scheme: OutboundScheme
    public let tag: String
    public let host: String
    public let port: UInt16
    public let secret: String
    public let username: String
    public let method: String
    public let sni: String
    public let fingerprint: String
    public let certificateSha256: String
    public let flow: String
    public let realityPublicKey: String
    public let realityShortId: String
    public let transport: String
    public let path: String
    public let hostHeader: String
    public let xhttpMode: String
    public let snellVersion: Int
    public let obfs: String
    public let obfsHost: String
    public let congestionControl: String
    public let udpRelayMode: String
    public let privateKeyFile: String
    public let protocolName: String
    public let httpVersion: String
    public let padding: Bool
    public let udp: Bool
}

public enum ShareLinkError: Error, LocalizedError, Sendable {
    case missingScheme
    case unsupportedScheme(String)
    case invalidAuthority
    case invalidCredential

    public var errorDescription: String? {
        switch self {
        case .missingScheme: "Missing URI scheme"
        case .unsupportedScheme(let s): "Unsupported URI scheme: \(s)"
        case .invalidAuthority: "Invalid userinfo@host:port"
        case .invalidCredential: "Invalid or empty credential"
        }
    }
}

/// Parses standard proxy share URIs (vless://, trojan://, anytls://, hy2://, tuic://, snell://, ss://, ssh://)
/// and renders Nexus KDL 2.0 outbound blocks referencing private secret files (never inline credentials).
public enum ShareLinkParser {
    public static func parse(_ rawURI: String) throws -> ParsedOutbound {
        let trimmed = rawURI.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let sep = trimmed.range(of: "://") else { throw ShareLinkError.missingScheme }
        let schemeStr = String(trimmed[..<sep.lowerBound]).lowercased()
        let scheme: OutboundScheme
        var naiveProto = ""
        switch schemeStr {
        case "vless": scheme = .vless
        case "trojan": scheme = .trojan
        case "anytls": scheme = .anytls
        case "hy2", "hysteria2": scheme = .hysteria2
        case "tuic": scheme = .tuic
        case "snell": scheme = .snell
        case "ss": scheme = .shadowsocks
        case "ssh": scheme = .ssh
        case "naive+https", "naive+h2":
            scheme = .naive
            naiveProto = "h2"
        case "naive+quic", "naive+h3":
            scheme = .naive
            naiveProto = "h3"
        case "https":
            scheme = .httpConnect
        default: throw ShareLinkError.unsupportedScheme(schemeStr)
        }

        var rest = String(trimmed[sep.upperBound...])
        var fragment = ""
        if let hash = rest.firstIndex(of: "#") {
            fragment = String(rest[rest.index(after: hash)...]).removingPercentEncoding ?? ""
            rest = String(rest[..<hash])
        }
        var query: [String: String] = [:]
        if let q = rest.firstIndex(of: "?") {
            let queryStr = String(rest[rest.index(after: q)...])
            rest = String(rest[..<q])
            for pair in queryStr.split(separator: "&") {
                if let eq = pair.firstIndex(of: "=") {
                    let k = String(pair[..<eq]).removingPercentEncoding ?? String(pair[..<eq])
                    let v = String(pair[pair.index(after: eq)...]).removingPercentEncoding ?? ""
                    query[k] = v
                }
            }
        }
        if let slash = rest.firstIndex(of: "/") {
            rest = String(rest[..<slash])
        }

        let userinfo: String
        let host: String
        let port: UInt16
        if let at = rest.lastIndex(of: "@") {
            let rawUser = String(rest[..<at])
            userinfo = rawUser.removingPercentEncoding ?? rawUser
            (host, port) = try splitHostPort(String(rest[rest.index(after: at)...]))
        } else if scheme == .httpConnect {
            userinfo = ""
            (host, port) = try splitHostPort(rest)
        } else {
            throw ShareLinkError.invalidAuthority
        }
        let tag = sanitizeTag(fragment, fallback: "\(schemeStr)-\(host)")

        if scheme == .shadowsocks {
            let decoded: String
            if userinfo.contains(":") {
                decoded = userinfo
            } else {
                var b64 = userinfo.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
                let rem = b64.count % 4
                if rem != 0 { b64 += String(repeating: "=", count: 4 - rem) }
                guard let data = Data(base64Encoded: b64), let s = String(data: data, encoding: .utf8) else {
                    throw ShareLinkError.invalidCredential
                }
                decoded = s
            }
            guard let colon = decoded.firstIndex(of: ":"),
                  colon > decoded.startIndex,
                  decoded.index(after: colon) < decoded.endIndex
            else { throw ShareLinkError.invalidCredential }
            return ParsedOutbound(
                scheme: scheme, tag: tag, host: host, port: port,
                secret: String(decoded[decoded.index(after: colon)...]), username: "",
                method: String(decoded[..<colon]), sni: "", fingerprint: "", certificateSha256: "",
                flow: "", realityPublicKey: "", realityShortId: "",
                transport: "", path: "", hostHeader: "", xhttpMode: "",
                snellVersion: 0, obfs: "", obfsHost: "", congestionControl: "", udpRelayMode: "",
                privateKeyFile: "", protocolName: "", httpVersion: "", padding: false, udp: false
            )
        }

        if scheme != .httpConnect { guard !userinfo.isEmpty else { throw ShareLinkError.invalidCredential } }
        var username = ""
        var secret = userinfo
        if scheme == .tuic || scheme == .naive, let colon = userinfo.firstIndex(of: ":") {
            username = String(userinfo[..<colon])
            secret = String(userinfo[userinfo.index(after: colon)...])
            guard !username.isEmpty, !secret.isEmpty else { throw ShareLinkError.invalidCredential }
        } else if scheme == .naive {
            throw ShareLinkError.invalidCredential
        } else if scheme == .ssh || scheme == .httpConnect {
            if !userinfo.isEmpty {
                if let colon = userinfo.firstIndex(of: ":") {
                    username = String(userinfo[..<colon])
                    secret = String(userinfo[userinfo.index(after: colon)...])
                } else {
                    username = userinfo
                    secret = ""
                }
                if scheme == .ssh { guard !username.isEmpty else { throw ShareLinkError.invalidCredential } }
            }
        }
        let rawTransport = (query["type"] ?? "").lowercased()
        let transport: String = switch rawTransport {
        case "ws", "websocket": "websocket"
        case "httpupgrade": "httpupgrade"
        case "grpc": "grpc"
        case "xhttp", "splithttp": "xhttp"
        default: rawTransport
        }
        let certPin = query["host-key-sha256"] ?? query["host_key_sha256"]
            ?? query["certificate-sha256"] ?? query["pinSHA256"] ?? query["pcs"] ?? ""
        let snellVer = Int(query["version"] ?? query["v"] ?? "") ?? 5
        let privKeyFile = scheme == .ssh
            ? (query["private-key-file"] ?? query["private_key_file"] ?? query["private-key"] ?? query["key"] ?? "")
            : ""
        let cipher = scheme == .ssh ? (query["cipher"] ?? "") : ""
        let padVal = (query["padding"] ?? "1").lowercased()
        let paddingEnabled = scheme == .naive ? !(padVal == "0" || padVal == "false" || padVal == "off") : false
        var httpVer = ""
        var enableUdp = false
        if scheme == .httpConnect {
            let hv = (query["http-version"] ?? query["ver"] ?? "").lowercased()
            if hv == "h3" || hv == "3" || query["h3"] == "1" || query["h3"] == "true" { httpVer = "h3" }
            else if hv == "h2" || hv == "2" || query["h2"] == "1" || query["h2"] == "true" { httpVer = "h2" }
            else if hv == "h1" || hv == "1.1" { httpVer = "h1" }
            else { httpVer = "auto" }
            enableUdp = (query["udp"] == "1" || query["udp"] == "true") && httpVer == "h3"
        }
        return ParsedOutbound(
            scheme: scheme, tag: tag, host: host, port: port,
            secret: secret, username: username, method: cipher,
            sni: (query["sni"]?.isEmpty == false ? query["sni"]! : (query["peer"] ?? host)),
            fingerprint: query["fp"] ?? "",
            certificateSha256: certPin,
            flow: query["flow"] ?? "",
            realityPublicKey: query["pbk"] ?? "",
            realityShortId: query["sid"] ?? "",
            transport: transport,
            path: query["path"] ?? query["serviceName"] ?? query["service-name"] ?? "",
            hostHeader: query["host"] ?? query["authority"] ?? "",
            xhttpMode: query["mode"] ?? "",
            snellVersion: scheme == .snell ? snellVer : 0,
            obfs: query["obfs"] ?? "",
            obfsHost: query["obfs-host"] ?? query["obfs_host"] ?? "",
            congestionControl: query["congestion_control"] ?? query["cc"] ?? "",
            udpRelayMode: query["udp_relay_mode"] ?? "",
            privateKeyFile: privKeyFile,
            protocolName: naiveProto,
            httpVersion: httpVer,
            padding: paddingEnabled,
            udp: enableUdp
        )
    }

    public static func renderKdlOutbound(_ node: ParsedOutbound, secretFilePath: String) -> String {
        if node.scheme == .naive {
            var lines = [
                "outbound \(q(node.tag)) type=\"naive\" {",
                "    protocol \(q(node.protocolName == "h3" ? "h3" : "h2"))",
                "    server host=\(q(node.host)) port=\(node.port)",
                "    authentication username=\(q(node.username)) password-file=\(q(secretFilePath))",
                "    tls {",
                "        server-name \(q(node.sni))",
            ]
            if !node.fingerprint.isEmpty { lines.append("        fingerprint \(q(node.fingerprint))") }
            if !node.certificateSha256.isEmpty { lines.append("        certificate-sha256 \(q(node.certificateSha256))") }
            lines.append("        verify #true")
            lines.append("    }")
            lines.append("    padding \(node.padding ? "#true" : "#false")")
            lines.append("}")
            return lines.joined(separator: "\n") + "\n"
        }
        if node.scheme == .httpConnect {
            var lines = ["outbound \(q(node.tag)) type=\"http-connect\" {"]
            if !node.httpVersion.isEmpty { lines.append("    http-version \(q(node.httpVersion))") }
            lines.append("    server host=\(q(node.host)) port=\(node.port)")
            if !node.username.isEmpty, !secretFilePath.isEmpty {
                lines.append("    authentication username=\(q(node.username)) password-file=\(q(secretFilePath))")
            }
            if node.udp { lines.append("    udp #true") }
            lines.append("    tls {")
            lines.append("        server-name \(q(node.sni))")
            if !node.fingerprint.isEmpty { lines.append("        fingerprint \(q(node.fingerprint))") }
            if !node.certificateSha256.isEmpty { lines.append("        certificate-sha256 \(q(node.certificateSha256))") }
            lines.append("        verify #true")
            lines.append("    }")
            lines.append("}")
            return lines.joined(separator: "\n") + "\n"
        }
        var lines = [
            "outbound \(q(node.tag)) type=\(q(node.scheme.rawValue)) {",
            "    server host=\(q(node.host)) port=\(node.port)",
        ]
        if node.scheme == .ssh {
            if !node.username.isEmpty { lines.append("    user \(q(node.username))") }
            if !node.secret.isEmpty, !secretFilePath.isEmpty {
                lines.append("    password-file \(q(secretFilePath))")
            } else if !node.privateKeyFile.isEmpty {
                lines.append("    private-key-file \(q(node.privateKeyFile))")
            } else if !secretFilePath.isEmpty {
                lines.append("    private-key-file \(q(secretFilePath))")
            }
            if !node.certificateSha256.isEmpty {
                lines.append("    host-key-sha256 \(q(node.certificateSha256))")
            }
            if !node.method.isEmpty { lines.append("    cipher \(q(node.method))") }
            lines.append("}")
            return lines.joined(separator: "\n") + "\n"
        }
        if node.scheme == .shadowsocks {
            lines.append("    method \(q(node.method))")
            lines.append("    key-file \(q(secretFilePath))")
            lines.append("}")
            return lines.joined(separator: "\n") + "\n"
        }
        if node.scheme == .snell {
            lines.append("    version \(node.snellVersion == 4 ? 4 : 5)")
            lines.append("    psk-file \(q(secretFilePath))")
            if node.obfs == "http" {
                lines.append("    obfs \"http\" {")
                if !node.obfsHost.isEmpty { lines.append("        host \(q(node.obfsHost))") }
                lines.append("    }")
            }
            lines.append("}")
            return lines.joined(separator: "\n") + "\n"
        }
        if node.scheme == .vless {
            lines.append("    authentication {")
            lines.append("        uuid-file \(q(secretFilePath))")
            lines.append("    }")
            if !node.flow.isEmpty { lines.append("    flow \(q(node.flow))") }
        } else if node.scheme == .tuic {
            lines.append("    authentication {")
            if !node.username.isEmpty { lines.append("        uuid \(q(node.username))") }
            lines.append("        password-file \(q(secretFilePath))")
            lines.append("    }")
            if !node.congestionControl.isEmpty {
                lines.append("    congestion-control \(q(node.congestionControl))")
            }
            if !node.udpRelayMode.isEmpty {
                lines.append("    udp-relay-mode \(q(node.udpRelayMode))")
            }
        } else {
            lines.append("    authentication {")
            lines.append("        password-file \(q(secretFilePath))")
            lines.append("    }")
        }
        lines.append("    tls {")
        lines.append("        server-name \(q(node.sni))")
        if !node.fingerprint.isEmpty { lines.append("        fingerprint \(q(node.fingerprint))") }
        if !node.certificateSha256.isEmpty {
            lines.append("        certificate-sha256 \(q(node.certificateSha256))")
        }
        if !node.realityPublicKey.isEmpty {
            lines.append("        reality {")
            lines.append("            public-key \(q(node.realityPublicKey))")
            if !node.realityShortId.isEmpty { lines.append("            short-id \(q(node.realityShortId))") }
            lines.append("        }")
        }
        lines.append("    }")
        let supportsTransport = node.scheme == .vless || node.scheme == .trojan || node.scheme == .anytls
        if supportsTransport, !node.transport.isEmpty, node.transport != "tcp", node.transport != "raw" {
            lines.append("    transport \(q(node.transport)) {")
            if node.transport == "grpc" {
                if !node.path.isEmpty { lines.append("        service-name \(q(node.path))") }
                if !node.hostHeader.isEmpty { lines.append("        authority \(q(node.hostHeader))") }
            } else {
                if !node.path.isEmpty { lines.append("        path \(q(node.path))") }
                if !node.hostHeader.isEmpty { lines.append("        host \(q(node.hostHeader))") }
                if node.transport == "xhttp", !node.xhttpMode.isEmpty {
                    lines.append("        mode \(q(node.xhttpMode))")
                }
            }
            lines.append("    }")
        }
        lines.append("}")
        return lines.joined(separator: "\n") + "\n"
    }

    private static func q(_ v: String) -> String {
        let escaped = v.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: "\n", with: "")
        return "\"\(escaped)\""
    }

    private static func splitHostPort(_ hp: String) throws -> (String, UInt16) {
        let host: String
        let portStr: String
        if hp.hasPrefix("[") {
            guard let end = hp.firstIndex(of: "]"),
                  hp.index(after: end) < hp.endIndex,
                  hp[hp.index(after: end)] == ":"
            else { throw ShareLinkError.invalidAuthority }
            host = String(hp[hp.index(after: hp.startIndex)..<end])
            portStr = String(hp[hp.index(end, offsetBy: 2)...])
        } else {
            guard let colon = hp.lastIndex(of: ":") else { throw ShareLinkError.invalidAuthority }
            host = String(hp[..<colon])
            portStr = String(hp[hp.index(after: colon)...])
        }
        guard !host.isEmpty, let port = UInt16(portStr), port > 0 else {
            throw ShareLinkError.invalidAuthority
        }
        return (host, port)
    }

    private static func sanitizeTag(_ raw: String, fallback: String) -> String {
        let mapped = raw.compactMap { ch -> Character? in
            if ch.isASCII && (ch.isLetter || ch.isNumber || ch == "-" || ch == "_") { return ch }
            if ch == " " || ch == "." || ch == "+" { return "-" }
            return nil
        }
        let cleaned = String(mapped).drop(while: { $0 == "-" }).prefix(48)
        return cleaned.isEmpty ? fallback : String(cleaned)
    }
}
