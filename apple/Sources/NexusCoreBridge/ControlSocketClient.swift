import Foundation
#if canImport(Darwin)
import Darwin
#endif

public enum ControlSocketError: Error, LocalizedError, Sendable {
    case invalidRequest
    case pathTooLong(Int)
    case socketFailed(Int32)
    case connectFailed(Int32)
    case ioFailed(Int32)
    case replyTooLarge

    public var errorDescription: String? {
        switch self {
        case .invalidRequest: return "Invalid NEXUS/1 control request"
        case .pathTooLong(let len): return "Unix socket path length \(len) exceeds macOS 104-byte sun_path limit"
        case .socketFailed(let code): return "socket() failed with errno \(code)"
        case .connectFailed(let code): return "connect() failed with errno \(code)"
        case .ioFailed(let code): return "socket I/O failed with errno \(code)"
        case .replyTooLarge: return "Control reply exceeded 64 KiB limit"
        }
    }
}

/// Pure POSIX AF_UNIX client speaking Nexus's NEXUS/1 NUL-delimited control protocol.
public struct ControlSocketClient: Sendable {
    /// macOS sockaddr_un.sun_path is 104 bytes (shorter than Linux's 108 bytes).
    public static let maxUnixPathBytes = 104
    public static let maxRequestBytes = 1024
    public static let maxReplyBytes = 65_536

    public let socketPath: String
    public let timeoutSeconds: Int

    public init(socketPath: String, timeoutSeconds: Int = 2) {
        self.socketPath = socketPath
        self.timeoutSeconds = max(1, timeoutSeconds)
    }

    public static func buildFrame(_ tokens: [String]) throws -> Data {
        guard !tokens.isEmpty else { throw ControlSocketError.invalidRequest }
        for token in tokens {
            if token.isEmpty || token.utf8.contains(0) {
                throw ControlSocketError.invalidRequest
            }
        }
        let wire = "NEXUS/1 " + tokens.joined(separator: "\0")
        let data = Data(wire.utf8)
        guard data.count <= maxRequestBytes else { throw ControlSocketError.invalidRequest }
        return data
    }

    public static func validateSocketPath(_ path: String) throws {
        let count = path.utf8.count
        guard path.hasPrefix("/"), count > 1, !path.hasSuffix("/"), !path.utf8.contains(0) else {
            throw ControlSocketError.invalidRequest
        }
        guard count < maxUnixPathBytes else {
            throw ControlSocketError.pathTooLong(count)
        }
    }

    public func request(_ tokens: [String]) throws -> String {
        try Self.validateSocketPath(socketPath)
        let frame = try Self.buildFrame(tokens)

        #if canImport(Darwin)
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw ControlSocketError.socketFailed(errno) }
        defer { Darwin.close(fd) }

        var noSigPipe: Int32 = 1
        _ = Darwin.setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))

        var tv = timeval(tv_sec: timeoutSeconds, tv_usec: 0)
        _ = Darwin.setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        _ = Darwin.setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            for (idx, b) in pathBytes.enumerated() {
                raw[idx] = b
            }
        }
        let addrLen = socklen_t(MemoryLayout<sockaddr_un>.offset(of: \.sun_path)! + pathBytes.count + 1)
        let rc = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.connect(fd, sa, addrLen)
            }
        }
        guard rc == 0 else { throw ControlSocketError.connectFailed(errno) }

        try frame.withUnsafeBytes { raw in
            var sent = 0
            while sent < raw.count {
                let n = Darwin.send(fd, raw.baseAddress!.advanced(by: sent), raw.count - sent, 0)
                guard n > 0 else { throw ControlSocketError.ioFailed(errno) }
                sent += n
            }
        }
        _ = Darwin.shutdown(fd, SHUT_WR)

        var out = Data()
        var buf = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = Darwin.recv(fd, &buf, buf.count, 0)
            if n == 0 { break }
            guard n > 0 else { throw ControlSocketError.ioFailed(errno) }
            if out.count + n > Self.maxReplyBytes { throw ControlSocketError.replyTooLarge }
            out.append(contentsOf: buf[0..<n])
        }
        return String(decoding: out, as: UTF8.self)
        #else
        throw ControlSocketError.socketFailed(ENOTSUP)
        #endif
    }

    public func status() throws -> String { try request(["status"]) }
    public func reload() throws -> String { try request(["reload"]) }
    public func setLogLevel(_ level: String) throws -> String { try request(["log-level", level]) }
    public func selectOutbound(group: String, member: String) throws -> String {
        try request(["select", group, member])
    }
    public func resetGroupAuto(group: String) throws -> String {
        try request(["select", group, "--auto"])
    }
    public func notifyNetworkChange(generation: UInt64) throws -> String {
        try request(["network-change", String(generation)])
    }
}

/// Dedicated actor serializing blocking AF_UNIX control I/O off the MainActor
/// without requiring unstructured Task.detached calls from SwiftUI views.
public actor ControlSocketSession {
    private let client: ControlSocketClient

    public init(socketPath: String, timeoutSeconds: Int = 2) {
        self.client = ControlSocketClient(socketPath: socketPath, timeoutSeconds: timeoutSeconds)
    }

    public func status() throws -> String { try client.status() }
    public func reload() throws -> String { try client.reload() }
    public func setLogLevel(_ level: String) throws -> String { try client.setLogLevel(level) }
    public func selectOutbound(group: String, member: String) throws -> String {
        try client.selectOutbound(group: group, member: member)
    }
    public func resetGroupAuto(group: String) throws -> String {
        try client.resetGroupAuto(group: group)
    }
    public func notifyNetworkChange(generation: UInt64) throws -> String {
        try client.notifyNetworkChange(generation: generation)
    }
}
