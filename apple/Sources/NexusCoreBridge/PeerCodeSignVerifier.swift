import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(Darwin)
import Darwin
#endif

public struct PeerIdentity: Sendable, Equatable {
    public let uid: uid_t
    public let pid: pid_t
    public let cdHashHex: String
}

public enum PeerVerificationError: Error, Sendable {
    case unsupportedPlatform
    case peerCredentialUnavailable(Int32)
    case uidMismatch(expected: uid_t, actual: uid_t)
    case codeSignInvalid(flags: UInt32)
    case cdHashMismatch
    case configDigestMismatch
}

/// Hardened macOS privileged daemon IPC authentication boundary (Stage A SMAppService.daemon).
/// Verifies peer UID, PID (LOCAL_PEERPID), hardened runtime signature flags, and CDHash via csops(),
/// plus SHA-256 config digest verification to defeat TOCTOU swaps.
public enum PeerCodeSignVerifier {
    private static let csOpsStatus: UInt32 = 0
    private static let csOpsCdHash: UInt32 = 5
    private static let csValid: UInt32 = 0x0000_0001
    private static let csRuntime: UInt32 = 0x0001_0000
    private static let localPeerPid: Int32 = 0x002

    #if os(macOS)
    @_silgen_name("csops")
    private static func darwinCsops(
        _ pid: pid_t,
        _ ops: UInt32,
        _ useraddr: UnsafeMutableRawPointer?,
        _ usersize: Int
    ) -> Int32
    #endif

    public static func verifyUnixPeer(
        fd: Int32,
        expectedUid: uid_t,
        allowedCdHashesHex: Set<String>
    ) throws -> PeerIdentity {
        #if os(macOS)
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard Darwin.getpeereid(fd, &uid, &gid) == 0 else {
            throw PeerVerificationError.peerCredentialUnavailable(errno)
        }
        guard uid == expectedUid else {
            throw PeerVerificationError.uidMismatch(expected: expectedUid, actual: uid)
        }

        var pid: pid_t = 0
        var pidLen = socklen_t(MemoryLayout<pid_t>.size)
        guard Darwin.getsockopt(fd, SOL_LOCAL, localPeerPid, &pid, &pidLen) == 0, pid > 0 else {
            throw PeerVerificationError.peerCredentialUnavailable(errno)
        }

        var flags: UInt32 = 0
        guard darwinCsops(pid, csOpsStatus, &flags, MemoryLayout<UInt32>.size) == 0 else {
            throw PeerVerificationError.peerCredentialUnavailable(errno)
        }
        let requiredFlags = csValid | csRuntime
        guard (flags & requiredFlags) == requiredFlags else {
            throw PeerVerificationError.codeSignInvalid(flags: flags)
        }

        var cdHash = [UInt8](repeating: 0, count: 20)
        guard darwinCsops(pid, csOpsCdHash, &cdHash, cdHash.count) == 0 else {
            throw PeerVerificationError.peerCredentialUnavailable(errno)
        }
        let hex = cdHash.map { String(format: "%02x", $0) }.joined()
        guard allowedCdHashesHex.isEmpty || allowedCdHashesHex.contains(hex) else {
            throw PeerVerificationError.cdHashMismatch
        }
        return PeerIdentity(uid: uid, pid: pid, cdHashHex: hex)
        #else
        throw PeerVerificationError.unsupportedPlatform
        #endif
    }

    public static func sha256Hex(_ data: Data) -> String {
        #if canImport(CryptoKit)
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        #else
        return ""
        #endif
    }

    public static func verifyConfigDigest(_ data: Data, expectedSha256Hex: String) throws {
        let actual = sha256Hex(data)
        guard !actual.isEmpty, actual.caseInsensitiveCompare(expectedSha256Hex) == .orderedSame else {
            throw PeerVerificationError.configDigestMismatch
        }
    }
}
