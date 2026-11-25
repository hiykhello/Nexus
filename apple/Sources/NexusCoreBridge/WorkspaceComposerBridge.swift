import Foundation

public enum WorkspaceBridgeError: Error, LocalizedError, Equatable, Sendable {
    case hookUnavailable(String)
    case emptyPassphrase
    case emptyProfileSelection
    case fullCustomKdlNotShareable(String)
    case invalidShareURI(String)
    case invalidEnvelopeFormat(String)
    case invalidJSON(String)
    case coreRejected(code: Int32, message: String)

    public var errorDescription: String? {
        switch self {
        case .hookUnavailable(let name): return "Embedded core hook unavailable: \(name)"
        case .emptyPassphrase: return "Sync passphrase must not be empty"
        case .emptyProfileSelection: return "At least one profile ID is required for share export"
        case .fullCustomKdlNotShareable(let id): return "full_custom_kdl profile '\(id)' cannot be exported via nexus://"
        case .invalidShareURI(let reason): return "Invalid nexus:// share URI: \(reason)"
        case .invalidEnvelopeFormat(let fmt): return "Unsupported sync envelope format: \(fmt)"
        case .invalidJSON(let detail): return "Malformed bridge JSON: \(detail)"
        case .coreRejected(let code, let message): return "Core bridge rejected request (\(code)): \(message)"
        }
    }
}

public struct WorkspaceComposeResult: Codable, Sendable, Equatable {
    public let ok: Bool
    public let activeTag: String
    public let selectorTag: String
    public let selectorMembers: [String]
    public let warnings: [String]
    public let errors: [String]
    public let secretFiles: [String]
    public let kdl: String

    enum CodingKeys: String, CodingKey {
        case ok, warnings, errors, kdl
        case activeTag = "active_tag"
        case selectorTag = "selector_tag"
        case selectorMembers = "selector_members"
        case secretFiles = "secret_files"
    }

    public init(
        ok: Bool,
        activeTag: String = "",
        selectorTag: String = "proxy",
        selectorMembers: [String] = [],
        warnings: [String] = [],
        errors: [String] = [],
        secretFiles: [String] = [],
        kdl: String = ""
    ) {
        self.ok = ok
        self.activeTag = activeTag
        self.selectorTag = selectorTag
        self.selectorMembers = selectorMembers
        self.warnings = warnings
        self.errors = errors
        self.secretFiles = secretFiles
        self.kdl = kdl
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.ok = try c.decodeIfPresent(Bool.self, forKey: .ok) ?? false
        self.activeTag = try c.decodeIfPresent(String.self, forKey: .activeTag) ?? ""
        self.selectorTag = try c.decodeIfPresent(String.self, forKey: .selectorTag) ?? "proxy"
        self.selectorMembers = try c.decodeIfPresent([String].self, forKey: .selectorMembers) ?? []
        self.warnings = try c.decodeIfPresent([String].self, forKey: .warnings) ?? []
        self.errors = try c.decodeIfPresent([String].self, forKey: .errors) ?? []
        self.secretFiles = try c.decodeIfPresent([String].self, forKey: .secretFiles) ?? []
        self.kdl = try c.decodeIfPresent(String.self, forKey: .kdl) ?? ""
    }
}

public struct WorkspaceShareExportResult: Codable, Sendable, Equatable {
    public let ok: Bool
    public let uri: String
    public let exportedCount: Int
    public let warnings: [String]
    public let errors: [String]

    enum CodingKeys: String, CodingKey {
        case ok, uri, warnings, errors
        case exportedCount = "exported_count"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.ok = try c.decodeIfPresent(Bool.self, forKey: .ok) ?? false
        self.uri = try c.decodeIfPresent(String.self, forKey: .uri) ?? ""
        self.exportedCount = try c.decodeIfPresent(Int.self, forKey: .exportedCount) ?? 0
        self.warnings = try c.decodeIfPresent([String].self, forKey: .warnings) ?? []
        self.errors = try c.decodeIfPresent([String].self, forKey: .errors) ?? []
    }
}

public struct WorkspaceShareImportResult: Codable, Sendable, Equatable {
    public let ok: Bool
    public let importedIds: [String]
    public let warnings: [String]
    public let errors: [String]
    public let workspaceJSON: String

    enum CodingKeys: String, CodingKey {
        case ok, warnings, errors
        case importedIds = "imported_ids"
        case workspaceJSON = "workspace_json"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.ok = try c.decodeIfPresent(Bool.self, forKey: .ok) ?? false
        self.importedIds = try c.decodeIfPresent([String].self, forKey: .importedIds) ?? []
        self.warnings = try c.decodeIfPresent([String].self, forKey: .warnings) ?? []
        self.errors = try c.decodeIfPresent([String].self, forKey: .errors) ?? []
        self.workspaceJSON = try c.decodeIfPresent(String.self, forKey: .workspaceJSON) ?? ""
    }
}

public struct WorkspaceSyncSealResult: Codable, Sendable, Equatable {
    public let ok: Bool
    public let revision: Int64
    public let updatedAtMs: Int64
    public let envelopeSha256: String
    public let warnings: [String]
    public let errors: [String]
    public let envelopeJSON: String

    enum CodingKeys: String, CodingKey {
        case ok, revision, warnings, errors
        case updatedAtMs = "updated_at_ms"
        case envelopeSha256 = "envelope_sha256"
        case envelopeJSON = "envelope_json"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.ok = try c.decodeIfPresent(Bool.self, forKey: .ok) ?? false
        self.revision = try c.decodeIfPresent(Int64.self, forKey: .revision) ?? 0
        self.updatedAtMs = try c.decodeIfPresent(Int64.self, forKey: .updatedAtMs) ?? 0
        self.envelopeSha256 = try c.decodeIfPresent(String.self, forKey: .envelopeSha256) ?? ""
        self.warnings = try c.decodeIfPresent([String].self, forKey: .warnings) ?? []
        self.errors = try c.decodeIfPresent([String].self, forKey: .errors) ?? []
        self.envelopeJSON = try c.decodeIfPresent(String.self, forKey: .envelopeJSON) ?? ""
    }
}

public struct WorkspaceSyncOpenResult: Codable, Sendable, Equatable {
    public let ok: Bool
    public let revision: Int64
    public let updatedAtMs: Int64
    public let deviceLabel: String
    public let warnings: [String]
    public let errors: [String]
    public let workspaceJSON: String

    enum CodingKeys: String, CodingKey {
        case ok, revision, warnings, errors
        case updatedAtMs = "updated_at_ms"
        case deviceLabel = "device_label"
        case workspaceJSON = "workspace_json"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.ok = try c.decodeIfPresent(Bool.self, forKey: .ok) ?? false
        self.revision = try c.decodeIfPresent(Int64.self, forKey: .revision) ?? 0
        self.updatedAtMs = try c.decodeIfPresent(Int64.self, forKey: .updatedAtMs) ?? 0
        self.deviceLabel = try c.decodeIfPresent(String.self, forKey: .deviceLabel) ?? ""
        self.warnings = try c.decodeIfPresent([String].self, forKey: .warnings) ?? []
        self.errors = try c.decodeIfPresent([String].self, forKey: .errors) ?? []
        self.workspaceJSON = try c.decodeIfPresent(String.self, forKey: .workspaceJSON) ?? ""
    }
}

/// Cleartext metadata header of a `nexus-sync-v1` E2EE envelope (`nexus-workspace-v1.enc`).
public struct WorkspaceSyncEnvelope: Codable, Sendable, Equatable {
    public static let expectedFormat = "nexus-sync-v1"

    public let format: String
    public let kdf: String
    public let kdfN: Int
    public let kdfR: Int
    public let kdfP: Int
    public let aead: String
    public let saltB64: String
    public let nonceB64: String
    public let revision: Int64
    public let updatedAtMs: Int64
    public let deviceLabel: String
    public let plaintextSha256: String
    public let ciphertextB64: String

    enum CodingKeys: String, CodingKey {
        case format, kdf, aead, revision
        case kdfN = "kdf_n"
        case kdfR = "kdf_r"
        case kdfP = "kdf_p"
        case saltB64 = "salt_b64"
        case nonceB64 = "nonce_b64"
        case updatedAtMs = "updated_at_ms"
        case deviceLabel = "device_label"
        case plaintextSha256 = "plaintext_sha256"
        case ciphertextB64 = "ciphertext_b64"
    }

    public static func decode(from jsonText: String) throws -> WorkspaceSyncEnvelope {
        guard let data = jsonText.data(using: .utf8) else {
            throw WorkspaceBridgeError.invalidJSON("envelope is not valid UTF-8")
        }
        let env: WorkspaceSyncEnvelope
        do {
            env = try JSONDecoder().decode(WorkspaceSyncEnvelope.self, from: data)
        } catch {
            throw WorkspaceBridgeError.invalidJSON(error.localizedDescription)
        }
        guard env.format == Self.expectedFormat else {
            throw WorkspaceBridgeError.invalidEnvelopeFormat(env.format)
        }
        return env
    }
}

/// Swift 6 actor bridging canonical Workspace composition, `nexus://` portable share bundles,
/// and `nexus-sync-v1` E2EE envelope seal/open through `EmbeddedCoreHooks`.
public actor WorkspaceComposerBridge {
    public static let shareURIPrefix = "nexus://share/v1/"
    public static let maxShareURIBytes = 256 * 1024

    private let hooks: EmbeddedCoreHooks

    public init(hooks: EmbeddedCoreHooks) {
        self.hooks = hooks
    }

    public func compose(
        workspace: WorkspaceDocument,
        host: AppleHostConfig,
        secretsDir: String,
        activeProfileID: String
    ) throws -> WorkspaceComposeResult {
        guard let hook = hooks.composeWorkspace else {
            throw WorkspaceBridgeError.hookUnavailable("composeWorkspace")
        }
        let wsJSON = try workspace.encodeCanonicalJSON(pretty: false)
        let hostJSON = try host.encodeCanonicalJSON(pretty: false)
        let raw = hook(wsJSON, hostJSON, secretsDir, activeProfileID)
        guard !raw.resultJSON.isEmpty else {
            throw WorkspaceBridgeError.coreRejected(code: raw.code, message: raw.errorMessage)
        }
        let decoded = try Self.decodeResult(WorkspaceComposeResult.self, from: raw.resultJSON)
        try Self.ensureFailClosed(code: raw.code, ok: decoded.ok, errors: decoded.errors, errorMessage: raw.errorMessage)
        return decoded
    }

    public func exportShare(
        workspace: WorkspaceDocument,
        profileIDs: [String]
    ) throws -> WorkspaceShareExportResult {
        guard !profileIDs.isEmpty else { throw WorkspaceBridgeError.emptyProfileSelection }
        let selectedSet = Set(profileIDs)
        for profile in workspace.profiles where selectedSet.contains(profile.id) && profile.kind == .fullCustomKdl {
            throw WorkspaceBridgeError.fullCustomKdlNotShareable(profile.id)
        }
        guard let hook = hooks.exportShare else {
            throw WorkspaceBridgeError.hookUnavailable("exportShare")
        }
        let wsJSON = try workspace.encodeCanonicalJSON(pretty: false)
        let raw = hook(wsJSON, profileIDs)
        guard !raw.resultJSON.isEmpty else {
            throw WorkspaceBridgeError.coreRejected(code: raw.code, message: raw.errorMessage)
        }
        let decoded = try Self.decodeResult(WorkspaceShareExportResult.self, from: raw.resultJSON)
        try Self.ensureFailClosed(code: raw.code, ok: decoded.ok, errors: decoded.errors, errorMessage: raw.errorMessage)
        return decoded
    }

    public func importShare(
        workspace: WorkspaceDocument,
        uri: String,
        subscriptionID: String = ""
    ) throws -> WorkspaceShareImportResult {
        let trimmed = uri.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix(Self.shareURIPrefix), trimmed.count > Self.shareURIPrefix.count else {
            throw WorkspaceBridgeError.invalidShareURI("must start with \(Self.shareURIPrefix)")
        }
        guard trimmed.utf8.count <= Self.maxShareURIBytes else {
            throw WorkspaceBridgeError.invalidShareURI("exceeds 256 KiB limit")
        }
        guard let hook = hooks.importShare else {
            throw WorkspaceBridgeError.hookUnavailable("importShare")
        }
        let wsJSON = try workspace.encodeCanonicalJSON(pretty: false)
        let raw = hook(wsJSON, trimmed, subscriptionID)
        guard !raw.resultJSON.isEmpty else {
            throw WorkspaceBridgeError.coreRejected(code: raw.code, message: raw.errorMessage)
        }
        let decoded = try Self.decodeResult(WorkspaceShareImportResult.self, from: raw.resultJSON)
        try Self.ensureFailClosed(code: raw.code, ok: decoded.ok, errors: decoded.errors, errorMessage: raw.errorMessage)
        return decoded
    }

    public func sealSync(
        workspace: WorkspaceDocument,
        passphrase: String,
        deviceLabel: String
    ) throws -> WorkspaceSyncSealResult {
        guard !passphrase.isEmpty else { throw WorkspaceBridgeError.emptyPassphrase }
        guard let hook = hooks.sealSync else {
            throw WorkspaceBridgeError.hookUnavailable("sealSync")
        }
        // Encode strictly canonical Layer 1 workspace JSON (zero host/telemetry/WebDAV creds).
        let wsJSON = try workspace.encodeCanonicalJSON(pretty: false)
        let raw = hook(wsJSON, passphrase, deviceLabel)
        guard !raw.resultJSON.isEmpty else {
            throw WorkspaceBridgeError.coreRejected(code: raw.code, message: raw.errorMessage)
        }
        let decoded = try Self.decodeResult(WorkspaceSyncSealResult.self, from: raw.resultJSON)
        try Self.ensureFailClosed(code: raw.code, ok: decoded.ok, errors: decoded.errors, errorMessage: raw.errorMessage)
        return decoded
    }

    public func openSync(
        envelopeJSON: String,
        passphrase: String
    ) throws -> WorkspaceSyncOpenResult {
        guard !passphrase.isEmpty else { throw WorkspaceBridgeError.emptyPassphrase }
        _ = try WorkspaceSyncEnvelope.decode(from: envelopeJSON)
        guard let hook = hooks.openSync else {
            throw WorkspaceBridgeError.hookUnavailable("openSync")
        }
        let raw = hook(envelopeJSON, passphrase)
        guard !raw.resultJSON.isEmpty else {
            throw WorkspaceBridgeError.coreRejected(code: raw.code, message: raw.errorMessage)
        }
        let decoded = try Self.decodeResult(WorkspaceSyncOpenResult.self, from: raw.resultJSON)
        try Self.ensureFailClosed(code: raw.code, ok: decoded.ok, errors: decoded.errors, errorMessage: raw.errorMessage)
        return decoded
    }

    private static func ensureFailClosed(
        code: Int32,
        ok: Bool,
        errors: [String],
        errorMessage: String
    ) throws {
        if code != 0 && (ok || errors.isEmpty) {
            let msg = errorMessage.isEmpty ? "core hook exited with code \(code)" : errorMessage
            throw WorkspaceBridgeError.coreRejected(code: code, message: msg)
        }
    }

    /// Mirrors `src/provider/workspace_detail.cppm::sanitize_tag` for live-switch tag parity.
    public static func sanitizeCoreTag(_ raw: String, fallback: String = "node") -> String {
        var out = ""
        for ch in raw {
            if ch.isASCII && (ch.isLetter || ch.isNumber || ch == "-" || ch == "_") {
                out.append(ch)
            } else if ch == " " || ch == "." || ch == "+" || ch == "/" {
                out.append("-")
            }
        }
        while out.first == "-" { out.removeFirst() }
        while out.last == "-" { out.removeLast() }
        if out.isEmpty { out = fallback }
        if out.count > 56 { out = String(out.prefix(56)) }
        if out == "direct" || out == "block" || out == "proxy" { out += "-node" }
        return out
    }

    private static func decodeResult<T: Decodable>(_ type: T.Type, from json: String) throws -> T {
        guard let data = json.data(using: .utf8) else {
            throw WorkspaceBridgeError.invalidJSON("non-UTF8 result")
        }
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw WorkspaceBridgeError.invalidJSON(error.localizedDescription)
        }
    }
}
