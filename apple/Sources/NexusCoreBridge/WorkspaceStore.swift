import Foundation
#if canImport(Darwin)
import Darwin
#endif

public enum WorkspaceStoreError: Error, LocalizedError, Equatable, Sendable {
    case ioFailed(String)

    public var errorDescription: String? {
        switch self {
        case .ioFailed(let detail): return "Workspace storage I/O failed: \(detail)"
        }
    }
}

/// Swift 6 actor managing atomic `0600` persistence for Layer 1 canonical `workspace.json`.
public actor WorkspaceStore {
    public nonisolated let rootDirectory: URL
    public nonisolated let workspaceFileURL: URL

    public init(rootDirectory: URL, fileName: String = "workspace.json") {
        self.rootDirectory = rootDirectory
        self.workspaceFileURL = rootDirectory.appendingPathComponent(fileName)
    }

    public func loadOrInit() throws -> WorkspaceDocument {
        if !FileManager.default.fileExists(atPath: workspaceFileURL.path) {
            let initial = WorkspaceDocument(
                schemaVersion: WorkspaceDocument.currentSchemaVersion,
                revision: 1,
                updatedAtMs: Self.nowEpochMs(),
                routingProfiles: WorkspaceDocument.defaultRoutingProfiles()
            )
            return try save(initial, bumpRevision: false)
        }
        let text = try String(contentsOf: workspaceFileURL, encoding: .utf8)
        return try WorkspaceDocument.decodeCanonicalJSON(text)
    }

    @discardableResult
    public func save(_ doc: WorkspaceDocument, bumpRevision: Bool = true) throws -> WorkspaceDocument {
        var persisted = doc
        persisted.schemaVersion = WorkspaceDocument.currentSchemaVersion
        persisted.revision = bumpRevision ? max(1, doc.revision + 1) : max(1, doc.revision)
        persisted.updatedAtMs = Self.nowEpochMs()
        let encoded = try persisted.encodeCanonicalJSON(pretty: true)
        try Self.atomicWrite0600(data: Data(encoded.utf8), to: workspaceFileURL)
        return persisted
    }

    public func exportPortableJSON(_ doc: WorkspaceDocument? = nil) throws -> String {
        let target: WorkspaceDocument
        if let doc {
            target = doc
        } else {
            target = try loadOrInit()
        }
        return try target.encodeCanonicalJSON(pretty: true)
    }

    @discardableResult
    public func importPortableJSON(_ rawJSON: String, bumpRevision: Bool = true) throws -> WorkspaceDocument {
        let decoded = try WorkspaceDocument.decodeCanonicalJSON(rawJSON)
        return try save(decoded, bumpRevision: bumpRevision)
    }

    public static func sanitizeID(_ raw: String) -> String {
        var out = ""
        for ch in raw.lowercased() {
            if ch.isASCII && (ch.isLetter || ch.isNumber || ch == "-" || ch == "_") {
                out.append(ch)
            } else if ch == " " || ch == "." || ch == "/" {
                out.append("-")
            }
        }
        let trimmed = String(out.drop(while: { $0 == "-" }).prefix(48))
        return trimmed.isEmpty ? "prof" : trimmed
    }

    public static func newProfileID(prefix: String = "prof") -> String {
        "\(sanitizeID(prefix))-\(UUID().uuidString.prefix(8).lowercased())"
    }

    public static func makeUniqueID(_ base: String, existing: Set<String>) -> String {
        let clean = sanitizeID(base)
        var candidate = clean
        var suffix = 2
        while existing.contains(candidate) {
            candidate = "\(clean)-\(suffix)"
            suffix += 1
        }
        return candidate
    }

    /// Atomic POSIX `0600` write with `O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC` and `F_FULLFSYNC` on Darwin.
    public static func atomicWrite0600(data: Data, to destination: URL) throws {
        let parent = destination.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)

        #if canImport(Darwin)
        let tmpName = ".\(destination.lastPathComponent).tmp.\(UUID().uuidString)"
        let tmpURL = parent.appendingPathComponent(tmpName)
        let tmpPath = tmpURL.path
        let destPath = destination.path

        let fd = Darwin.open(tmpPath, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard fd >= 0 else {
            throw WorkspaceStoreError.ioFailed("open(\(tmpName)) errno=\(errno)")
        }
        var closed = false
        defer {
            if !closed { _ = Darwin.close(fd) }
        }
        guard Darwin.fchmod(fd, mode_t(0o600)) == 0 else {
            _ = Darwin.unlink(tmpPath)
            throw WorkspaceStoreError.ioFailed("fchmod errno=\(errno)")
        }
        if !data.isEmpty {
            try data.withUnsafeBytes { raw in
                guard let base = raw.baseAddress else { return }
                var written = 0
                while written < raw.count {
                    let n = Darwin.write(fd, base.advanced(by: written), raw.count - written)
                    if n < 0 && errno == EINTR { continue }
                    guard n > 0 else {
                        _ = Darwin.unlink(tmpPath)
                        throw WorkspaceStoreError.ioFailed("write errno=\(errno)")
                    }
                    written += n
                }
            }
        }
        _ = Darwin.fcntl(fd, F_FULLFSYNC)
        let closeRC = Darwin.close(fd)
        closed = true
        guard closeRC == 0 else {
            _ = Darwin.unlink(tmpPath)
            throw WorkspaceStoreError.ioFailed("close errno=\(errno)")
        }
        guard Darwin.rename(tmpPath, destPath) == 0 else {
            _ = Darwin.unlink(tmpPath)
            throw WorkspaceStoreError.ioFailed("rename errno=\(errno)")
        }
        #else
        try data.write(to: destination, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
        #endif
    }

    private static func nowEpochMs() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1000)
    }
}
