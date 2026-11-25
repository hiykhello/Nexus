import Foundation

public enum WebDavSyncError: Error, LocalizedError, Equatable, Sendable {
    case invalidEndpointURL(String)
    case insecureEndpoint(String)
    case invalidRemoteFileName(String)
    case unsafeCredentialCharacters
    case missingCredentials(String)
    case invalidResponse
    case httpStatus(Int, String)
    case sealFailed(String)
    case openFailed(String)

    public var errorDescription: String? {
        switch self {
        case .invalidEndpointURL(let url): return "Invalid WebDAV endpoint URL: \(url)"
        case .insecureEndpoint(let url): return "WebDAV requires HTTPS (non-loopback HTTP rejected): \(url)"
        case .invalidRemoteFileName(let name): return "Invalid WebDAV remote filename: \(name)"
        case .unsafeCredentialCharacters: return "WebDAV credentials contain forbidden CR/LF/NUL characters"
        case .missingCredentials(let field): return "Missing required WebDAV sync credential: \(field)"
        case .invalidResponse: return "Invalid HTTP response from WebDAV server"
        case .httpStatus(let code, let body): return "WebDAV HTTP \(code): \(body)"
        case .sealFailed(let msg): return "E2EE sync seal failed: \(msg)"
        case .openFailed(let msg): return "E2EE sync open failed: \(msg)"
        }
    }
}

/// Non-secret local WebDAV sync settings. Passwords and E2EE sync passphrases are NEVER stored here
/// (and NEVER inside `workspace.json`); use `WebDavKeychainCredentials` instead.
public struct WebDavSyncConfig: Codable, Sendable, Equatable {
    public var endpointURL: String
    public var remoteFileName: String
    public var username: String
    public var deviceLabel: String
    public var lastSyncedETag: String
    public var lastSyncedRevision: Int64

    enum CodingKeys: String, CodingKey {
        case username
        case endpointURL = "endpoint_url"
        case remoteFileName = "remote_file_name"
        case deviceLabel = "device_label"
        case lastSyncedETag = "last_synced_etag"
        case lastSyncedRevision = "last_synced_revision"
    }

    public init(
        endpointURL: String = "",
        remoteFileName: String = "nexus-workspace-v1.enc",
        username: String = "",
        deviceLabel: String = "Apple",
        lastSyncedETag: String = "",
        lastSyncedRevision: Int64 = 0
    ) {
        self.endpointURL = endpointURL
        self.remoteFileName = remoteFileName
        self.username = username
        self.deviceLabel = deviceLabel
        self.lastSyncedETag = lastSyncedETag
        self.lastSyncedRevision = lastSyncedRevision
    }
}

/// Keychain-backed secret storage for WebDAV password and E2EE sync passphrase (never touches `workspace.json`).
public struct WebDavKeychainCredentials: Sendable {
    public let webDavPasswordStore: KeychainTokenStore
    public let syncPassphraseStore: KeychainTokenStore

    public init(service: String = "org.nexus.apple.sync", accessGroup: String? = nil) {
        self.webDavPasswordStore = KeychainTokenStore(service: service, account: "webdav-password", accessGroup: accessGroup)
        self.syncPassphraseStore = KeychainTokenStore(service: service, account: "e2ee-passphrase", accessGroup: accessGroup)
    }

    public func saveWebDavPassword(_ password: String) -> Bool { webDavPasswordStore.saveToken(password) }
    public func loadWebDavPassword() -> String? { webDavPasswordStore.loadToken() }
    public func deleteWebDavPassword() { webDavPasswordStore.deleteToken() }

    public func saveSyncPassphrase(_ passphrase: String) -> Bool { syncPassphraseStore.saveToken(passphrase) }
    public func loadSyncPassphrase() -> String? { syncPassphraseStore.loadToken() }
    public func deleteSyncPassphrase() { syncPassphraseStore.deleteToken() }

    public func clearAll() {
        webDavPasswordStore.deleteToken()
        syncPassphraseStore.deleteToken()
    }
}

public struct WebDavRemoteProbe: Sendable, Equatable {
    public let exists: Bool
    public let etag: String
    public let contentLength: Int64?

    public init(exists: Bool, etag: String = "", contentLength: Int64? = nil) {
        self.exists = exists
        self.etag = etag
        self.contentLength = contentLength
    }
}

public enum WebDavSyncOutcome: Sendable, Equatable {
    case pushed(revision: Int64, etag: String)
    case pulled(workspace: WorkspaceDocument, revision: Int64, deviceLabel: String, etag: String, backupURL: URL?)
    case conflict(remoteRevision: Int64, remoteDevice: String, remoteETag: String)
    case noRemoteSnapshot
}

public typealias WebDavTransport = @Sendable (URLRequest) async throws -> (Data, HTTPURLResponse)

/// Refuses HTTP redirects on WebDAV requests to prevent HTTPS->HTTP downgrade or Basic Auth leakage.
///
/// Concurrency invariant (`@unchecked Sendable`): holds zero stored or mutable state;
/// `NSObject` is non-Sendable in Swift 6 strict concurrency, so `@unchecked Sendable` is required.
private final class NoRedirectSessionDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

/// Swift 6 actor implementing strict-HTTPS, ETag- and revision-conflict-aware WebDAV E2EE sync
/// (`MKCOL` / `HEAD` / `GET` / `PUT` with `If-Match` / `If-None-Match`) backed by `URLSession`.
public actor WebDavSyncClient {
    private let ownedSession: URLSession?
    private let transport: WebDavTransport

    public init(timeoutSeconds: TimeInterval = 15.0) {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeoutSeconds
        config.timeoutIntervalForResource = timeoutSeconds
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.httpShouldSetCookies = false
        let session = URLSession(configuration: config)
        let delegate = NoRedirectSessionDelegate()
        self.ownedSession = session
        self.transport = { request in
            let (data, response) = try await session.data(for: request, delegate: delegate)
            guard let http = response as? HTTPURLResponse else {
                throw WebDavSyncError.invalidResponse
            }
            return (data, http)
        }
    }

    public init(transport: @escaping WebDavTransport) {
        self.ownedSession = nil
        self.transport = transport
    }

    deinit {
        ownedSession?.finishTasksAndInvalidate()
    }

    public static func validateEndpointURL(_ raw: String) throws -> URL {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let url = URL(string: trimmed), let scheme = url.scheme?.lowercased(), let host = url.host?.lowercased(), !host.isEmpty else {
            throw WebDavSyncError.invalidEndpointURL(raw)
        }
        if scheme == "https" {
            return url
        }
        if scheme == "http" && (host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]") {
            return url
        }
        throw WebDavSyncError.insecureEndpoint(raw)
    }

    public static func resolveRemoteFileURL(config: WebDavSyncConfig) throws -> (collection: URL, file: URL) {
        let base = try validateEndpointURL(config.endpointURL)
        let name = config.remoteFileName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty,
              name != ".",
              !name.contains("/"),
              !name.contains("\\"),
              !name.contains(".."),
              !name.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F })
        else {
            throw WebDavSyncError.invalidRemoteFileName(config.remoteFileName)
        }
        let baseStr = base.absoluteString
        let collectionStr = baseStr.hasSuffix("/") ? baseStr : baseStr + "/"
        guard let collection = URL(string: collectionStr) else {
            throw WebDavSyncError.invalidEndpointURL(config.endpointURL)
        }
        return (collection, collection.appendingPathComponent(name, isDirectory: false))
    }

    public func headRemote(config: WebDavSyncConfig, webDavPassword: String) async throws -> WebDavRemoteProbe {
        let (_, fileURL) = try Self.resolveRemoteFileURL(config: config)
        let req = try Self.buildRequest(method: "HEAD", url: fileURL, username: config.username, password: webDavPassword)
        let (data, http) = try await transport(req)
        if http.statusCode == 404 {
            return WebDavRemoteProbe(exists: false)
        }
        guard (200..<300).contains(http.statusCode) else {
            throw WebDavSyncError.httpStatus(http.statusCode, String(decoding: data, as: UTF8.self))
        }
        let etag = Self.extractETag(from: http)
        let len = http.value(forHTTPHeaderField: "Content-Length").flatMap(Int64.init)
        return WebDavRemoteProbe(exists: true, etag: etag, contentLength: len)
    }

    public func ensureCollection(config: WebDavSyncConfig, webDavPassword: String) async throws {
        let (collectionURL, _) = try Self.resolveRemoteFileURL(config: config)
        let req = try Self.buildRequest(method: "MKCOL", url: collectionURL, username: config.username, password: webDavPassword)
        let (data, http) = try await transport(req)
        // 201 Created, 200 OK, 301/405 already exists on standard WebDAV servers.
        let allowed: Set<Int> = [200, 201, 204, 301, 405]
        guard allowed.contains(http.statusCode) else {
            throw WebDavSyncError.httpStatus(http.statusCode, String(decoding: data, as: UTF8.self))
        }
    }

    public func pushEncryptedWorkspace(
        workspace: WorkspaceDocument,
        config: WebDavSyncConfig,
        webDavPassword: String,
        syncPassphrase: String,
        bridge: WorkspaceComposerBridge,
        forceOverwrite: Bool = false
    ) async throws -> WebDavSyncOutcome {
        guard !syncPassphrase.isEmpty else { throw WebDavSyncError.missingCredentials("syncPassphrase") }
        let (_, fileURL) = try Self.resolveRemoteFileURL(config: config)

        let probe = try await headRemote(config: config, webDavPassword: webDavPassword)
        if probe.exists && !forceOverwrite {
            let etagChanged = !config.lastSyncedETag.isEmpty && !probe.etag.isEmpty && probe.etag != config.lastSyncedETag
            let unseenRemote = config.lastSyncedETag.isEmpty && config.lastSyncedRevision == 0
            let missingETagCheck = probe.etag.isEmpty || config.lastSyncedETag.isEmpty
            if etagChanged || unseenRemote || missingETagCheck {
                let remoteMeta = try await fetchRemoteConflictMetadata(
                    fileURL: fileURL,
                    username: config.username,
                    password: webDavPassword,
                    fallbackETag: probe.etag
                )
                if !remoteMeta.valid || etagChanged || unseenRemote || remoteMeta.revision > config.lastSyncedRevision {
                    return .conflict(
                        remoteRevision: remoteMeta.revision,
                        remoteDevice: remoteMeta.deviceLabel,
                        remoteETag: remoteMeta.etag
                    )
                }
            }
        }

        let sealed = try await bridge.sealSync(
            workspace: workspace,
            passphrase: syncPassphrase,
            deviceLabel: config.deviceLabel
        )
        guard sealed.ok, !sealed.envelopeJSON.isEmpty else {
            throw WebDavSyncError.sealFailed(sealed.errors.first ?? "seal returned ok=false")
        }

        try await ensureCollection(config: config, webDavPassword: webDavPassword)

        var putReq = try Self.buildRequest(
            method: "PUT",
            url: fileURL,
            username: config.username,
            password: webDavPassword,
            body: Data(sealed.envelopeJSON.utf8),
            contentType: "application/json"
        )
        if !forceOverwrite {
            if !probe.exists {
                putReq.setValue("*", forHTTPHeaderField: "If-None-Match")
            } else if !config.lastSyncedETag.isEmpty {
                putReq.setValue(config.lastSyncedETag, forHTTPHeaderField: "If-Match")
            }
        }

        let (putData, putHTTP) = try await transport(putReq)
        if putHTTP.statusCode == 412 {
            let remoteMeta = try await fetchRemoteConflictMetadata(
                fileURL: fileURL,
                username: config.username,
                password: webDavPassword,
                fallbackETag: ""
            )
            return .conflict(
                remoteRevision: remoteMeta.revision,
                remoteDevice: remoteMeta.deviceLabel,
                remoteETag: remoteMeta.etag
            )
        }
        guard (200..<300).contains(putHTTP.statusCode) else {
            throw WebDavSyncError.httpStatus(putHTTP.statusCode, String(decoding: putData, as: UTF8.self))
        }

        var nextETag = Self.extractETag(from: putHTTP)
        if nextETag.isEmpty {
            nextETag = (try? await headRemote(config: config, webDavPassword: webDavPassword).etag) ?? ""
        }
        return .pushed(revision: sealed.revision, etag: nextETag)
    }

    public func pullEncryptedWorkspace(
        localWorkspace: WorkspaceDocument?,
        config: WebDavSyncConfig,
        webDavPassword: String,
        syncPassphrase: String,
        bridge: WorkspaceComposerBridge,
        backupDirectory: URL? = nil,
        forceOverwrite: Bool = false
    ) async throws -> WebDavSyncOutcome {
        guard !syncPassphrase.isEmpty else { throw WebDavSyncError.missingCredentials("syncPassphrase") }
        let (_, fileURL) = try Self.resolveRemoteFileURL(config: config)

        let getReq = try Self.buildRequest(method: "GET", url: fileURL, username: config.username, password: webDavPassword)
        let (data, http) = try await transport(getReq)
        if http.statusCode == 404 {
            return .noRemoteSnapshot
        }
        guard (200..<300).contains(http.statusCode) else {
            throw WebDavSyncError.httpStatus(http.statusCode, String(decoding: data, as: UTF8.self))
        }

        let remoteETag = Self.extractETag(from: http)
        let envelopeJSON = String(decoding: data, as: UTF8.self)
        let meta = try WorkspaceSyncEnvelope.decode(from: envelopeJSON)

        if !forceOverwrite, let local = localWorkspace {
            let localAhead = local.revision > meta.revision
            let localEdited = local.revision > config.lastSyncedRevision
            let remoteChangedByETag = !config.lastSyncedETag.isEmpty
                && !remoteETag.isEmpty
                && remoteETag != config.lastSyncedETag
            let remoteChangedByRevision = config.lastSyncedRevision > 0 && meta.revision != config.lastSyncedRevision
            let diverged = localEdited && (remoteChangedByETag || remoteChangedByRevision)
            if localAhead || diverged {
                return .conflict(remoteRevision: meta.revision, remoteDevice: meta.deviceLabel, remoteETag: remoteETag)
            }
        }

        let opened = try await bridge.openSync(envelopeJSON: envelopeJSON, passphrase: syncPassphrase)
        guard opened.ok, !opened.workspaceJSON.isEmpty else {
            throw WebDavSyncError.openFailed(opened.errors.first ?? "open returned ok=false")
        }
        let decodedWorkspace = try WorkspaceDocument.decodeCanonicalJSON(opened.workspaceJSON)

        var backupURL: URL?
        if let backupDirectory, let local = localWorkspace {
            let ts = Int64(Date().timeIntervalSince1970 * 1000)
            let dest = backupDirectory.appendingPathComponent("workspace-backup-\(ts).json")
            let rawLocal = try local.encodeCanonicalJSON(pretty: true)
            try WorkspaceStore.atomicWrite0600(data: Data(rawLocal.utf8), to: dest)
            backupURL = dest
        }

        return .pulled(
            workspace: decodedWorkspace,
            revision: opened.revision,
            deviceLabel: opened.deviceLabel.isEmpty ? meta.deviceLabel : opened.deviceLabel,
            etag: remoteETag,
            backupURL: backupURL
        )
    }

    private func fetchRemoteConflictMetadata(
        fileURL: URL,
        username: String,
        password: String,
        fallbackETag: String
    ) async throws -> (revision: Int64, deviceLabel: String, etag: String, valid: Bool) {
        let getReq = try Self.buildRequest(method: "GET", url: fileURL, username: username, password: password)
        guard let (data, http) = try? await transport(getReq), (200..<300).contains(http.statusCode) else {
            return (0, "", fallbackETag, false)
        }
        let etag = Self.extractETag(from: http)
        let effectiveETag = etag.isEmpty ? fallbackETag : etag
        if let env = try? WorkspaceSyncEnvelope.decode(from: String(decoding: data, as: UTF8.self)) {
            return (env.revision, env.deviceLabel, effectiveETag, true)
        }
        return (0, "", effectiveETag, false)
    }

    private static func buildRequest(
        method: String,
        url: URL,
        username: String,
        password: String,
        body: Data? = nil,
        contentType: String? = nil
    ) throws -> URLRequest {
        if hasControlChars(username) || hasControlChars(password) {
            throw WebDavSyncError.unsafeCredentialCharacters
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        if !username.isEmpty || !password.isEmpty {
            let token = Data("\(username):\(password)".utf8).base64EncodedString()
            request.setValue("Basic \(token)", forHTTPHeaderField: "Authorization")
        }
        if let contentType {
            request.setValue(contentType, forHTTPHeaderField: "Content-Type")
        }
        request.httpBody = body
        return request
    }

    private static func extractETag(from response: HTTPURLResponse) -> String {
        (response.value(forHTTPHeaderField: "ETag") ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func hasControlChars(_ text: String) -> Bool {
        text.unicodeScalars.contains { $0.value == 0 || $0.value == 0x0A || $0.value == 0x0D }
    }
}
