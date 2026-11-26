import Foundation
import XCTest
@testable import NexusCoreBridge

private actor MockWebDavServer {
    struct Entry {
        var data: Data
        var etag: String
    }

    var collectionCreated = false
    var files: [String: Entry] = [:]
    var lastAuthorizationHeader: String?
    var lastIfMatchHeader: String?
    var forceNextPut412 = false

    func seed(path: String, json: String, etag: String) {
        files[path] = Entry(data: Data(json.utf8), etag: etag)
    }

    func setForceNextPut412(_ value: Bool) {
        forceNextPut412 = value
    }

    func handle(_ request: URLRequest) -> (Data, HTTPURLResponse) {
        let url = request.url ?? URL(string: "http://127.0.0.1:8080/")!
        let method = request.httpMethod ?? "GET"
        let path = url.path
        lastAuthorizationHeader = request.value(forHTTPHeaderField: "Authorization")
        lastIfMatchHeader = request.value(forHTTPHeaderField: "If-Match")

        func respond(_ status: Int, body: Data = Data(), headers: [String: String] = [:]) -> (Data, HTTPURLResponse) {
            let http = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
            return (body, http)
        }

        switch method {
        case "MKCOL":
            let existed = collectionCreated
            collectionCreated = true
            return respond(existed ? 405 : 201)
        case "HEAD":
            guard let entry = files[path] else { return respond(404) }
            return respond(200, headers: ["ETag": entry.etag, "Content-Length": "\(entry.data.count)"])
        case "GET":
            guard let entry = files[path] else { return respond(404) }
            return respond(200, body: entry.data, headers: ["ETag": entry.etag])
        case "PUT":
            if forceNextPut412 {
                forceNextPut412 = false
                return respond(412)
            }
            if let ifMatch = request.value(forHTTPHeaderField: "If-Match"),
               let existing = files[path],
               existing.etag != ifMatch {
                return respond(412)
            }
            let nextTag = "\"etag-\(files.count + 1)-\(Int.random(in: 1000...9999))\""
            files[path] = Entry(data: request.httpBody ?? Data(), etag: nextTag)
            return respond(201, headers: ["ETag": nextTag])
        default:
            return respond(405)
        }
    }
}

final class WorkspaceAndSyncTests: XCTestCase {
    private func makeTempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nexus-apple-ws-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func makeSampleNode(id: String, remarks: String, server: String, port: Int = 443, path: String = "/ws") -> WorkspaceProfileItem {
        WorkspaceProfileItem(
            id: id,
            remarks: remarks,
            subscriptionId: "sub-1",
            isFromSub: true,
            kind: .node,
            node: WorkspaceNodeConfig(
                protocolName: "vless",
                server: server,
                port: port,
                password: "uuid-\(id)",
                tls: WorkspaceTlsConfig(enabled: true, sni: server),
                transport: WorkspaceTransportConfig(type: "websocket", path: path)
            )
        )
    }

    func testWorkspaceModelsCanonicalV1ParityAndIsolation() async throws {
        let doc = WorkspaceDocument(
            schemaVersion: 1,
            revision: 3,
            updatedAtMs: 1_700_000_000_000,
            profiles: [
                WorkspaceProfileItem(
                    id: "p-node",
                    remarks: "HK-01",
                    kind: .node,
                    node: WorkspaceNodeConfig(
                        protocolName: "vless",
                        server: "hk.example.com",
                        port: 443,
                        password: "uuid-1",
                        flow: "xtls-rprx-vision",
                        tls: WorkspaceTlsConfig(enabled: true, sni: "hk.example.com", realityPublicKey: "pubk", realityShortId: "12ab"),
                        transport: WorkspaceTransportConfig(type: "RAW")
                    )
                ),
                WorkspaceProfileItem(id: "p-custom", remarks: "Custom", kind: .customOutbound, customOutboundKdl: "outbound \"{{tag}}\" type=\"direct\""),
                WorkspaceProfileItem(
                    id: "p-group",
                    remarks: "Auto",
                    kind: .policyGroup,
                    policyGroup: WorkspacePolicyGroupConfig(strategy: "url-test", memberIds: ["p-node"], dynamicSubId: "sub-1")
                ),
                WorkspaceProfileItem(id: "p-chain", remarks: "Chain", kind: .proxyChain, proxyChain: WorkspaceProxyChainConfig(hopIds: ["p-node", "p-custom"])),
                WorkspaceProfileItem(id: "p-kdl", remarks: "RawKdl", kind: .fullCustomKdl, fullCustomKdl: "schema-version 1\n"),
            ],
            subscriptions: [WorkspaceSubscriptionItem(id: "sub-1", remarks: "Main", url: "https://sub.example.com/list")],
            dns: WorkspaceDnsConfig(
                mode: "simple",
                simple: WorkspaceSimpleDnsConfig(hosts: ["internal.lan": "10.0.0.5"])
            ),
            ruleSetAssets: [WorkspaceRuleSetAsset(tag: "cn", sourceType: "local", format: "nxmm", path: "/var/lib/nexus/cn.nxmm")],
            fullTemplate: WorkspaceFullTemplateConfig(enabled: false, templateKdl: "", appendProxiesOnly: false, proxyDetour: "")
        )

        let encoded = try doc.encodeCanonicalJSON(pretty: true)
        XCTAssertTrue(encoded.contains("\"schema_version\" : 1") || encoded.contains("\"schema_version\":1"))
        XCTAssertTrue(encoded.contains("\"routing_profiles\""))
        XCTAssertTrue(encoded.contains("\"rule_set_assets\""))
        XCTAssertTrue(encoded.contains("\"full_template\""))
        // Verify ZERO host/telemetry/WebDAV credential leakage into Layer 1 workspace.json.
        XCTAssertFalse(encoded.contains("control_http_listen"))
        XCTAssertFalse(encoded.contains("webdav"))
        XCTAssertFalse(encoded.contains("passphrase"))
        XCTAssertFalse(encoded.contains("unread_unexpected_crash"))

        let decoded = try WorkspaceDocument.decodeCanonicalJSON(encoded)
        XCTAssertEqual(decoded.profiles.count, 5)
        XCTAssertEqual(decoded.profiles[0].node?.transport.type, "")
        XCTAssertEqual(decoded.profiles[0].kind.badgeTitle, "节点")
        XCTAssertEqual(decoded.profiles[2].kind.badgeTitle, "策略组")
        XCTAssertEqual(decoded.profiles[3].kind.badgeTitle, "代理链")
        XCTAssertEqual(decoded.profiles[4].kind.badgeTitle, "完整 KDL")

        // Array-tolerant dns.simple.hosts decode parity with Core/Android.
        let arrayHostsJSON = """
        {"schema_version":1,"revision":2,"updated_at_ms":10,"dns":{"mode":"simple","simple":{"hosts":{"multi.lan":["10.0.0.8","10.0.0.9"]}}}}
        """
        let arrayHostsDoc = try WorkspaceDocument.decodeCanonicalJSON(arrayHostsJSON)
        XCTAssertEqual(arrayHostsDoc.dns.simple.hosts["multi.lan"], "10.0.0.8")

        // Unsupported schema_version must throw.
        XCTAssertThrowsError(try WorkspaceDocument.decodeCanonicalJSON("{\"schema_version\":99}"))

        // Layer 3 AppleHostConfig v1 for desktop-macos & ios (default workers=1, no 16 cap, workers_spec/workers_max parity).
        let defaultHost = AppleHostConfig()
        XCTAssertEqual(defaultHost.workers, 1)
        XCTAssertEqual(defaultHost.workersSpec, "")
        XCTAssertEqual(defaultHost.workersMax, 0)
        let defaultJSON = try defaultHost.encodeCanonicalJSON(pretty: false)
        XCTAssertFalse(defaultJSON.contains("\"workers_spec\""))
        XCTAssertFalse(defaultJSON.contains("\"workers_max\""))

        let macHost = AppleHostConfig(
            platform: .desktopMacOS,
            workers: 20,
            workersSpec: "max-2",
            workersMax: 12,
            controlHttpListen: "127.0.0.1:9090"
        )
        XCTAssertEqual(macHost.workers, 20)
        let macJSON = try macHost.encodeCanonicalJSON(pretty: false)
        XCTAssertTrue(macJSON.contains("\"platform\":\"desktop-macos\""))
        XCTAssertTrue(macJSON.contains("\"schema_version\":1"))
        XCTAssertTrue(macJSON.contains("\"workers\":20"))
        XCTAssertTrue(macJSON.contains("\"workers_spec\":\"max-2\""))
        XCTAssertTrue(macJSON.contains("\"workers_max\":12"))
        XCTAssertFalse(macJSON.contains("passphrase"))
        let decodedMac = try JSONDecoder().decode(AppleHostConfig.self, from: Data(macJSON.utf8))
        XCTAssertEqual(decodedMac, macHost)

        let iosHost = AppleHostConfig(platform: .iOS)
        let iosJSON = try iosHost.encodeCanonicalJSON(pretty: false)
        XCTAssertTrue(iosJSON.contains("\"platform\":\"ios\""))
        let clampedHost = try JSONDecoder().decode(
            AppleHostConfig.self,
            from: Data("{\"schema_version\":1,\"platform\":\"ios\",\"workers\":0,\"workers_max\":-4}".utf8)
        )
        XCTAssertEqual(clampedHost.workers, 1)
        XCTAssertEqual(clampedHost.workersSpec, "")
        XCTAssertEqual(clampedHost.workersMax, 0)

        // Layer 4 TelemetryStore isolated from workspace.json.
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let telemetry = TelemetryStore(fileURL: dir.appendingPathComponent("telemetry.json"))
        _ = try await telemetry.setActiveProfileId("p-node")
        _ = try await telemetry.setOutboundMode("global")
        _ = try await telemetry.recordUnexpectedCrash(reason: "signal 11", nowMs: 12345)
        _ = try await telemetry.updateLatency(profileId: "p-node", latencyMs: 42, nowMs: 12346)
        let snap = await telemetry.load()
        XCTAssertEqual(snap.activeProfileId, "p-node")
        XCTAssertEqual(snap.outboundMode, "global")
        XCTAssertTrue(snap.unreadUnexpectedCrash)
        XCTAssertEqual(snap.profiles["p-node"]?.latencyMs, 42)
        _ = try await telemetry.clearUnexpectedCrash()
        let cleared = await telemetry.load()
        XCTAssertFalse(cleared.unreadUnexpectedCrash)
    }

    func testWorkspaceStoreAtomic0600ReplacementAndOrphanGC() async throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let store = WorkspaceStore(rootDirectory: dir)
        let initial = try await store.loadOrInit()
        XCTAssertEqual(initial.schemaVersion, 1)
        XCTAssertEqual(initial.revision, 1)

        let attrs = try FileManager.default.attributesOfItem(atPath: store.database.dbURL.path)
        let perms = (attrs[.posixPermissions] as? NSNumber)?.intValue
        XCTAssertEqual(perms, 0o600)

        let secretURL = dir.appendingPathComponent("probe.secret")
        try WorkspaceStore.atomicWrite0600(data: Data("top-secret".utf8), to: secretURL)
        let secAttrs = try FileManager.default.attributesOfItem(atPath: secretURL.path)
        XCTAssertEqual((secAttrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)

        // 5-tier multi-pass replacement: earlier weak candidate must NOT steal ID from later Tier-1 exact match.
        let existingA = makeSampleNode(id: "id-a", remarks: "Tokyo", server: "jp.example.com", port: 443, path: "/v1")
        let existingB = makeSampleNode(id: "id-b", remarks: "Singapore", server: "sg.example.com", port: 443, path: "/v1")
        let manual = WorkspaceProfileItem(id: "manual-1", remarks: "Manual", isFromSub: false, kind: .node, node: WorkspaceNodeConfig(server: "1.1.1.1"))
        let chain = WorkspaceProfileItem(id: "chain-1", remarks: "MyChain", kind: .proxyChain, proxyChain: WorkspaceProxyChainConfig(hopIds: ["id-a", "id-b"]))
        let ws = WorkspaceDocument(profiles: [existingA, existingB, manual, chain])

        // Empty incoming aborts fail-closed.
        let aborted = WorkspaceProfileReplacement.replaceSubscriptionNodes(workspace: ws, subscriptionId: "sub-1", incomingNodes: [], activeProfileId: "id-a")
        XCTAssertTrue(aborted.abortedEmpty)
        XCTAssertEqual(aborted.workspace.profiles.count, 4)

        // Incoming[0] shares server/port with existingA (Tier 4) while Incoming[1] is exact Tier-1 match for existingA!
        let incomingWeak = WorkspaceProfileItem(
            id: "",
            remarks: "Tokyo-New",
            kind: .node,
            node: WorkspaceNodeConfig(protocolName: "vless", server: "jp.example.com", port: 443, password: "new-password", tls: WorkspaceTlsConfig(sni: "jp.example.com"), transport: WorkspaceTransportConfig(type: "grpc", path: "/g"))
        )
        let incomingExact = makeSampleNode(id: "", remarks: "Tokyo", server: "jp.example.com", port: 443, path: "/v1")
        var exactCopy = incomingExact
        exactCopy.node?.password = "uuid-id-a"

        let res = WorkspaceProfileReplacement.replaceSubscriptionNodes(
            workspace: ws,
            subscriptionId: "sub-1",
            incomingNodes: [incomingWeak, exactCopy],
            activeProfileId: "id-a"
        )
        XCTAssertFalse(res.abortedEmpty)
        XCTAssertEqual(res.matchedCount, 1)
        XCTAssertEqual(res.addedCount, 1)
        XCTAssertEqual(res.removedIds, ["id-b"])
        XCTAssertEqual(res.activeProfileId, "id-a")
        XCTAssertTrue(res.orphanedChainRefs.contains("chain-1->id-b"))
        let exactReplaced = res.workspace.profiles.first(where: { $0.remarks == "Tokyo" })
        XCTAssertEqual(exactReplaced?.id, "id-a")
        XCTAssertNotNil(res.workspace.profiles.first(where: { $0.id == "manual-1" }))

        // Regex filter (including malformed regex fail-safe).
        let filtered = WorkspaceProfileReplacement.filterNodesByRegex(res.workspace.profiles, includeRegex: "Tokyo", excludeRegex: "New")
        XCTAssertEqual(filtered.map(\.remarks), ["Tokyo"])
        let badRegex = WorkspaceProfileReplacement.filterNodesByRegex(res.workspace.profiles, includeRegex: "[unclosed", excludeRegex: "")
        XCTAssertEqual(badRegex.count, res.workspace.profiles.count)

        // Fail-closed orphan secret GC (.secret, .pem, .ech).
        let secDir = dir.appendingPathComponent("secrets", isDirectory: true)
        try FileManager.default.createDirectory(at: secDir, withIntermediateDirectories: true)
        let keepSec = secDir.appendingPathComponent("keep.secret")
        let staleSec = secDir.appendingPathComponent("stale.secret")
        let stalePem = secDir.appendingPathComponent("stale.pem")
        let staleEch = secDir.appendingPathComponent("stale.ech")
        let unrelated = secDir.appendingPathComponent("notes.txt")
        for u in [keepSec, staleSec, stalePem, staleEch, unrelated] {
            try Data("x".utf8).write(to: u)
        }
        let noOp = WorkspaceProfileReplacement.gcOrphanSecretFiles(in: secDir, activeSecretFiles: [keepSec.path], composeOk: false)
        XCTAssertTrue(noOp.isEmpty)
        XCTAssertTrue(FileManager.default.fileExists(atPath: staleSec.path))

        let swept = WorkspaceProfileReplacement.gcOrphanSecretFiles(in: secDir, activeSecretFiles: [keepSec.path], composeOk: true)
        XCTAssertEqual(Set(swept.map(\.lastPathComponent)), ["stale.secret", "stale.pem", "stale.ech"])
        XCTAssertTrue(FileManager.default.fileExists(atPath: keepSec.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: unrelated.path))
    }

    func testSubscriptionInfoParserHeadersAndSafeUrls() {
        let b64Title = Data("我的机场\u{0007}".utf8).base64EncodedString().replacingOccurrences(of: "=", with: "")
        let parsed = SubscriptionInfoParser.parseHeaders([
            "Subscription-Userinfo": "upload=1024; download=2.048e3; total=1073741824; expire=1900000000",
            "Profile-Title": "base64:\(b64Title)",
            "Profile-Web-Page-URL": "https://portal.example.com/home",
            "Support-URL": "tg://resolve?domain=nexus_support",
            "Profile-Update-Interval": "6",
        ])
        XCTAssertEqual(parsed.usage.uploadBytes, 1024)
        XCTAssertEqual(parsed.usage.downloadBytes, 2048)
        XCTAssertEqual(parsed.usage.totalBytes, 1_073_741_824)
        XCTAssertEqual(parsed.usage.expireUnixSec, 1_900_000_000)
        XCTAssertEqual(parsed.usage.profileTitle, "我的机场")
        XCTAssertEqual(parsed.usage.webPageUrl, "https://portal.example.com/home")
        XCTAssertEqual(parsed.usage.supportUrl, "tg://resolve?domain=nexus_support")
        XCTAssertEqual(parsed.updateIntervalMinutes, 360)

        XCTAssertEqual(SubscriptionInfoParser.sanitizeSafeURL("javascript:alert(1)"), "")
        XCTAssertEqual(SubscriptionInfoParser.sanitizeSafeURL("file" + ":///etc/passwd"), "")
        XCTAssertEqual(SubscriptionInfoParser.sanitizeSafeURL("https://ok.example.com/a b"), "")
        XCTAssertEqual(SubscriptionInfoParser.decodeProfileTitle("Nexus%20Cloud"), "Nexus Cloud")
    }

    func testWorkspaceComposerBridgeHooksAndWebDavETagConflict() async throws {
        let fakeEnvelope = """
        {"format":"nexus-sync-v1","kdf":"scrypt","kdf_n":32768,"kdf_r":8,"kdf_p":1,"aead":"xchacha20-poly1305","salt_b64":"AAAA","nonce_b64":"BBBB","revision":5,"updated_at_ms":1700000005000,"device_label":"MacBook","plaintext_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","ciphertext_b64":"CCCC"}
        """
        let restoredWS = try WorkspaceDocument(revision: 5, profiles: [makeSampleNode(id: "p1", remarks: "Pulled", server: "pull.example.com")]).encodeCanonicalJSON(pretty: false)

        let hooks = EmbeddedCoreHooks(
            version: { "0.1.0" },
            runArgs: { _ in 0 },
            checkConfig: { _ in 0 },
            requestStop: {},
            requestReload: {},
            isRunning: { false },
            composeWorkspace: { _, _, _, _ in
                (0, #"{"ok":true,"active_tag":"HK-01","selector_tag":"proxy","selector_members":["HK-01"],"warnings":[],"errors":[],"secret_files":["/tmp/a.secret"],"kdl":"schema-version 1\n"}"#, "")
            },
            exportShare: { _, ids in
                (0, #"{"ok":true,"uri":"nexus://share/v1/eyJzY2hlbWFfdmVyc2lvbiI6MX0","exported_count":\#(ids.count),"warnings":[],"errors":[]}"#, "")
            },
            importShare: { wsJSON, _, _ in
                let escaped = wsJSON.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
                return (0, #"{"ok":true,"imported_ids":["p-imp-1"],"warnings":[],"errors":[],"workspace_json":"\#(escaped)"}"#, "")
            },
            sealSync: { _, _, _ in
                let escapedEnv = fakeEnvelope.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
                return (0, #"{"ok":true,"revision":5,"updated_at_ms":1700000005000,"envelope_sha256":"abcd","warnings":[],"errors":[],"envelope_json":"\#(escapedEnv)"}"#, "")
            },
            openSync: { _, _ in
                let escapedWS = restoredWS.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
                return (0, #"{"ok":true,"revision":5,"updated_at_ms":1700000005000,"device_label":"MacBook","warnings":[],"errors":[],"workspace_json":"\#(escapedWS)"}"#, "")
            }
        )

        let bridge = WorkspaceComposerBridge(hooks: hooks)
        let ws = WorkspaceDocument(revision: 4, profiles: [
            makeSampleNode(id: "p1", remarks: "HK-01", server: "hk.example.com"),
            WorkspaceProfileItem(id: "p-raw", remarks: "Raw", kind: .fullCustomKdl, fullCustomKdl: "schema-version 1\n"),
        ])

        let composed = try await bridge.compose(workspace: ws, host: AppleHostConfig(platform: .desktopMacOS), secretsDir: "/tmp/s", activeProfileID: "p1")
        XCTAssertTrue(composed.ok)
        XCTAssertEqual(composed.activeTag, "HK-01")
        XCTAssertEqual(composed.secretFiles, ["/tmp/a.secret"])

        // full_custom_kdl must be rejected on share export.
        do {
            _ = try await bridge.exportShare(workspace: ws, profileIDs: ["p-raw"])
            XCTFail("Expected fullCustomKdlNotShareable")
        } catch WorkspaceBridgeError.fullCustomKdlNotShareable(let id) {
            XCTAssertEqual(id, "p-raw")
        }

        let exported = try await bridge.exportShare(workspace: ws, profileIDs: ["p1"])
        XCTAssertTrue(exported.ok)
        XCTAssertTrue(exported.uri.hasPrefix("nexus://share/v1/"))

        let imported = try await bridge.importShare(workspace: ws, uri: exported.uri)
        XCTAssertTrue(imported.ok)
        XCTAssertEqual(imported.importedIds, ["p-imp-1"])
        XCTAssertEqual(WorkspaceComposerBridge.sanitizeCoreTag("direct"), "direct-node")

        // WebDAV ETag conflict + HTTPS enforcement + pre-pull backup.
        let mockServer = MockWebDavServer()
        let dav = WebDavSyncClient { req in await mockServer.handle(req) }

        let insecure = WebDavSyncConfig(endpointURL: "http://dav.example.com/nexus/", username: "alice")
        do {
            _ = try await dav.headRemote(config: insecure, webDavPassword: "pw")
            XCTFail("Expected insecureEndpoint")
        } catch WebDavSyncError.insecureEndpoint {
            // Expected
        }

        var cfg = WebDavSyncConfig(endpointURL: "http://127.0.0.1:8080/nexus/", username: "alice", deviceLabel: "MacBook")
        let cfgJSON = String(decoding: try JSONEncoder().encode(cfg), as: UTF8.self)
        XCTAssertFalse(cfgJSON.contains("password"))
        XCTAssertFalse(cfgJSON.contains("passphrase"))

        let push1 = try await dav.pushEncryptedWorkspace(workspace: ws, config: cfg, webDavPassword: "secret", syncPassphrase: "correct horse", bridge: bridge)
        guard case .pushed(let rev1, let etag1) = push1 else {
            return XCTFail("Expected pushed, got \(push1)")
        }
        XCTAssertEqual(rev1, 5)
        XCTAssertFalse(etag1.isEmpty)
        let authHeader = await mockServer.lastAuthorizationHeader
        XCTAssertEqual(authHeader, "Basic \(Data("alice:secret".utf8).base64EncodedString())")

        // Simulate concurrent update on server -> HEAD ETag conflict detected before overwrite.
        cfg.lastSyncedETag = etag1
        cfg.lastSyncedRevision = rev1
        await mockServer.seed(path: "/nexus/nexus-workspace-v1.enc", json: fakeEnvelope, etag: "\"etag-remote-newer\"")
        let pushConflict = try await dav.pushEncryptedWorkspace(workspace: ws, config: cfg, webDavPassword: "secret", syncPassphrase: "correct horse", bridge: bridge)
        XCTAssertEqual(pushConflict, .conflict(remoteRevision: 5, remoteDevice: "MacBook", remoteETag: "\"etag-remote-newer\""))

        // Simulate TOCTOU 412 Precondition Failed on PUT -> also yields conflict cleanly.
        cfg.lastSyncedETag = "\"etag-remote-newer\""
        await mockServer.setForceNextPut412(true)
        let put412Conflict = try await dav.pushEncryptedWorkspace(workspace: ws, config: cfg, webDavPassword: "secret", syncPassphrase: "correct horse", bridge: bridge)
        XCTAssertEqual(put412Conflict, .conflict(remoteRevision: 5, remoteDevice: "MacBook", remoteETag: "\"etag-remote-newer\""))

        // Pull with local revision <= remote creates 0600 backup and returns decrypted workspace.
        let backupDir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: backupDir) }
        let pullOutcome = try await dav.pullEncryptedWorkspace(
            localWorkspace: ws,
            config: cfg,
            webDavPassword: "secret",
            syncPassphrase: "correct horse",
            bridge: bridge,
            backupDirectory: backupDir
        )
        guard case .pulled(let pulledWS, let pulledRev, let device, _, let backupURL) = pullOutcome else {
            return XCTFail("Expected pulled, got \(pullOutcome)")
        }
        XCTAssertEqual(pulledRev, 5)
        XCTAssertEqual(device, "MacBook")
        XCTAssertEqual(pulledWS.profiles.first?.remarks, "Pulled")
        XCTAssertNotNil(backupURL)
        if let backupURL {
            XCTAssertTrue(FileManager.default.fileExists(atPath: backupURL.path))
        }

        // Pull when local revision is strictly ahead of remote must return conflict unless forceOverwrite is set.
        let aheadLocal = WorkspaceDocument(revision: 9, profiles: ws.profiles)
        let pullConflict = try await dav.pullEncryptedWorkspace(
            localWorkspace: aheadLocal,
            config: cfg,
            webDavPassword: "secret",
            syncPassphrase: "correct horse",
            bridge: bridge
        )
        XCTAssertEqual(pullConflict, .conflict(remoteRevision: 5, remoteDevice: "MacBook", remoteETag: "\"etag-remote-newer\""))

        // Force-overwrite push succeeds even with stale ETag.
        let forcedPush = try await dav.pushEncryptedWorkspace(
            workspace: aheadLocal,
            config: cfg,
            webDavPassword: "secret",
            syncPassphrase: "correct horse",
            bridge: bridge,
            forceOverwrite: true
        )
        guard case .pushed(let forcedRev, _) = forcedPush else {
            return XCTFail("Expected forced pushed, got \(forcedPush)")
        }
        XCTAssertEqual(forcedRev, 5)
    }
}
