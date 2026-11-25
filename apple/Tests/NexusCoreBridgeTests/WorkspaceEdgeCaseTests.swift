import Foundation
import XCTest
@testable import NexusCoreBridge

private actor EdgeMockWebDav {
    var exists = false
    var body = Data()
    var etag = ""
    var getStatusOverride: Int?
    var lastPutIfMatch: String?
    var lastPutIfNoneMatch: String?

    func configure(exists: Bool, body: String = "", etag: String = "", getStatusOverride: Int? = nil) {
        self.exists = exists
        self.body = Data(body.utf8)
        self.etag = etag
        self.getStatusOverride = getStatusOverride
    }

    func handle(_ req: URLRequest) -> (Data, HTTPURLResponse) {
        let url = req.url ?? URL(string: "http://127.0.0.1:8080/")!
        let method = req.httpMethod ?? "GET"
        func respond(_ code: Int, data: Data = Data(), headers: [String: String] = [:]) -> (Data, HTTPURLResponse) {
            (data, HTTPURLResponse(url: url, statusCode: code, httpVersion: "HTTP/1.1", headerFields: headers)!)
        }

        switch method {
        case "MKCOL":
            return respond(201)
        case "HEAD":
            guard exists else { return respond(404) }
            let hdrs = etag.isEmpty ? [:] : ["ETag": etag]
            return respond(200, headers: hdrs)
        case "GET":
            if let override = getStatusOverride { return respond(override) }
            guard exists else { return respond(404) }
            let hdrs = etag.isEmpty ? [:] : ["ETag": etag]
            return respond(200, data: body, headers: hdrs)
        case "PUT":
            lastPutIfMatch = req.value(forHTTPHeaderField: "If-Match")
            lastPutIfNoneMatch = req.value(forHTTPHeaderField: "If-None-Match")
            if lastPutIfNoneMatch == "*" && exists {
                return respond(412)
            }
            if let m = lastPutIfMatch, (!exists || m != etag) {
                return respond(412)
            }
            exists = true
            body = req.httpBody ?? Data()
            etag = "\"created-etag\""
            return respond(201, headers: ["ETag": etag])
        default:
            return respond(405)
        }
    }
}

final class WorkspaceEdgeCaseTests: XCTestCase {
    private func makeEnvelope(revision: Int64, device: String = "iPad") -> String {
        #"{"format":"nexus-sync-v1","kdf":"scrypt","kdf_n":32768,"kdf_r":8,"kdf_p":1,"aead":"xchacha20-poly1305","salt_b64":"AAAA","nonce_b64":"BBBB","revision":\#(revision),"updated_at_ms":1700000000000,"device_label":"\#(device)","plaintext_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","ciphertext_b64":"CCCC"}"#
    }

    func testWebDavFailClosedMetadataIfNoneMatchCreateAndETaglessDivergence() async throws {
        let env7 = makeEnvelope(revision: 7, device: "iPad")
        let hooks = EmbeddedCoreHooks(
            version: { "0.1.0" },
            runArgs: { _ in 0 },
            checkConfig: { _ in 0 },
            requestStop: {},
            requestReload: {},
            isRunning: { false },
            sealSync: { _, _, _ in
                let esc = env7.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
                return (0, #"{"ok":true,"revision":7,"updated_at_ms":1700000000000,"envelope_sha256":"aa","warnings":[],"errors":[],"envelope_json":"\#(esc)"}"#, "")
            },
            openSync: { _, _ in
                (0, #"{"ok":true,"revision":7,"updated_at_ms":1700000000000,"device_label":"iPad","warnings":[],"errors":[],"workspace_json":"{\"schema_version\":1,\"revision\":7}"}"#, "")
            }
        )
        let bridge = WorkspaceComposerBridge(hooks: hooks)
        let server = EdgeMockWebDav()
        let dav = WebDavSyncClient { req in await server.handle(req) }

        // P2 #6: "." remote filename must be rejected.
        XCTAssertThrowsError(try WebDavSyncClient.resolveRemoteFileURL(config: WebDavSyncConfig(endpointURL: "https://dav.example.com/nexus/", remoteFileName: ".")))

        // P1 #2a: ETag-less server where remote GET fails/corrupts MUST fail closed with .conflict (never overwrite!).
        await server.configure(exists: true, body: "corrupt-not-json", etag: "", getStatusOverride: 500)
        let staleCfg = WebDavSyncConfig(endpointURL: "http://127.0.0.1:8080/nexus/", username: "u", lastSyncedETag: "", lastSyncedRevision: 5)
        let failClosed = try await dav.pushEncryptedWorkspace(
            workspace: WorkspaceDocument(revision: 6),
            config: staleCfg,
            webDavPassword: "p",
            syncPassphrase: "pass",
            bridge: bridge
        )
        XCTAssertEqual(failClosed, .conflict(remoteRevision: 0, remoteDevice: "", remoteETag: ""))

        // P1 #2b: Remote deleted -> !probe.exists with stale lastSyncedETag sends If-None-Match: * (NOT If-Match!).
        await server.configure(exists: false)
        let recreatedCfg = WebDavSyncConfig(endpointURL: "http://127.0.0.1:8080/nexus/", username: "u", lastSyncedETag: "\"deleted-old\"", lastSyncedRevision: 5)
        let created = try await dav.pushEncryptedWorkspace(
            workspace: WorkspaceDocument(revision: 6),
            config: recreatedCfg,
            webDavPassword: "p",
            syncPassphrase: "pass",
            bridge: bridge
        )
        XCTAssertEqual(created, .pushed(revision: 7, etag: "\"created-etag\""))
        let sentIfNoneMatch = await server.lastPutIfNoneMatch
        let sentIfMatch = await server.lastPutIfMatch
        XCTAssertEqual(sentIfNoneMatch, "*")
        XCTAssertNil(sentIfMatch)

        // P1 #2c: ETag-less pull 3-way divergence (base=r5, local=r6, remote=r7) MUST report .conflict!
        await server.configure(exists: true, body: env7, etag: "")
        let etaglessPull = try await dav.pullEncryptedWorkspace(
            localWorkspace: WorkspaceDocument(revision: 6),
            config: WebDavSyncConfig(endpointURL: "http://127.0.0.1:8080/nexus/", username: "u", lastSyncedETag: "", lastSyncedRevision: 5),
            webDavPassword: "p",
            syncPassphrase: "pass",
            bridge: bridge
        )
        XCTAssertEqual(etaglessPull, .conflict(remoteRevision: 7, remoteDevice: "iPad", remoteETag: ""))
    }

    func testComposerBridgeFailClosedOnNonZeroExitCodes() async throws {
        let env = makeEnvelope(revision: 2)
        let hooks = EmbeddedCoreHooks(
            version: { "0.1.0" },
            runArgs: { _ in 0 },
            checkConfig: { _ in 0 },
            requestStop: {},
            requestReload: {},
            isRunning: { false },
            exportShare: { _, _ in (-2, #"{"ok":true,"uri":"nexus://share/v1/abc","exported_count":1,"warnings":[],"errors":[]}"#, "forced failure") },
            importShare: { _, _, _ in (-2, #"{"ok":false,"imported_ids":[],"warnings":[],"errors":[],"workspace_json":""}"#, "empty errors") },
            sealSync: { _, _, _ in (-1, #"{"ok":true,"revision":1,"updated_at_ms":0,"envelope_sha256":"","warnings":[],"errors":[],"envelope_json":"{}"}"#, "seal rc=-1") },
            openSync: { _, _ in (-1, #"{"ok":true,"revision":1,"updated_at_ms":0,"device_label":"","warnings":[],"errors":[],"workspace_json":"{}"}"#, "open rc=-1") }
        )
        let bridge = WorkspaceComposerBridge(hooks: hooks)
        let ws = WorkspaceDocument(profiles: [WorkspaceProfileItem(id: "p1", remarks: "N1", kind: .node, node: WorkspaceNodeConfig(server: "1.1.1.1"))])

        do {
            _ = try await bridge.exportShare(workspace: ws, profileIDs: ["p1"])
            XCTFail("Expected coreRejected")
        } catch WorkspaceBridgeError.coreRejected(let code, _) {
            XCTAssertEqual(code, -2)
        }
        do {
            _ = try await bridge.importShare(workspace: ws, uri: "nexus://share/v1/abc")
            XCTFail("Expected coreRejected")
        } catch WorkspaceBridgeError.coreRejected(let code, _) {
            XCTAssertEqual(code, -2)
        }
        do {
            _ = try await bridge.sealSync(workspace: ws, passphrase: "pw", deviceLabel: "Mac")
            XCTFail("Expected coreRejected")
        } catch WorkspaceBridgeError.coreRejected(let code, _) {
            XCTAssertEqual(code, -1)
        }
        do {
            _ = try await bridge.openSync(envelopeJSON: env, passphrase: "pw")
            XCTFail("Expected coreRejected")
        } catch WorkspaceBridgeError.coreRejected(let code, _) {
            XCTAssertEqual(code, -1)
        }
    }

    func testHostAndTelemetryTolerantDecodeAndSchemaVersionValidation() throws {
        // Minimal iOS host.json without "desktop" block must decode cleanly.
        let minimalIOS = Data(#"{"schema_version":1,"platform":"ios"}"#.utf8)
        let iosHost = try JSONDecoder().decode(AppleHostConfig.self, from: minimalIOS)
        XCTAssertEqual(iosHost.platform, .iOS)
        XCTAssertEqual(iosHost.schemaVersion, 1)
        XCTAssertEqual(iosHost.workers, 1)

        // Unsupported host schema_version must throw.
        let badHost = Data(#"{"schema_version":2,"platform":"desktop-macos"}"#.utf8)
        XCTAssertThrowsError(try JSONDecoder().decode(AppleHostConfig.self, from: badHost))

        // Partial telemetry.json must decode without wiping surviving fields.
        let partialTel = Data(#"{"active_profile_id":"p-42","profiles":{"p-42":{"latency_ms":28}}}"#.utf8)
        let tel = try JSONDecoder().decode(TelemetryDocument.self, from: partialTel)
        XCTAssertEqual(tel.activeProfileId, "p-42")
        XCTAssertEqual(tel.outboundMode, "rule")
        XCTAssertEqual(tel.profiles["p-42"]?.latencyMs, 28)
        XCTAssertEqual(tel.profiles["p-42"]?.uploadBytes, 0)
    }

    func testTier4And5IncomingUniquenessAndUrlTransportSanitization() throws {
        // P2 #5: Two duplicate incoming Tier-4 nodes must NOT steal the single old ID ambiguously.
        let oldNode = WorkspaceProfileItem(
            id: "old-t4",
            remarks: "OldName",
            subscriptionId: "sub-1",
            isFromSub: true,
            kind: .node,
            node: WorkspaceNodeConfig(protocolName: "vless", server: "same.example.com", port: 443, password: "old-pw", transport: WorkspaceTransportConfig(type: "websocket", path: "/a"))
        )
        let dupA = WorkspaceProfileItem(
            id: "",
            remarks: "DupA",
            kind: .node,
            node: WorkspaceNodeConfig(protocolName: "vless", server: "same.example.com", port: 443, password: "pw-a", transport: WorkspaceTransportConfig(type: "grpc", path: "/x"))
        )
        let dupB = WorkspaceProfileItem(
            id: "",
            remarks: "DupB",
            kind: .node,
            node: WorkspaceNodeConfig(protocolName: "vless", server: "same.example.com", port: 443, password: "pw-b", transport: WorkspaceTransportConfig(type: "grpc", path: "/y"))
        )
        let t4Res = WorkspaceProfileReplacement.replaceSubscriptionNodes(
            workspace: WorkspaceDocument(profiles: [oldNode]),
            subscriptionId: "sub-1",
            incomingNodes: [dupA, dupB]
        )
        XCTAssertEqual(t4Res.matchedCount, 0)
        XCTAssertEqual(t4Res.addedCount, 2)
        XCTAssertEqual(t4Res.removedIds, ["old-t4"])

        // P2 #5: Two duplicate incoming Tier-5 nodes with same remarks+protocol must NOT steal old ID.
        let oldT5 = WorkspaceProfileItem(
            id: "old-t5",
            remarks: "SameLabel",
            subscriptionId: "sub-1",
            isFromSub: true,
            kind: .node,
            node: WorkspaceNodeConfig(protocolName: "trojan", server: "old.example.com", port: 443, password: "p0")
        )
        let t5A = WorkspaceProfileItem(id: "", remarks: "SameLabel", kind: .node, node: WorkspaceNodeConfig(protocolName: "trojan", server: "a.example.com", port: 8443, password: "p1"))
        let t5B = WorkspaceProfileItem(id: "", remarks: "SameLabel", kind: .node, node: WorkspaceNodeConfig(protocolName: "trojan", server: "b.example.com", port: 8443, password: "p2"))
        let t5Res = WorkspaceProfileReplacement.replaceSubscriptionNodes(
            workspace: WorkspaceDocument(profiles: [oldT5]),
            subscriptionId: "sub-1",
            incomingNodes: [t5A, t5B]
        )
        XCTAssertEqual(t5Res.matchedCount, 0)
        XCTAssertEqual(t5Res.addedCount, 2)
        XCTAssertEqual(t5Res.removedIds, ["old-t5"])

        // P2 #6: "none" transport normalization + unsafe subscription URL filtering on decode.
        XCTAssertEqual(WorkspaceTransportConfig(type: "NONE").type, "")
        let subJSON = """
        {"schema_version":1,"subscriptions":[{"id":"s1","url":"javascript:alert(1)","more_urls":["https://ok.example.com/sub","data:text/plain,evil"],"usage":{"web_page_url":"javascript:x","support_url":"tg://resolve?domain=ok"}}]}
        """
        let subDoc = try WorkspaceDocument.decodeCanonicalJSON(subJSON)
        XCTAssertEqual(subDoc.subscriptions.first?.url, "")
        XCTAssertEqual(subDoc.subscriptions.first?.moreUrls, ["https://ok.example.com/sub"])
        XCTAssertEqual(subDoc.subscriptions.first?.usage.webPageUrl, "")
        XCTAssertEqual(subDoc.subscriptions.first?.usage.supportUrl, "tg://resolve?domain=ok")
    }
}
