import Foundation
import SQLite3
import XCTest
@testable import NexusCoreBridge

final class NexusClientDatabaseTests: XCTestCase {
    private func makeTempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nexus-apple-sqlite-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    func testSchemaV1VerticalSplitAndLosslessWorkspaceRoundTrip() async throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let db = NexusClientDatabase(rootDirectory: dir)
        let version = try await db.schemaUserVersion()
        XCTAssertEqual(version, NexusClientDatabase.schemaVersion)
        let hasDataInitially = try await db.hasWorkspaceData()
        XCTAssertFalse(hasDataInitially)
        let emptyLoad = try await db.loadWorkspace()
        XCTAssertNil(emptyLoad)

        let attrs = try FileManager.default.attributesOfItem(atPath: db.dbURL.path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)

        let doc = WorkspaceDocument(
            schemaVersion: 1,
            revision: 7,
            updatedAtMs: 1_700_000_007_000,
            profiles: [
                WorkspaceProfileItem(
                    id: "p-vless",
                    remarks: "Tokyo-VLESS",
                    subscriptionId: "sub-jp",
                    isFromSub: true,
                    kind: .node,
                    node: WorkspaceNodeConfig(
                        protocolName: "vless",
                        server: "jp.example.com",
                        port: 443,
                        password: "secret-uuid",
                        flow: "xtls-rprx-vision",
                        tls: WorkspaceTlsConfig(enabled: true, sni: "jp.example.com", realityPublicKey: "pbk1", realityShortId: "aa11"),
                        transport: WorkspaceTransportConfig(type: "websocket", path: "/ws")
                    )
                ),
                WorkspaceProfileItem(
                    id: "p-custom",
                    remarks: "Custom-Out",
                    kind: .customOutbound,
                    customOutboundKdl: "outbound \"{{tag}}\" type=\"direct\""
                ),
                WorkspaceProfileItem(
                    id: "p-group",
                    remarks: "Auto-JP",
                    kind: .policyGroup,
                    policyGroup: WorkspacePolicyGroupConfig(strategy: "url-test", memberIds: ["p-vless"], dynamicSubId: "sub-jp", toleranceMs: 40)
                ),
                WorkspaceProfileItem(
                    id: "p-chain",
                    remarks: "Relay-Chain",
                    kind: .proxyChain,
                    proxyChain: WorkspaceProxyChainConfig(hopIds: ["p-vless", "p-custom"])
                ),
                WorkspaceProfileItem(
                    id: "p-kdl",
                    remarks: "Raw-KDL",
                    kind: .fullCustomKdl,
                    fullCustomKdl: "schema-version 1\nrole \"client\"\n"
                ),
            ],
            subscriptions: [
                WorkspaceSubscriptionItem(
                    id: "sub-jp",
                    remarks: "Japan Feed",
                    url: "https://sub.example.com/jp",
                    moreUrls: ["https://mirror.example.com/jp"],
                    autoUpdateMinutes: 120,
                    requestHeaders: ["X-Client": "Nexus-Apple"],
                    updatedAtMs: 1_700_000_001_000,
                    usage: WorkspaceSubscriptionUsage(
                        uploadBytes: 1024,
                        downloadBytes: 4096,
                        totalBytes: 1_073_741_824,
                        expireUnixSec: 1_900_000_000,
                        profileTitle: "JP Plan",
                        webPageUrl: "https://portal.example.com",
                        supportUrl: "tg://resolve?domain=nexus_help"
                    )
                ),
            ],
            dns: WorkspaceDnsConfig(
                mode: "simple",
                simple: WorkspaceSimpleDnsConfig(fakeIpEnabled: true, hosts: ["corp.lan": "10.0.1.9"])
            ),
            ruleSetAssets: [
                WorkspaceRuleSetAsset(tag: "cn-ip", sourceType: "local", format: "nxmm", path: "/var/lib/nexus/cn.nxmm"),
            ],
            fullTemplate: WorkspaceFullTemplateConfig(enabled: false, templateKdl: "", appendProxiesOnly: false, proxyDetour: "")
        )

        try await db.saveWorkspace(doc)
        let loaded = try await db.loadWorkspace()
        XCTAssertEqual(loaded, doc)

        // Vertical split: fast index-only profile summaries without touching profile_payloads.
        let allSummaries = try await db.listProfileSummaries()
        XCTAssertEqual(allSummaries.map(\.id), ["p-vless", "p-custom", "p-group", "p-chain", "p-kdl"])
        XCTAssertEqual(allSummaries[0].protocolName, "vless")
        XCTAssertEqual(allSummaries[0].server, "jp.example.com")
        XCTAssertEqual(allSummaries[0].port, 443)

        let subSummaries = try await db.listProfileSummaries(subscriptionId: "sub-jp")
        XCTAssertEqual(subSummaries.map(\.id), ["p-vless"])
        let groupSummaries = try await db.listProfileSummaries(kind: .policyGroup)
        XCTAssertEqual(groupSummaries.map(\.id), ["p-group"])

        let payloadBefore = try await db.loadProfilePayload(id: "p-vless")
        XCTAssertEqual(payloadBefore, doc.profiles[0])

        // Deleting a profile cascades cleanly to profile_payloads via ON DELETE CASCADE.
        try await db.deleteProfile(id: "p-vless")
        let payloadAfter = try await db.loadProfilePayload(id: "p-vless")
        XCTAssertNil(payloadAfter)

        try await db.shrinkMemory()
        await db.close()
    }

    func testNodeTelemetryTrafficLedgerHostKVAndDaemonPersistence() async throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let db = NexusClientDatabase(rootDirectory: dir)

        // node_telemetry upsert & list
        try await db.upsertNodeTelemetry(
            NodeTelemetryRecord(profileId: "p-1", latencyMs: 38, ewmaMs: 41, statusCode: 204, state: "up", testedAt: 1000)
        )
        try await db.upsertNodeTelemetry(
            NodeTelemetryRecord(profileId: "p-1", latencyMs: 29, ewmaMs: 35, statusCode: 204, state: "up", testedAt: 2000)
        )
        let nodes = try await db.listNodeTelemetry()
        XCTAssertEqual(nodes.count, 1)
        XCTAssertEqual(nodes[0].latencyMs, 29)
        XCTAssertEqual(nodes[0].ewmaMs, 35)
        XCTAssertEqual(nodes[0].statusCode, 204)
        XCTAssertEqual(nodes[0].state, "up")

        // traffic_ledger additive accumulation + sinceHour filtering
        try await db.recordTrafficDelta(bucketHour: 100, profileId: "p-1", uploadBytes: 1000, downloadBytes: 5000)
        try await db.recordTrafficDelta(bucketHour: 100, profileId: "p-1", uploadBytes: 500, downloadBytes: 2500)
        try await db.recordTrafficDelta(bucketHour: 101, profileId: "p-1", uploadBytes: 200, downloadBytes: 800)
        try await db.recordTrafficDelta(bucketHour: 101, profileId: "p-2", uploadBytes: 10, downloadBytes: 20)

        let since100 = try await db.queryTrafficLedger(sinceHour: 100, profileId: "p-1")
        XCTAssertEqual(since100.count, 2)
        XCTAssertEqual(since100[0], TrafficLedgerRecord(bucketHour: 100, profileId: "p-1", uploadBytes: 1500, downloadBytes: 7500))
        XCTAssertEqual(since100[1], TrafficLedgerRecord(bucketHour: 101, profileId: "p-1", uploadBytes: 200, downloadBytes: 800))

        let since101All = try await db.queryTrafficLedger(sinceHour: 101)
        XCTAssertEqual(since101All.count, 2)

        // loadTelemetry merges node_telemetry and summed traffic_ledger
        let telSnap = try await db.loadTelemetry()
        XCTAssertEqual(telSnap.profiles["p-1"]?.latencyMs, 29)
        XCTAssertEqual(telSnap.profiles["p-1"]?.uploadBytes, 1700)
        XCTAssertEqual(telSnap.profiles["p-1"]?.downloadBytes, 8300)

        // Saving telemetry metadata and TelemetryStore.updateLatency must preserve extended node_telemetry columns
        var updatedTel = telSnap
        updatedTel.activeProfileId = "p-1"
        try await db.saveTelemetry(updatedTel)
        let telStore = TelemetryStore(rootDirectory: dir, database: db)
        _ = try await telStore.updateLatency(profileId: "p-1", latencyMs: 18, nowMs: 3000)
        let preservedNodes = try await db.listNodeTelemetry()
        XCTAssertEqual(preservedNodes.first?.latencyMs, 18)
        XCTAssertEqual(preservedNodes.first?.testedAt, 3000)
        XCTAssertEqual(preservedNodes.first?.ewmaMs, 35)
        XCTAssertEqual(preservedNodes.first?.statusCode, 204)
        XCTAssertEqual(preservedNodes.first?.state, "up")

        // host_kv get/set/delete
        let missingKV = try await db.getHostKV("custom_key")
        XCTAssertNil(missingKV)
        try await db.setHostKV("custom_key", value: "{\"ok\":true}")
        let presentKV = try await db.getHostKV("custom_key")
        XCTAssertEqual(presentKV, "{\"ok\":true}")
        try await db.deleteHostKV("custom_key")
        let deletedKV = try await db.getHostKV("custom_key")
        XCTAssertNil(deletedKV)

        // DaemonManager elevation mode persists strictly in host_kv (no UserDefaults)
        let defaultMode = await PrivilegedDaemonController.loadSavedElevationMode(from: db)
        XCTAssertEqual(defaultMode, .persistentDaemon)
        try await PrivilegedDaemonController.saveElevationMode(.sessionOnly, to: db)
        let savedRaw = try await db.getHostKV(PrivilegedDaemonController.elevationModeHostKVKey)
        XCTAssertEqual(savedRaw, "\"session_only\"")
        let loadedMode = await PrivilegedDaemonController.loadSavedElevationMode(from: db)
        XCTAssertEqual(loadedMode, .sessionOnly)

        try await db.shrinkMemory()
    }

    func testOneShotLegacyJsonMigrationForWorkspaceHostAndTelemetry() async throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        // Seed legacy workspace.json, host.json, and telemetry.json before DB is created.
        let legacyWS = WorkspaceDocument(
            revision: 4,
            updatedAtMs: 1_700_000_004_000,
            profiles: [
                WorkspaceProfileItem(
                    id: "legacy-hk",
                    remarks: "Legacy HK",
                    kind: .node,
                    node: WorkspaceNodeConfig(protocolName: "trojan", server: "hk.example.com", port: 443, password: "pw")
                ),
            ]
        )
        try WorkspaceStore.atomicWrite0600(
            data: Data(try legacyWS.encodeCanonicalJSON(pretty: true).utf8),
            to: dir.appendingPathComponent("workspace.json")
        )

        let legacyHost = AppleHostConfig(platform: .desktopMacOS, logLevel: "debug", workers: 3, controlHttpListen: "127.0.0.1:9191")
        try WorkspaceStore.atomicWrite0600(
            data: Data(try legacyHost.encodeCanonicalJSON(pretty: true).utf8),
            to: dir.appendingPathComponent("host.json")
        )

        let legacyTel = TelemetryDocument(
            activeProfileId: "legacy-hk",
            outboundMode: "global",
            unreadUnexpectedCrash: true,
            lastCrashTimestampMs: 9999,
            lastCrashReason: "oom",
            profiles: ["legacy-hk": ProfileTelemetryEntry(latencyMs: 55, lastTestedMs: 8888, uploadBytes: 300, downloadBytes: 900)]
        )
        let telData = try JSONEncoder().encode(legacyTel)
        try WorkspaceStore.atomicWrite0600(data: telData, to: dir.appendingPathComponent("telemetry.json"))

        let db = NexusClientDatabase(rootDirectory: dir)
        let wsStore = WorkspaceStore(rootDirectory: dir, database: db)
        let hostStore = HostConfigStore(rootDirectory: dir, database: db)
        let telStore = TelemetryStore(rootDirectory: dir, database: db)

        let migratedWS = try await wsStore.loadOrInit()
        XCTAssertEqual(migratedWS.revision, 4)
        XCTAssertEqual(migratedWS.profiles.map(\.id), ["legacy-hk"])

        let migratedHost = try await hostStore.loadOrInit()
        XCTAssertEqual(migratedHost.logLevel, "debug")
        XCTAssertEqual(migratedHost.workers, 3)
        XCTAssertEqual(migratedHost.controlHttpListen, "127.0.0.1:9191")

        let migratedTel = await telStore.load()
        XCTAssertEqual(migratedTel.activeProfileId, "legacy-hk")
        XCTAssertEqual(migratedTel.outboundMode, "global")
        XCTAssertTrue(migratedTel.unreadUnexpectedCrash)
        XCTAssertEqual(migratedTel.profiles["legacy-hk"]?.latencyMs, 55)
        XCTAssertEqual(migratedTel.profiles["legacy-hk"]?.uploadBytes, 300)
        XCTAssertEqual(migratedTel.profiles["legacy-hk"]?.downloadBytes, 900)

        // Subsequent mutations live in SQLite even if legacy JSON files are deleted.
        try FileManager.default.removeItem(at: dir.appendingPathComponent("workspace.json"))
        try FileManager.default.removeItem(at: dir.appendingPathComponent("host.json"))
        try FileManager.default.removeItem(at: dir.appendingPathComponent("telemetry.json"))

        let reopenedDB = NexusClientDatabase(rootDirectory: dir)
        let reopenedWSStore = WorkspaceStore(rootDirectory: dir, database: reopenedDB)
        let reloadedWS = try await reopenedWSStore.loadOrInit()
        XCTAssertEqual(reloadedWS.profiles.map(\.id), ["legacy-hk"])
        let summaries = try await reopenedWSStore.listProfileSummaries()
        XCTAssertEqual(summaries.map(\.id), ["legacy-hk"])
        try await reopenedWSStore.shrinkMemory()

        let reloadedHost = try await HostConfigStore(rootDirectory: dir, database: reopenedDB).loadOrInit()
        XCTAssertEqual(reloadedHost.workers, 3)

        let reopenedTelStore = TelemetryStore(rootDirectory: dir, database: reopenedDB)
        let reloadedTel = await reopenedTelStore.load()
        XCTAssertEqual(reloadedTel.activeProfileId, "legacy-hk")
        try await reopenedTelStore.recordTrafficDelta(bucketHour: 500, profileId: "legacy-hk", uploadBytes: 120, downloadBytes: 480)
        let ledger = try await reopenedTelStore.queryTrafficLedger(sinceHour: 500, profileId: "legacy-hk")
        XCTAssertEqual(ledger, [TrafficLedgerRecord(bucketHour: 500, profileId: "legacy-hk", uploadBytes: 120, downloadBytes: 480)])
    }

    func testSyncRevisionActiveRoutingForwardSchemaGuardAndTrafficOnlyNoReimport() async throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let db = NexusClientDatabase(rootDirectory: dir)
        let doc = WorkspaceDocument(revision: 9, updatedAtMs: 1_700_000_009_000)
        try await db.saveWorkspace(doc)

        // Verify sync_revision meta key and active_routing_id application on load.
        let overwriteAttempt = try await db.saveWorkspaceIfEmpty(WorkspaceDocument(revision: 1))
        XCTAssertEqual(overwriteAttempt.revision, 9)
        let existingKV = try await db.setHostKVIfAbsent("k", value: "\"first\"")
        XCTAssertEqual(existingKV, "\"first\"")
        let secondKV = try await db.setHostKVIfAbsent("k", value: "\"second\"")
        XCTAssertEqual(secondKV, "\"first\"")
        await db.close()

        let rawRevision = try Self.readSyncRevisionAndSwitchActiveRouting(at: db.dbURL, activeRoutingID: "global")
        XCTAssertEqual(rawRevision, "9")

        let reloadedOpt = try await NexusClientDatabase(dbURL: db.dbURL).loadWorkspace()
        let reloaded = try XCTUnwrap(reloadedOpt)
        XCTAssertEqual(reloaded.revision, 9)
        XCTAssertEqual(reloaded.activeRoutingProfile().id, "global")
        XCTAssertTrue(reloaded.routingProfiles.first(where: { $0.id == "global" })?.isActive == true)
        XCTAssertTrue(reloaded.routingProfiles.first(where: { $0.id == "bypass-lan-cn" })?.isActive == false)

        // Forward schema version (> 1) must fail closed with unsupportedSchemaVersion.
        let futureURL = dir.appendingPathComponent("future.db")
        try Self.createDatabaseWithUserVersion(at: futureURL, version: 99)
        do {
            _ = try await NexusClientDatabase(dbURL: futureURL).loadWorkspace()
            XCTFail("Expected unsupportedSchemaVersion(99)")
        } catch let err as NexusDatabaseError {
            XCTAssertEqual(err, .unsupportedSchemaVersion(99))
        }

        // Traffic-only DB must NOT re-import stale telemetry.json on disk.
        let trafficDir = dir.appendingPathComponent("traffic-only", isDirectory: true)
        try FileManager.default.createDirectory(at: trafficDir, withIntermediateDirectories: true)
        let staleTel = TelemetryDocument(activeProfileId: "stale-id", outboundMode: "direct")
        try WorkspaceStore.atomicWrite0600(data: try JSONEncoder().encode(staleTel), to: trafficDir.appendingPathComponent("telemetry.json"))
        let trafficDB = NexusClientDatabase(rootDirectory: trafficDir)
        try await trafficDB.recordTrafficDelta(bucketHour: 700, profileId: "p-live", uploadBytes: 50, downloadBytes: 80)
        let hasTel = try await trafficDB.hasTelemetryData()
        XCTAssertTrue(hasTel)
        let loadedTel = await TelemetryStore(rootDirectory: trafficDir, database: trafficDB).load()
        XCTAssertEqual(loadedTel.activeProfileId, "")
        XCTAssertEqual(loadedTel.profiles["p-live"]?.uploadBytes, 50)
    }

    private static func readSyncRevisionAndSwitchActiveRouting(at url: URL, activeRoutingID: String) throws -> String {
        var rawDB: OpaquePointer?
        XCTAssertEqual(sqlite3_open_v2(url.path, &rawDB, SQLITE_OPEN_READWRITE, nil), SQLITE_OK)
        let opened = try XCTUnwrap(rawDB)
        defer { sqlite3_close_v2(opened) }
        var stmt: OpaquePointer?
        XCTAssertEqual(sqlite3_prepare_v2(opened, "SELECT value_json FROM workspace_meta WHERE key = 'sync_revision';", -1, &stmt, nil), SQLITE_OK)
        let rev: String
        do {
            defer { sqlite3_finalize(stmt) }
            XCTAssertEqual(sqlite3_step(stmt), SQLITE_ROW)
            rev = String(cString: try XCTUnwrap(sqlite3_column_text(stmt, 0)))
        }
        let sql = "UPDATE workspace_meta SET value_json = '\"\(activeRoutingID)\"' WHERE key = 'active_routing_id';"
        XCTAssertEqual(sqlite3_exec(opened, sql, nil, nil, nil), SQLITE_OK)
        return rev
    }

    private static func createDatabaseWithUserVersion(at url: URL, version: Int32) throws {
        var rawDB: OpaquePointer?
        XCTAssertEqual(sqlite3_open_v2(url.path, &rawDB, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil), SQLITE_OK)
        let opened = try XCTUnwrap(rawDB)
        defer { sqlite3_close_v2(opened) }
        XCTAssertEqual(sqlite3_exec(opened, "PRAGMA user_version = \(version);", nil, nil, nil), SQLITE_OK)
    }
}
