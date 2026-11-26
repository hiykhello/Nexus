import Foundation
import XCTest
@testable import NexusCoreBridge

final class Wave35InstrumentTests: XCTestCase {
    private static func assertSendable<T: Sendable>(_: T.Type) {}

    func testWave35TypesAreSendable() {
        Self.assertSendable(NexusThemePreset.self)
        Self.assertSendable(GroupLatencySummary.self)
        Self.assertSendable(SparklineOnsetMarker.self)
        Self.assertSendable(SparklineOnsetTracker.self)
        Self.assertSendable(DomainRouteExplanation.self)
    }

    func testThemePresetLegacyMigrationAndSqlitePersistence() async throws {
        XCTAssertEqual(NexusThemePreset.fromStored("dark"), .obsidian)
        XCTAssertEqual(NexusThemePreset.fromStored("obsidian"), .obsidian)
        XCTAssertEqual(NexusThemePreset.fromStored("light"), .paper)
        XCTAssertEqual(NexusThemePreset.fromStored("daylight"), .paper)
        XCTAssertEqual(NexusThemePreset.fromStored("paper"), .paper)
        XCTAssertEqual(NexusThemePreset.fromStored("amber"), .studioAmber)
        XCTAssertEqual(NexusThemePreset.fromStored("studio_amber"), .studioAmber)
        XCTAssertEqual(NexusThemePreset.fromStored("unknown"), .system)

        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nexus-w35-theme-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }
        let db = NexusClientDatabase(rootDirectory: tmpDir)

        let initial = await ThemePreferenceStore.load(from: db)
        XCTAssertEqual(initial, .system)

        try await ThemePreferenceStore.save(.studioAmber, to: db)
        let loaded = await ThemePreferenceStore.load(from: db)
        XCTAssertEqual(loaded, .studioAmber)

        try await ThemePreferenceStore.save(.paper, to: db)
        let loadedPaper = await ThemePreferenceStore.load(from: db)
        XCTAssertEqual(loadedPaper, .paper)
    }

    func testGroupLatencySummaryComputesP50FiveTiersAndRelativeMeter() {
        let empty = GroupLatencySummary.compute(members: [])
        XCTAssertEqual(empty.totalCount, 0)
        XCTAssertNil(empty.p50Ms)
        XCTAssertNil(empty.maxHealthyMs)

        let members: [OutboundMemberSnapshot] = [
            OutboundMemberSnapshot(name: "hk-1", state: "up", latencyMs: 40),
            OutboundMemberSnapshot(name: "sg-1", state: "up", latencyMs: 120),
            OutboundMemberSnapshot(name: "jp-1", state: "up", latencyMs: 220),
            OutboundMemberSnapshot(name: "us-1", state: "up", latencyMs: 400),
            OutboundMemberSnapshot(name: "eu-down", state: "timeout", latencyMs: -1),
            OutboundMemberSnapshot(name: "tw-idle", state: "idle", latencyMs: -1),
        ]
        let summary = GroupLatencySummary.compute(members: members)
        XCTAssertEqual(summary.totalCount, 6)
        XCTAssertEqual(summary.healthyCount, 4)
        XCTAssertEqual(summary.fastCount, 1)
        XCTAssertEqual(summary.goodCount, 1)
        XCTAssertEqual(summary.midCount, 1)
        XCTAssertEqual(summary.slowCount, 1)
        XCTAssertEqual(summary.timeoutCount, 1)
        XCTAssertEqual(summary.unprobedCount, 1)
        XCTAssertEqual(summary.p50Ms, 170) // (120 + 220) / 2
        XCTAssertEqual(summary.maxHealthyMs, 400)

        XCTAssertEqual(summary.relativeRatio(for: 400), 1.0)
        XCTAssertEqual(summary.relativeRatio(for: 200), 0.5)
        XCTAssertEqual(summary.relativeRatio(for: 10), 0.08) // clamped floor
        XCTAssertNil(summary.relativeRatio(for: nil))
        XCTAssertNil(summary.relativeRatio(for: -1))
    }

    func testSparklineOnsetTrackerShiftsAndEvictsExpiredMarkers() {
        var tracker = SparklineOnsetTracker(capacity: 4)
        tracker.record(label: "HK-01")
        XCTAssertEqual(tracker.markers.count, 1)
        XCTAssertEqual(tracker.markers[0].sampleIndex, 3)

        tracker.shiftLeft()
        XCTAssertEqual(tracker.markers[0].sampleIndex, 2)
        tracker.record(label: "全局")
        XCTAssertEqual(tracker.markers.count, 2)
        XCTAssertEqual(tracker.markers[1].sampleIndex, 3)

        tracker.shiftLeft()
        tracker.shiftLeft()
        tracker.shiftLeft()
        // First marker evicted (< 0), second marker shifted from 3 -> 0
        XCTAssertEqual(tracker.markers.count, 1)
        XCTAssertEqual(tracker.markers[0].label, "全局")
        XCTAssertEqual(tracker.markers[0].sampleIndex, 0)

        tracker.shiftLeft()
        XCTAssertTrue(tracker.markers.isEmpty)
    }

    func testDomainRouteExplainerHandlesModesRulesOpaqueWarningAndResolution() {
        XCTAssertTrue(DomainRouteExplainer.looksLikeDomainQuery("example.com"))
        XCTAssertTrue(DomainRouteExplainer.looksLikeDomainQuery("https://Sub.Example.COM:443/a"))
        XCTAssertFalse(DomainRouteExplainer.looksLikeDomainQuery(">reload"))
        XCTAssertFalse(DomainRouteExplainer.looksLikeDomainQuery("hk node"))
        XCTAssertFalse(DomainRouteExplainer.looksLikeDomainQuery("localhost"))
        XCTAssertEqual(DomainRouteExplainer.normalizeHost("https://API.GitHub.com:443/v1"), "api.github.com")

        let groups = [
            OutboundGroupSnapshot(
                tag: "proxy",
                mode: "selector",
                active: "HK-01",
                members: [OutboundMemberSnapshot(name: "HK-01", state: "up", latencyMs: 36)]
            ),
        ]
        let rules = [
            RuleMetric(index: 1, type: "rule-set", action: "outbound", target: "direct", summary: "cn-domains"),
            RuleMetric(index: 2, type: "domain-suffix", action: "outbound", target: "proxy", summary: "github.com"),
            RuleMetric(index: 3, type: "domain-keyword", action: "outbound", target: "direct", summary: "localcorp"),
            RuleMetric(index: 4, type: "final", action: "outbound", target: "proxy", summary: "match"),
        ]

        let directExp = DomainRouteExplainer.explain(domain: "github.com", outboundMode: "direct", rules: rules, groups: groups)
        XCTAssertEqual(directExp.targetTag, "direct")
        XCTAssertFalse(directExp.isEstimate)

        let globalExp = DomainRouteExplainer.explain(domain: "github.com", outboundMode: "global", rules: rules, groups: groups)
        XCTAssertEqual(globalExp.resolvedOutbound, "HK-01")
        XCTAssertEqual(globalExp.activeLatencyMs, 36)
        XCTAssertFalse(globalExp.isEstimate)

        let suffixExp = DomainRouteExplainer.explain(domain: "api.github.com", outboundMode: "rule", rules: rules, groups: groups)
        XCTAssertEqual(suffixExp.matchedRuleIndex, 2)
        XCTAssertEqual(suffixExp.resolvedOutbound, "HK-01")
        XCTAssertEqual(suffixExp.activeLatencyMs, 36)
        XCTAssertTrue(suffixExp.isEstimate)
        XCTAssertTrue(suffixExp.estimateNote.contains("规则预估"))

        let kwExp = DomainRouteExplainer.explain(domain: "git.localcorp.net", outboundMode: "rule", rules: rules, groups: groups)
        XCTAssertEqual(kwExp.matchedRuleIndex, 3)
        XCTAssertEqual(kwExp.targetTag, "direct")
    }

    func testFirstQueryableDomainExtractsPrefixedAndCommaPatterns() {
        XCTAssertEqual(DomainRouteExplainer.firstQueryableDomain(in: "domain-suffix: github.com"), "github.com")
        XCTAssertEqual(DomainRouteExplainer.firstQueryableDomain(in: "domain-suffix: .Example.COM, google.com"), "example.com")
        XCTAssertEqual(DomainRouteExplainer.firstQueryableDomain(in: "a.example.org, b.example.org"), "a.example.org")
        XCTAssertNil(DomainRouteExplainer.firstQueryableDomain(in: "10.0.0.0/8"))
        XCTAssertNil(DomainRouteExplainer.firstQueryableDomain(in: "192.168.1.1"))
        XCTAssertNil(DomainRouteExplainer.firstQueryableDomain(in: "domain-regex: ^foo\\.bar$"))
        XCTAssertNil(DomainRouteExplainer.firstQueryableDomain(in: "cn-domains"))
    }
}
