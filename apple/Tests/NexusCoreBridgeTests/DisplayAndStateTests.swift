import Foundation
import XCTest
@testable import NexusCoreBridge

final class DisplayAndStateTests: XCTestCase {
    private static func assertSendable<T: Sendable>(_: T.Type) {}

    func testDisplayCopyMapsRawStatesModesInboundsAndErrors() {
        Self.assertSendable(OptimisticTransition<String>.self)

        XCTAssertEqual(NexusDisplayCopy.coreStateTitle("running"), "运行中")
        XCTAssertEqual(NexusDisplayCopy.coreStateTitle("stopped"), "未连接")
        XCTAssertEqual(NexusDisplayCopy.coreStateTitle("degraded"), "降级运行")
        XCTAssertEqual(NexusDisplayCopy.coreStateTitle("error"), "异常")

        XCTAssertEqual(NexusDisplayCopy.outboundModeTitle("rule"), "规则")
        XCTAssertEqual(NexusDisplayCopy.outboundModeTitle("global"), "全局")
        XCTAssertEqual(NexusDisplayCopy.outboundModeTitle("direct"), "直连")

        XCTAssertEqual(NexusDisplayCopy.connectionInboundLabel(inbound: "mixed-in", listener: 1), "mixed-in")
        XCTAssertEqual(NexusDisplayCopy.connectionInboundLabel(inbound: "", listener: 2), "入站 #2")
        XCTAssertEqual(NexusDisplayCopy.connectionInboundLabel(inbound: "", listener: 0), "本地入站")

        let authErr = NexusDisplayCopy.friendlyErrorMessage(HttpControlError.httpStatus(401, "unauthorized"))
        XCTAssertTrue(authErr.contains("钥匙串"))
        XCTAssertFalse(authErr.contains("HTTP 401"))

        let connErr = NexusDisplayCopy.friendlyErrorMessage(URLError(.cannotConnectToHost))
        XCTAssertTrue(connErr.contains("无法连接"))
    }

    func testOptimisticTransitionCommitsAndRollsBackDeterministically() {
        var mode = OptimisticTransition(initial: "rule")
        let (prev, gen1) = mode.begin(to: "global")
        XCTAssertEqual(prev, "rule")
        XCTAssertEqual(gen1, 1)
        XCTAssertEqual(mode.current, "global")
        XCTAssertEqual(mode.pendingFrom, "rule")

        let reverted = mode.rollback(for: gen1)
        XCTAssertEqual(reverted, "rule")
        XCTAssertEqual(mode.current, "rule")
        XCTAssertNil(mode.pendingFrom)

        // Overlapping rapid switches: stale older generation must neither commit nor roll back newer choice,
        // and if the newest also fails, rollback restores the original last-confirmed baseline ("rule").
        let (_, gen2) = mode.begin(to: "global")
        let (baseline3, gen3) = mode.begin(to: "direct")
        XCTAssertEqual(baseline3, "rule")
        XCTAssertEqual(gen3, gen2 + 1)
        XCTAssertNil(mode.rollback(for: gen2))
        XCTAssertFalse(mode.commit("global", for: gen2))
        XCTAssertEqual(mode.current, "direct")
        XCTAssertEqual(mode.rollback(for: gen3), "rule")
        XCTAssertEqual(mode.current, "rule")

        let (_, gen4) = mode.begin(to: "direct")
        XCTAssertTrue(mode.commit("direct", for: gen4))
        XCTAssertEqual(mode.current, "direct")
        XCTAssertNil(mode.pendingFrom)
        XCTAssertEqual(mode.rollback(for: gen4), "direct")
    }

    func testCompactTabNormalizerPreventsUntaggedTabStranding() {
        let compactTabs = ["overview", "proxies", "rulesDns", "connections", "settings"]
        XCTAssertEqual(
            CompactTabNormalizer.normalize(selected: "workspace", compactTabs: compactTabs, fallback: "overview"),
            "overview"
        )
        XCTAssertEqual(
            CompactTabNormalizer.normalize(selected: "logs", compactTabs: compactTabs, fallback: "overview"),
            "overview"
        )
        XCTAssertEqual(
            CompactTabNormalizer.normalize(selected: "connections", compactTabs: compactTabs, fallback: "overview"),
            "connections"
        )
    }

    func testPlatformStatusLabelsContainZeroRawSdkJargon() {
        for backend in AppleTunnelBackend.allCases {
            XCTAssertFalse(backend.displayName.isEmpty)
            XCTAssertFalse(backend.displayName.contains("LaunchDaemon"))
            XCTAssertFalse(backend.displayName.contains("utun"))
        }
        for mode in TunElevationMode.allCases {
            XCTAssertFalse(mode.displayName.contains("LaunchDaemon"))
            XCTAssertFalse(mode.detailText.contains("SMAppService"))
            XCTAssertFalse(mode.detailText.contains("LaunchDaemon"))
        }
        let daemonStates: [DaemonRegistrationState] = [.enabled, .requiresApproval, .notRegistered, .unsupported]
        for state in daemonStates {
            XCTAssertFalse(state.summaryText.contains("LaunchDaemon"))
            XCTAssertFalse(state.summaryText.contains("SMAppService"))
        }
        XCTAssertFalse(LoginItemStatus.unsupported.summaryText.contains("SMAppService"))
    }
}
