import Foundation
import XCTest
@testable import NexusCoreBridge

final class HttpControlWebSocketTests: XCTestCase {
    private static func assertSendable<T: Sendable>(_: T.Type) {}

    func testWebSocketTypesAreSendable() {
        Self.assertSendable(ControlWsChannel.self)
        Self.assertSendable(ControlWsSubscribeRequest.self)
        Self.assertSendable(ControlWsEvent.self)
        Self.assertSendable(ConnectionsSnapshot.self)
        Self.assertSendable(StatusMetricsSnapshot.self)
    }

    func testBuildWebSocketRequestUsesAuthorizationHeaderAndNeverQueryToken() throws {
        let httpURL = try XCTUnwrap(URL(string: "http://127.0.0.1:9090/ignored?token=bad&secret=leak#frag"))
        let req = try HttpControlClient.buildWebSocketRequest(
            baseURL: httpURL,
            bearerToken: "ws-secret-bearer-token"
        )
        let wsURL = try XCTUnwrap(req.url)
        XCTAssertEqual(wsURL.scheme, "ws")
        XCTAssertEqual(wsURL.host, "127.0.0.1")
        XCTAssertEqual(wsURL.port, 9090)
        XCTAssertEqual(wsURL.path(percentEncoded: true), "/v1/ws")
        XCTAssertNil(wsURL.query)
        XCTAssertNil(wsURL.fragment)
        XCTAssertFalse(wsURL.absoluteString.contains("token="))
        XCTAssertFalse(wsURL.absoluteString.contains("secret="))
        XCTAssertFalse(wsURL.absoluteString.contains("ws-secret-bearer-token"))
        XCTAssertEqual(req.value(forHTTPHeaderField: "Authorization"), "Bearer ws-secret-bearer-token")

        // HTTPS baseURL upgrades to wss:// and omits Authorization when token is nil/empty.
        let httpsClient = HttpControlClient(baseURL: try XCTUnwrap(URL(string: "https://127.0.0.1:9443")), bearerToken: nil)
        let wssReq = try httpsClient.makeWebSocketRequest()
        XCTAssertEqual(wssReq.url?.scheme, "wss")
        XCTAssertEqual(wssReq.url?.path(percentEncoded: true), "/v1/ws")
        XCTAssertNil(wssReq.url?.query)
        XCTAssertNil(wssReq.value(forHTTPHeaderField: "Authorization"))

        // Non-HTTP/WS schemes must be rejected.
        let badURL = try XCTUnwrap(URL(string: "ftp://127.0.0.1:9090"))
        XCTAssertThrowsError(try HttpControlClient.buildWebSocketRequest(baseURL: badURL, bearerToken: "t"))
    }

    func testEncodeSubscribePayloadAndIntervalClamping() throws {
        let raw = try HttpControlClient.encodeWsSubscribeMessage(
            channels: [.logs, .connections, .metrics],
            since: 42,
            intervalMs: 1000
        )
        let decoded = try JSONDecoder().decode(ControlWsSubscribeRequest.self, from: Data(raw.utf8))
        XCTAssertEqual(decoded.type, "subscribe")
        XCTAssertEqual(decoded.channels, [.logs, .connections, .metrics])
        XCTAssertEqual(decoded.since, 42)
        XCTAssertEqual(decoded.intervalMs, 1000)
        XCTAssertTrue(raw.contains("\"type\":\"subscribe\""))
        XCTAssertTrue(raw.contains("\"interval_ms\":1000"))
        XCTAssertTrue(raw.contains("\"since\":42"))

        // Clamp interval bounds [200, 10000] and default empty channels to all channels.
        let low = ControlWsSubscribeRequest(channels: [], since: 0, intervalMs: 25)
        XCTAssertEqual(low.channels, ControlWsChannel.allCases)
        XCTAssertEqual(low.intervalMs, 200)

        let high = ControlWsSubscribeRequest(channels: [.metrics], since: 7, intervalMs: 99_000)
        XCTAssertEqual(high.channels, [.metrics])
        XCTAssertEqual(high.intervalMs, 10_000)
    }

    func testDecodeControlWsEventFrames() throws {
        // auth_ok
        let authEvent = try HttpControlClient.decodeControlWsEvent(Data(#"{"type":"auth_ok"}"#.utf8))
        XCTAssertEqual(authEvent, .authOk)

        // subscribed
        let subEvent = try HttpControlClient.decodeControlWsEvent(
            Data(#"{"type":"subscribed","channels":["logs","metrics","unknown_future"]}"#.utf8)
        )
        XCTAssertEqual(subEvent, .subscribed([.logs, .metrics]))

        // pong
        let pongEvent = try HttpControlClient.decodeControlWsEvent(Data(#"{"type":"pong"}"#.utf8))
        XCTAssertEqual(pongEvent, .pong)

        // log
        let logPayload = Data(#"{"type":"log","data":{"seq":"108","level":"warn","domain":"dns","event":204,"message":"upstream timeout"}}"#.utf8)
        let logEvent = try HttpControlClient.decodeControlWsEvent(logPayload)
        XCTAssertEqual(
            logEvent,
            .log(LogRingEntry(seq: 108, level: "warn", domain: "dns", eventCode: 204, message: "upstream timeout"))
        )

        // connections (canonical object wrapper)
        let connsPayload = Data(#"{"type":"connections","data":{"connections":[{"id":"c-7","listener":1,"inbound":"mixed","protocol":"tcp","path":"proxy","outbound":"HK-01","destination_port":443,"upload_bytes":"512","download_bytes":"2048","duration_ms":35,"can_close":true}]}}"#.utf8)
        let connsEvent = try HttpControlClient.decodeControlWsEvent(connsPayload)
        guard case .connections(let connSnap) = connsEvent else {
            return XCTFail("Expected .connections event")
        }
        XCTAssertEqual(connSnap.connections.count, 1)
        XCTAssertEqual(connSnap.connections[0].id, "c-7")
        XCTAssertEqual(connSnap.connections[0].outbound, "HK-01")
        XCTAssertEqual(connSnap.connections[0].uploadBytes, 512)
        XCTAssertEqual(connSnap.connections[0].downloadBytes, 2048)

        // connections (bare array tolerance)
        let bareConnsPayload = Data(#"{"type":"connections","data":[{"id":"c-8","protocol":"udp","path":"direct","destination_port":53}]}"#.utf8)
        let bareConnsEvent = try HttpControlClient.decodeControlWsEvent(bareConnsPayload)
        guard case .connections(let bareSnap) = bareConnsEvent else {
            return XCTFail("Expected .connections event for bare array")
        }
        XCTAssertEqual(bareSnap.connections.count, 1)
        XCTAssertEqual(bareSnap.connections[0].id, "c-8")

        // metrics (canonical /v1/status format)
        let metricsPayload = Data(#"{"type":"metrics","data":{"instance":"mac-1","state":"running","workers":2,"listeners":3,"control_generation":"12","active_sessions":9,"upload_bytes_total":"4096","download_bytes_total":"16384"}}"#.utf8)
        let metricsEvent = try HttpControlClient.decodeControlWsEvent(metricsPayload)
        XCTAssertEqual(
            metricsEvent,
            .metrics(StatusMetricsSnapshot(
                instance: "mac-1",
                state: "running",
                workers: 2,
                listeners: 3,
                controlGeneration: 12,
                activeSessions: 9,
                uploadBytesTotal: 4096,
                downloadBytesTotal: 16384
            ))
        )

        // metrics (compact upload_bytes/download_bytes fallback keys)
        let compactMetricsPayload = Data(#"{"type":"metrics","data":{"state":"running","active_sessions":2,"upload_bytes":111,"download_bytes":222}}"#.utf8)
        let compactEvent = try HttpControlClient.decodeControlWsEvent(compactMetricsPayload)
        guard case .metrics(let compactSnap) = compactEvent else {
            return XCTFail("Expected .metrics event")
        }
        XCTAssertEqual(compactSnap.uploadBytesTotal, 111)
        XCTAssertEqual(compactSnap.downloadBytesTotal, 222)

        // server error frame
        let errEvent = try HttpControlClient.decodeControlWsEvent(
            Data(#"{"type":"error","code":"unauthorized","message":"invalid token"}"#.utf8)
        )
        XCTAssertEqual(errEvent, .serverError(code: "unauthorized", message: "invalid token"))

        // unknown future frame returns nil (ignored cleanly)
        let unknownEvent = try HttpControlClient.decodeControlWsEvent(Data(#"{"type":"heartbeat"}"#.utf8))
        XCTAssertNil(unknownEvent)

        // malformed JSON throws
        XCTAssertThrowsError(try HttpControlClient.decodeControlWsEvent(Data("not-json".utf8)))
    }

    func testStreamControlWebSocketRejectsInvalidSchemeImmediately() async throws {
        let client = HttpControlClient(baseURL: try XCTUnwrap(URL(string: "ftp://127.0.0.1:9090")), bearerToken: "t")
        var threwInvalidURL = false
        do {
            for try await _ in client.streamControlWebSocket() {}
        } catch HttpControlError.invalidURL {
            threwInvalidURL = true
        }
        XCTAssertTrue(threwInvalidURL)
    }
}
