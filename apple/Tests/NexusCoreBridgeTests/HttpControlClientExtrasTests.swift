import Foundation
import XCTest
@testable import NexusCoreBridge
#if canImport(NetworkExtension)
import NetworkExtension
#endif

/// Thread-safe `URLProtocol` stub keyed by unique host so parallel XCTest runs stay fully isolated.
private final class MockControlURLProtocol: URLProtocol, @unchecked Sendable {
    typealias Handler = @Sendable (URLRequest) throws -> (Int, [String: String], Data)

    /// Concurrency invariant: all mutable accesses to `handlers` are guarded by `lock`.
    private static let lock = NSLock()
    nonisolated(unsafe) private static var handlers: [String: Handler] = [:]

    static func register(host: String, handler: @escaping Handler) {
        lock.withLock { handlers[host] = handler }
    }

    static func unregister(host: String) {
        lock.withLock { _ = handlers.removeValue(forKey: host) }
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url, let host = url.host else {
            client?.urlProtocol(self, didFailWithError: URLError(.badURL))
            return
        }
        let handler = Self.lock.withLock { Self.handlers[host] }
        guard let handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.cannotFindHost))
            return
        }
        do {
            let (status, headers, body) = try handler(request)
            let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            if !body.isEmpty {
                client?.urlProtocol(self, didLoad: body)
            }
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

final class HttpControlClientExtrasTests: XCTestCase {
    private static func assertSendable<T: Sendable>(_: T.Type) {}

    private func makeMockClient(
        bearerToken: String? = "test-secret-token-1234",
        handler: @escaping MockControlURLProtocol.Handler
    ) -> (client: HttpControlClient, host: String) {
        let host = "mock-\(UUID().uuidString.lowercased()).nexus.test"
        MockControlURLProtocol.register(host: host, handler: handler)
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [MockControlURLProtocol.self]
        let url = URL(string: "http://\(host):9090")!
        let client = HttpControlClient(baseURL: url, bearerToken: bearerToken, timeoutSeconds: 5.0, sessionConfiguration: cfg)
        return (client, host)
    }

    func testSendableConformancesAndPureDecoders() throws {
        Self.assertSendable(RuleMetric.self)
        Self.assertSendable(DnsQueryAnswer.self)
        Self.assertSendable(DnsQueryResponse.self)
        Self.assertSendable(FakeIpFlushResult.self)
        Self.assertSendable(OutboundProbeResult.self)
        Self.assertSendable(ControlModeSnapshot.self)
        Self.assertSendable(StatusSnapshot.self)
        Self.assertSendable(ControlEventItem.self)
        Self.assertSendable(ControlEventsSnapshot.self)
        Self.assertSendable(SseFrame.self)
        Self.assertSendable(SseLineParser.self)
        Self.assertSendable(AppleTunnelHttpProxyConfig.self)
        Self.assertSendable(HttpControlClient.self)

        let rulesJSON = Data(#"{"rules":[{"index":1,"type":"domain-suffix","action":"outbound","target":"proxy","summary":"example.com"},{"index":2,"type":"ip-cidr","action":"outbound","target":"direct","summary":"10.0.0.0/8"}]}"#.utf8)
        let rules = try HttpControlClient.decodeRules(rulesJSON)
        XCTAssertEqual(rules.count, 2)
        XCTAssertEqual(rules[0].index, 1)
        XCTAssertEqual(rules[0].target, "proxy")
        XCTAssertEqual(rules[1].summary, "10.0.0.0/8")

        let dnsJSON = Data(#"{"name":"example.com","type":"A","rcode":0,"rcode_name":"NOERROR","ttl":300,"elapsed_ms":14,"answers":[{"name":"example.com","type":"A","ttl":300,"data":"93.184.216.34"}]}"#.utf8)
        let dns = try HttpControlClient.decodeDnsQuery(dnsJSON)
        XCTAssertEqual(dns.rcode, 0)
        XCTAssertEqual(dns.rcodeName, "NOERROR")
        XCTAssertEqual(dns.elapsedMs, 14)
        XCTAssertEqual(dns.answers.count, 1)
        XCTAssertEqual(dns.answers[0].data, "93.184.216.34")

        let pendingDnsJSON = Data(#"{"id":9,"name":"slow.example","type":"AAAA","state":"pending"}"#.utf8)
        let pendingDns = try HttpControlClient.decodeDnsQuery(pendingDnsJSON)
        XCTAssertEqual(pendingDns.state, "pending")
        XCTAssertTrue(pendingDns.answers.isEmpty)

        let probeJSON = Data(#"{"outbound":"hk-1","resolved_outbound":"hk-1","state":"up","latency_ms":42,"status_code":204,"url":"https://www.gstatic.com/generate_204"}"#.utf8)
        let probe = try HttpControlClient.decodeOutboundProbe(probeJSON)
        XCTAssertEqual(probe.outbound, "hk-1")
        XCTAssertEqual(probe.latencyMs, 42)
        XCTAssertEqual(probe.statusCode, 204)

        let nullProbeJSON = Data(#"{"outbound":"jp-down","resolved_outbound":"jp-down","state":"down","latency_ms":null,"url":"https://www.gstatic.com/generate_204"}"#.utf8)
        let nullProbe = try HttpControlClient.decodeOutboundProbe(nullProbeJSON)
        XCTAssertEqual(nullProbe.state, "down")
        XCTAssertNil(nullProbe.latencyMs)

        let statusJSON = Data(#"{"instance":"apple-1","state":"running","workers":4,"listeners":2,"control_generation":"9","active_sessions":7,"upload_bytes_total":"4096","download_bytes_total":"16384"}"#.utf8)
        let status = try HttpControlClient.decodeStatus(statusJSON)
        XCTAssertEqual(status.workers, 4)
        XCTAssertEqual(status.controlGeneration, 9)
        XCTAssertEqual(status.downloadBytesTotal, 16384)

        // Core live log JSON emits "event", while legacy fixtures use "event_code".
        let liveLogEntry = try JSONDecoder().decode(
            LogRingEntry.self,
            from: Data(#"{"seq":"21","level":"info","domain":"net","event":107,"message":"connected"}"#.utf8)
        )
        XCTAssertEqual(liveLogEntry.eventCode, 107)
        let legacyLogEntry = try JSONDecoder().decode(
            LogRingEntry.self,
            from: Data(#"{"seq":"22","level":"warn","domain":"tls","event_code":205,"message":"retry"}"#.utf8)
        )
        XCTAssertEqual(legacyLogEntry.eventCode, 205)

        // Manual selection allowed only on selector/select/url-test (not fallback/load-balance).
        XCTAssertTrue(OutboundGroupSnapshot(tag: "g1", mode: "selector", active: "a").supportsManualSelection)
        XCTAssertTrue(OutboundGroupSnapshot(tag: "g2", mode: "url-test", active: "a").supportsManualSelection)
        XCTAssertFalse(OutboundGroupSnapshot(tag: "g3", mode: "fallback", active: "a").supportsManualSelection)
        XCTAssertFalse(OutboundGroupSnapshot(tag: "g4", mode: "load-balance", active: "a").supportsManualSelection)
    }

    func testSseLineParserHandlesBlankDelimitersMultilineDataCrlfAndKeepalive() {
        var parser = SseLineParser()
        let raw = ": keepalive\r\n\r\nevent: log\r\nid: 42\r\ndata: {\"seq\":\"42\"}\r\n\r\nevent: status\ndata: line1\ndata: line2\n\n"
        // Feed in small irregular byte chunks to verify stateful framing across TCP boundaries.
        let bytes = Array(raw.utf8)
        var frames: [SseFrame] = []
        var offset = 0
        while offset < bytes.count {
            let end = min(bytes.count, offset + 7)
            frames.append(contentsOf: parser.feedBytes(bytes[offset..<end]))
            offset = end
        }
        if let tail = parser.finish() { frames.append(tail) }

        XCTAssertEqual(frames.count, 2)
        XCTAssertEqual(frames[0], SseFrame(event: "log", data: #"{"seq":"42"}"#, id: "42"))
        XCTAssertEqual(frames[1], SseFrame(event: "status", data: "line1\nline2", id: "42"))
    }

    func testWave32HttpControlRoutesAndBearerAuthorization() async throws {
        let (client, host) = makeMockClient(bearerToken: "bearer-wave32-token") { req in
            guard req.value(forHTTPHeaderField: "Authorization") == "Bearer bearer-wave32-token" else {
                return (401, ["Content-Type": "application/json"], Data(#"{"error":"unauthorized"}"#.utf8))
            }
            let path = req.url?.path(percentEncoded: true) ?? ""
            let query = req.url?.query(percentEncoded: true) ?? ""
            switch (req.httpMethod ?? "GET", path) {
            case ("GET", "/v1/rules"):
                return (200, [:], Data(#"{"rules":[{"index":1,"type":"domain","action":"outbound","target":"proxy","summary":"github.com"}]}"#.utf8))
            case ("GET", "/v1/dns/query"):
                XCTAssertTrue(query.contains("name=example.com"))
                XCTAssertTrue(query.contains("type=AAAA"))
                XCTAssertTrue(query.contains("server=remote"))
                return (200, [:], Data(#"{"name":"example.com","type":"AAAA","rcode":0,"rcode_name":"NOERROR","ttl":120,"elapsed_ms":9,"answers":[{"name":"example.com","type":"AAAA","ttl":120,"data":"2606:2800:220:1::1"}]}"#.utf8))
            case ("POST", "/v1/cache/fakeip/flush"):
                return (200, [:], Data(#"{"flushed":17,"fakeip":true}"#.utf8))
            case ("POST", "/v1/state/clear-cache"):
                XCTAssertTrue(query.contains("scope=dns"))
                return (200, [:], Data(#"{"target":"dns","cleared":true,"detail":"ok"}"#.utf8))
            case ("POST", "/v1/outbounds/HK%20Node/probe"):
                return (200, [:], Data(#"{"outbound":"HK Node","resolved_outbound":"HK Node","state":"up","latency_ms":27,"status_code":204,"url":"https://www.gstatic.com/generate_204"}"#.utf8))
            case ("POST", "/v1/log-level"):
                return (200, [:], Data(#"{"domain":"dns","level":"debug"}"#.utf8))
            case ("PUT", "/v1/mode"):
                return (200, [:], Data(#"{"mode":"global","outbound":"proxy"}"#.utf8))
            case ("GET", "/v1/events"):
                return (200, [:], Data(#"{"instance":"i1","next":5,"latest":5,"gap":false,"events":[{"id":4,"event":"reload","control_generation":2}]}"#.utf8))
            default:
                return (404, [:], Data("not found: \(path)".utf8))
            }
        }
        defer { MockControlURLProtocol.unregister(host: host) }

        let rules = try await client.fetchRules()
        XCTAssertEqual(rules.count, 1)
        XCTAssertEqual(rules[0].summary, "github.com")

        let dns = try await client.queryDns(name: "example.com", type: "aaaa", server: "remote")
        XCTAssertEqual(dns.rcodeName, "NOERROR")
        XCTAssertEqual(dns.answers.first?.data, "2606:2800:220:1::1")

        let flushed = try await client.flushFakeIpCache()
        XCTAssertEqual(flushed, FakeIpFlushResult(flushed: 17, fakeip: true))

        try await client.clearCache(scope: "dns")

        let probe = try await client.probeOutbound(tag: "HK Node", timeoutMs: 3000, mode: "http")
        XCTAssertEqual(probe.outbound, "HK Node")
        XCTAssertEqual(probe.latencyMs, 27)

        try await client.setLogLevel(domain: "dns", level: "debug")

        let mode = try await client.setMode("global", outbound: "proxy")
        XCTAssertEqual(mode, ControlModeSnapshot(mode: "global", outbound: "proxy"))

        let events = try await client.fetchEvents(cursor: 0)
        XCTAssertEqual(events.next, 5)
        XCTAssertEqual(events.events.first?.event, "reload")
    }

    func testSseStreamingLogsAndStatusOverHttpControlClient() async throws {
        let sseLogsBody = Data("event: log\ndata: {\"seq\":\"10\",\"level\":\"info\",\"domain\":\"dns\",\"event_code\":1,\"message\":\"resolved\"}\n\n: keepalive\n\nevent: log\ndata: {\"seq\":\"11\",\"level\":\"warn\",\"domain\":\"route\",\"event_code\":2,\"message\":\"fallback\"}\n\n".utf8)
        let sseStatusBody = Data("event: status\ndata: {\"instance\":\"mac\",\"state\":\"running\",\"workers\":2,\"listeners\":1,\"control_generation\":\"3\",\"active_sessions\":5,\"upload_bytes_total\":\"100\",\"download_bytes_total\":\"200\"}\n\n".utf8)

        let (client, host) = makeMockClient(bearerToken: "sse-token-9999") { req in
            guard req.value(forHTTPHeaderField: "Authorization") == "Bearer sse-token-9999",
                  req.value(forHTTPHeaderField: "Accept") == "text/event-stream"
            else {
                return (401, [:], Data())
            }
            let path = req.url?.path(percentEncoded: true) ?? ""
            let query = req.url?.query(percentEncoded: true) ?? ""
            XCTAssertTrue(query.contains("stream=1"))
            if path == "/v1/logs" {
                return (200, ["Content-Type": "text/event-stream"], sseLogsBody)
            }
            if path == "/v1/status" {
                return (200, ["Content-Type": "text/event-stream"], sseStatusBody)
            }
            return (404, [:], Data())
        }
        defer { MockControlURLProtocol.unregister(host: host) }

        var receivedLogs: [LogRingEntry] = []
        for try await entry in client.streamLogs(level: "info") {
            receivedLogs.append(entry)
        }
        XCTAssertEqual(receivedLogs.count, 2)
        XCTAssertEqual(receivedLogs[0].seq, 10)
        XCTAssertEqual(receivedLogs[1].domain, "route")

        var receivedStatuses: [StatusSnapshot] = []
        for try await snap in client.streamStatus(intervalMs: 500) {
            receivedStatuses.append(snap)
        }
        XCTAssertEqual(receivedStatuses.count, 1)
        XCTAssertEqual(receivedStatuses[0].workers, 2)
        XCTAssertEqual(receivedStatuses[0].activeSessions, 5)
    }

    func testTunnelSettingsBuilderWiresOptionalNEProxySettings() throws {
        // Parsing IPv4, IPv6, and invalid listen strings.
        let v4 = AppleTunnelHttpProxyConfig.parseHostPort("127.0.0.1:7890")
        XCTAssertEqual(v4?.host, "127.0.0.1")
        XCTAssertEqual(v4?.port, 7890)

        let v6 = AppleTunnelHttpProxyConfig.parseHostPort("[::1]:7891")
        XCTAssertEqual(v6?.host, "::1")
        XCTAssertEqual(v6?.port, 7891)

        XCTAssertNil(AppleTunnelHttpProxyConfig.parseHostPort("invalid-listen"))
        XCTAssertNil(AppleTunnelHttpProxyConfig.parseHostPort("127.0.0.1:0"))

        // Disabled by default in AppleHostConfig.
        var hostCfg = AppleHostConfig()
        XCTAssertNil(AppleTunnelHttpProxyConfig.fromHostConfig(hostCfg))

        hostCfg.desktop.tunHttpProxyEnabled = true
        hostCfg.desktop.mixedListen = "127.0.0.1:7890"
        hostCfg.desktop.tunHttpProxyBypass = ["localhost", "*.corp.lan"]
        let derived = try XCTUnwrap(AppleTunnelHttpProxyConfig.fromHostConfig(hostCfg))
        XCTAssertTrue(derived.isEffective)
        XCTAssertEqual(derived.host, "127.0.0.1")
        XCTAssertEqual(derived.port, 7890)
        XCTAssertEqual(derived.effectiveBypassDomains, ["localhost", "*.corp.lan"])

        let inactiveProxy = AppleTunnelHttpProxyConfig(enabled: false, host: "127.0.0.1", port: 7890)
        XCTAssertFalse(inactiveProxy.isEffective)

        #if canImport(NetworkExtension)
        let plainSettings = TunnelSettingsBuilder.build(from: AppleTunnelProfile())
        XCTAssertNil(plainSettings.proxySettings)

        let proxyProfile = AppleTunnelProfile(httpProxy: derived)
        let proxySettings = TunnelSettingsBuilder.build(from: proxyProfile)
        let neProxy = try XCTUnwrap(proxySettings.proxySettings)
        XCTAssertTrue(neProxy.httpEnabled)
        XCTAssertTrue(neProxy.httpsEnabled)
        XCTAssertEqual(neProxy.httpServer?.address, "127.0.0.1")
        XCTAssertEqual(neProxy.httpServer?.port, 7890)
        XCTAssertEqual(neProxy.httpsServer?.address, "127.0.0.1")
        XCTAssertEqual(neProxy.httpsServer?.port, 7890)
        XCTAssertTrue(neProxy.excludeSimpleHostnames)
        XCTAssertEqual(neProxy.exceptionList, ["localhost", "*.corp.lan"])
        #endif
    }

    func testWave32WorkspaceCanonicalSnakeCaseParityRoundTrip() throws {
        let doc = WorkspaceDocument(
            revision: 3,
            profiles: [
                WorkspaceProfileItem(
                    id: "w32-node",
                    remarks: "Wave32-Node",
                    kind: .node,
                    node: WorkspaceNodeConfig(
                        protocolName: "vless",
                        server: "edge.example.com",
                        port: 443,
                        tls: WorkspaceTlsConfig(
                            enabled: true,
                            sni: "edge.example.com",
                            echMode: "dns",
                            echQueryServerName: "dns.example.com",
                            fragment: true,
                            recordFragment: true
                        ),
                        transport: WorkspaceTransportConfig(
                            type: "websocket",
                            path: "/ws",
                            maxEarlyData: 2048,
                            earlyDataHeaderName: "Sec-WebSocket-Protocol",
                            grpcIdleTimeoutMs: 15_000,
                            grpcPingTimeoutMs: 5_000,
                            grpcPermitWithoutStream: true
                        ),
                        multiplex: WorkspaceMultiplexConfig(enabled: true, protocolName: "h2mux", maxConnections: 4)
                    )
                ),
                WorkspaceProfileItem(
                    id: "w32-group",
                    remarks: "Wave32-Group",
                    kind: .policyGroup,
                    policyGroup: WorkspacePolicyGroupConfig(
                        strategy: "url-test",
                        memberIds: ["w32-node"],
                        interruptExistConnections: true
                    )
                ),
            ],
            routingProfiles: [
                WorkspaceRoutingProfile(
                    id: "w32-route",
                    name: "Wave32",
                    isActive: true,
                    autoDetectInterface: true,
                    findProcess: true
                ),
            ]
        )
        let json = try doc.encodeCanonicalJSON(pretty: false)
        XCTAssertTrue(json.contains("\"interrupt_exist_connections\":true"))
        XCTAssertTrue(json.contains("\"auto_detect_interface\":true"))
        XCTAssertTrue(json.contains("\"find_process\":true"))
        XCTAssertTrue(json.contains("\"ech_query_server_name\":\"dns.example.com\""))
        XCTAssertTrue(json.contains("\"fragment\":true"))
        XCTAssertTrue(json.contains("\"record_fragment\":true"))
        XCTAssertTrue(json.contains("\"max_early_data\":2048"))
        XCTAssertTrue(json.contains("\"early_data_header_name\":\"Sec-WebSocket-Protocol\""))
        XCTAssertTrue(json.contains("\"grpc_idle_timeout_ms\":15000"))
        XCTAssertTrue(json.contains("\"grpc_ping_timeout_ms\":5000"))
        XCTAssertTrue(json.contains("\"grpc_permit_without_stream\":true"))
        XCTAssertTrue(json.contains("\"protocol\":\"h2mux\""))
        let decoded = try WorkspaceDocument.decodeCanonicalJSON(json)
        XCTAssertEqual(decoded, doc)
    }
}
