import XCTest
@testable import NexusCoreBridge

final class NexusCoreBridgeTests: XCTestCase {
    func testBuildsValidNexus1Frame() throws {
        let data = try ControlSocketClient.buildFrame(["select", "proxy", "tokyo"])
        XCTAssertEqual(String(decoding: data, as: UTF8.self), "NEXUS/1 select\0proxy\0tokyo")
    }

    func testRejectsEmptyOrNulTokens() {
        XCTAssertThrowsError(try ControlSocketClient.buildFrame([]))
        XCTAssertThrowsError(try ControlSocketClient.buildFrame(["status", ""]))
        XCTAssertThrowsError(try ControlSocketClient.buildFrame(["bad\0token"]))
    }

    func testEnforcesMacOs104ByteSunPathLimit() throws {
        try ControlSocketClient.validateSocketPath("/var/run/org.nexus.apple/c.sock")
        let tooLong = "/" + String(repeating: "a", count: 104)
        XCTAssertThrowsError(try ControlSocketClient.validateSocketPath(tooLong))
    }

    func testTunnelProfilePreservesMdnsAndPrivateNetworks() {
        let profile = AppleTunnelProfile()
        let v4 = profile.ipv4ExcludedRoutes()
        XCTAssertTrue(v4.contains { $0.address == "192.168.0.0" && $0.mask == "255.255.0.0" })
        XCTAssertTrue(v4.contains { $0.address == "224.0.0.251" && $0.mask == "255.255.255.255" })

        let v6 = profile.ipv6ExcludedRoutes()
        XCTAssertTrue(v6.contains { $0.address == "fe80::" && $0.prefix == 10 })
        XCTAssertTrue(v6.contains { $0.address == "ff02::fb" && $0.prefix == 128 })
    }

    func testParsesOpenMetricsAndOutboundsJson() throws {
        let sample = """
        # HELP nexus_control_generation gen
        nexus_control_generation 5
        nexus_active_sessions{listener="0"} 3
        nexus_traffic_upload_bytes_total{listener="0"} 2048
        nexus_traffic_download_bytes_total{listener="0"} 8192
        """
        let m = HttpControlClient.parseOpenMetrics(sample)
        XCTAssertEqual(m, MetricsSnapshot(controlGeneration: 5, activeSessions: 3, uploadBytes: 2048, downloadBytes: 8192))

        let json = Data(#"{"groups":[{"name":"auto","mode":"url-test","selected":"hk","override":true,"members":[{"name":"hk","state":"up","latency_ms":35}]}]}"#.utf8)
        let groups = try HttpControlClient.decodeOutbounds(json)
        XCTAssertEqual(groups.count, 1)
        XCTAssertEqual(groups[0].tag, "auto")
        XCTAssertTrue(groups[0].manualOverride)
        XCTAssertEqual(groups[0].members.first?.latencyMs, 35)
    }

    func testBuildsResetGroupAutoFrame() throws {
        let frame = try ControlSocketClient.buildFrame(["select", "auto", "--auto"])
        XCTAssertEqual(String(decoding: frame, as: UTF8.self), "NEXUS/1 select\0auto\0--auto")

        let netChange = try ControlSocketClient.buildFrame(["network-change", "7"])
        XCTAssertEqual(String(decoding: netChange, as: UTF8.self), "NEXUS/1 network-change\07")

        let closeAny = try ControlSocketClient.buildFrame(["close-any", "42"])
        XCTAssertEqual(String(decoding: closeAny, as: UTF8.self), "NEXUS/1 close-any\042")

        let closeAll = try ControlSocketClient.buildFrame(["close-all"])
        XCTAssertEqual(String(decoding: closeAll, as: UTF8.self), "NEXUS/1 close-all")

        let probe = try ControlSocketClient.buildFrame(["probe", "auto"])
        XCTAssertEqual(String(decoding: probe, as: UTF8.self), "NEXUS/1 probe\0auto")
    }

    func testDecodesConnectionsJsonAndLaunchConfig() throws {
        let connJson = Data(#"{"connections":[{"id":"42","listener":0,"protocol":"socks5","path":"direct","destination_port":443,"upload_bytes":"1024","download_bytes":"8192"}]}"#.utf8)
        let conns = try HttpControlClient.decodeConnections(connJson)
        XCTAssertEqual(conns.count, 1)
        XCTAssertEqual(conns[0].id, "42")
        XCTAssertEqual(conns[0].protocolName, "socks5")
        XCTAssertEqual(conns[0].destinationPort, 443)
        XCTAssertEqual(conns[0].downloadBytes, 8192)

        let cfg = PacketTunnelLaunchConfig(httpControlPort: 9091, memoryBudgetMiB: 32)
        let encoded = try JSONEncoder().encode(cfg)
        let decoded = try JSONDecoder().decode(PacketTunnelLaunchConfig.self, from: encoded)
        XCTAssertEqual(decoded, cfg)

        let diagJson = Data(#"{"instance":"abc","authorized_requests":12,"unauthorized_requests":1,"expired_requests":0,"reply_failed":0,"listeners":1,"active_connections":2}"#.utf8)
        let diag = try HttpControlClient.decodeDiagnostics(diagJson)
        XCTAssertEqual(diag.authorizedRequests, 12)
        XCTAssertEqual(diag.activeConnections, 2)

        let ewmaJson = Data(#"{"groups":[{"name":"auto","mode":"url-test","selected":"hk","override":false,"members":[{"name":"hk","state":"up","latency_ms":35,"ewma_ms":38,"breaker_open":false},{"name":"jp","state":"down","ewma_ms":120,"breaker_open":true}]}]}"#.utf8)
        let groups = try HttpControlClient.decodeOutbounds(ewmaJson)
        XCTAssertEqual(groups[0].members[0].ewmaMs, 38)
        XCTAssertTrue(groups[0].members[1].breakerOpen)

        let detailJson = Data(#"{"id":"42","listener":0,"inbound":"socks","protocol":"socks5","path":"direct","source":"127.0.0.1:50000","target":"1.1.1.1:443","outbound":"direct","route_mode":"ordered","route_rule":"1","process_path":"/usr/bin/curl","source_uid":501,"destination_port":443,"duration_ms":"150","upload_bytes":"1024","download_bytes":"2048","can_close":true}"#.utf8)
        let detail = try HttpControlClient.decodeConnectionDetail(detailJson)
        XCTAssertEqual(detail.inbound, "socks")
        XCTAssertEqual(detail.outbound, "direct")
        XCTAssertEqual(detail.processPath, "/usr/bin/curl")
        XCTAssertEqual(detail.sourceUid, 501)
        XCTAssertTrue(detail.canClose)

        let logsJson = Data(#"{"latest_seq":"15","evicted":"3","entries":[{"seq":"14","level":"info","domain":"core","event_code":100,"message":"started"},{"seq":"15","level":"trace","domain":"route","event_code":102,"message":"matched"}]}"#.utf8)
        let logsSnap = try HttpControlClient.decodeLogs(logsJson)
        XCTAssertEqual(logsSnap.latestSeq, 15)
        XCTAssertEqual(logsSnap.evicted, 3)
        XCTAssertEqual(logsSnap.entries.count, 2)
        XCTAssertEqual(logsSnap.entries[1].level, "trace")

        let trojan = try ShareLinkParser.parse("trojan://secretpass@tr.example.com:443?sni=tr.example.com&type=ws&path=%2Fws&host=cdn.example.com&certificate-sha256=abcdef01#TR")
        let rendered = ShareLinkParser.renderKdlOutbound(trojan, secretFilePath: "/etc/nexus/tr.pass")
        XCTAssertTrue(rendered.contains(#"outbound "TR" type="trojan""#))
        XCTAssertTrue(rendered.contains(#"password-file "/etc/nexus/tr.pass""#))
        XCTAssertTrue(rendered.contains(#"certificate-sha256 "abcdef01""#))
        XCTAssertTrue(rendered.contains(#"transport "websocket""#))
        XCTAssertFalse(rendered.contains("verify #true"))

        let anytls = try ShareLinkParser.parse("anytls://anypass@any.example.com:443?sni=any.example.com&type=grpc&serviceName=tun&authority=any.example.com#AnyNode")
        let anyKdl = ShareLinkParser.renderKdlOutbound(anytls, secretFilePath: "/etc/nexus/any.pass")
        XCTAssertTrue(anyKdl.contains(#"outbound "AnyNode" type="anytls""#))
        XCTAssertTrue(anyKdl.contains(#"transport "grpc""#))
        XCTAssertTrue(anyKdl.contains(#"service-name "tun""#))

        let tuic = try ShareLinkParser.parse("tuic://11111111-2222-3333-4444-555555555555:tuicpass@t.example.com:8443?sni=t.example.com&congestion_control=bbr#TUIC")
        let tuicKdl = ShareLinkParser.renderKdlOutbound(tuic, secretFilePath: "/etc/nexus/tuic.pass")
        XCTAssertTrue(tuicKdl.contains(#"outbound "TUIC" type="tuic""#))
        XCTAssertTrue(tuicKdl.contains(#"uuid "11111111-2222-3333-4444-555555555555""#))
        XCTAssertTrue(tuicKdl.contains(#"congestion-control "bbr""#))

        let snell = try ShareLinkParser.parse("snell://pskvalue@sn.example.com:6160?version=5&obfs=http&obfs-host=bing.com#Snell5")
        let snellKdl = ShareLinkParser.renderKdlOutbound(snell, secretFilePath: "/etc/nexus/sn.psk")
        XCTAssertTrue(snellKdl.contains(#"outbound "Snell5" type="snell""#))
        XCTAssertTrue(snellKdl.contains("version 5"))
        XCTAssertTrue(snellKdl.contains(#"psk-file "/etc/nexus/sn.psk""#))
        XCTAssertTrue(snellKdl.contains(#"obfs "http""#))

        let ssh = try ShareLinkParser.parse("ssh://alice:s3cr3t@bastion.example.com:2222?host-key-sha256=SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU&cipher=chacha20-poly1305@openssh.com#Bastion")
        let sshKdl = ShareLinkParser.renderKdlOutbound(ssh, secretFilePath: "/etc/nexus/ssh.pass")
        XCTAssertTrue(sshKdl.contains(#"outbound "Bastion" type="ssh""#))
        XCTAssertTrue(sshKdl.contains(#"user "alice""#))
        XCTAssertTrue(sshKdl.contains(#"password-file "/etc/nexus/ssh.pass""#))
        XCTAssertTrue(sshKdl.contains(#"host-key-sha256 "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU""#))
        XCTAssertTrue(sshKdl.contains(#"cipher "chacha20-poly1305@openssh.com""#))
        XCTAssertFalse(sshKdl.contains("s3cr3t"))

        let nh2 = try ShareLinkParser.parse("naive+https://alice:pw@naive.example.com:443?sni=naive.example.com&fp=chrome#NaiveH2")
        XCTAssertEqual(nh2.scheme, .naive)
        XCTAssertEqual(nh2.protocolName, "h2")
        XCTAssertTrue(nh2.padding)
        let nh2Kdl = ShareLinkParser.renderKdlOutbound(nh2, secretFilePath: "/etc/nexus/n2.pass")
        XCTAssertTrue(nh2Kdl.contains(#"outbound "NaiveH2" type="naive""#))
        XCTAssertTrue(nh2Kdl.contains(#"protocol "h2""#))
        XCTAssertTrue(nh2Kdl.contains("verify #true"))

        let nh3 = try ShareLinkParser.parse("naive+quic://bob:pw@nq.example.com:8443?padding=0#NaiveH3")
        XCTAssertEqual(nh3.protocolName, "h3")
        XCTAssertFalse(nh3.padding)

        let h3Proxy = try ShareLinkParser.parse("https://u:p@h3p.example.com:443?h3=1&udp=1&fp=chrome#H3Proxy")
        XCTAssertEqual(h3Proxy.scheme, .httpConnect)
        XCTAssertEqual(h3Proxy.httpVersion, "h3")
        XCTAssertTrue(h3Proxy.udp)
        let h3Kdl = ShareLinkParser.renderKdlOutbound(h3Proxy, secretFilePath: "/etc/nexus/h3.pass")
        XCTAssertTrue(h3Kdl.contains(#"type="http-connect""#))
        XCTAssertTrue(h3Kdl.contains(#"http-version "h3""#))
        XCTAssertTrue(h3Kdl.contains("udp #true"))
        XCTAssertTrue(h3Kdl.contains("verify #true"))

        let slashPort = try ShareLinkParser.parse("vless://11111111-2222-3333-4444-555555555555@edge.example.com:443/?security=tls&sni=edge.example.com#SlashPort")
        XCTAssertEqual(slashPort.host, "edge.example.com")
        XCTAssertEqual(slashPort.port, 443)
        let slashV6 = try ShareLinkParser.parse("vless://11111111-2222-3333-4444-555555555555@[2001:db8::1]:443/?security=tls&sni=edge.example.com#SlashV6")
        XCTAssertEqual(slashV6.host, "2001:db8::1")
        XCTAssertEqual(slashV6.port, 443)
        let ssSlash = try ShareLinkParser.parse("ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206YT8/@1.2.3.4:8388/?plugin=none#SlashB64")
        XCTAssertEqual(ssSlash.method, "2022-blake3-aes-128-gcm")
        XCTAssertEqual(ssSlash.secret, "a??")
        XCTAssertEqual(ssSlash.host, "1.2.3.4")
        XCTAssertEqual(ssSlash.port, 8388)
        XCTAssertThrowsError(try ShareLinkParser.parse("snell://pskvalue@sn.example.com:6160?version=3#Snell3"))

        let launchCfg = PacketTunnelLaunchConfig(memoryBudgetMiB: 36)
        XCTAssertNotNil(launchCfg.coreLaunchArguments())
        XCTAssertTrue(launchCfg.coreLaunchArguments()?.contains("-D") == true)
        XCTAssertEqual(TunnelMemoryMonitor.pressureLevel(residentMiB: 20.0, budgetMiB: 36), .normal)
        XCTAssertEqual(TunnelMemoryMonitor.pressureLevel(residentMiB: 38.0, budgetMiB: 36), .warning)
        XCTAssertEqual(TunnelMemoryMonitor.pressureLevel(residentMiB: 48.0, budgetMiB: 36), .critical)
    }

    func testUtunPassthroughFramingAndLoginItemManager() {
        let adapter = UtunPassthroughAdapter()
        var ipv4 = Data(repeating: 0, count: 28)
        ipv4[0] = 0x45
        let framedV4 = adapter.framePacket(ipv4)
        XCTAssertNotNil(framedV4)
        XCTAssertEqual(framedV4?.prefix(4), Data([0, 0, 0, 2]))
        let unframedV4 = framedV4.flatMap { adapter.unframePacket($0) }
        XCTAssertEqual(unframedV4?.family, .ipv4)
        XCTAssertEqual(unframedV4?.payload, ipv4)

        var ipv6 = Data(repeating: 0, count: 48)
        ipv6[0] = 0x60
        let framedV6 = adapter.framePacket(ipv6)
        XCTAssertEqual(framedV6?.prefix(4), Data([0, 0, 0, 30]))
        XCTAssertEqual(framedV6.flatMap { adapter.unframePacket($0) }?.family, .ipv6)

        let oversized = Data([0x45] + Array(repeating: UInt8(0), count: AppleTunnelProfile.maxSafeMtu))
        XCTAssertNil(adapter.framePacket(oversized))
        XCTAssertNil(adapter.unframePacket(Data([0, 0, 0, 99, 0x45])))

        let loginStatus = LoginItemManager.currentStatus()
        XCTAssertFalse(loginStatus.summaryText.isEmpty)
    }

    func testEmbeddedCoreBridgeLifecycleAndCheckConfig() async throws {
        final class HookState: @unchecked Sendable {
            private let lock = NSLock()
            var running = false
            var stopRequested = false
            var reloadCount = 0
            var launchedArgv: [String] = []
        }

        let state = HookState()
        let hooks = EmbeddedCoreHooks(
            version: { "0.1.0" },
            runArgs: { argv in
                state.launchedArgv = argv
                state.running = true
                while !state.stopRequested {
                    Thread.sleep(forTimeInterval: 0.005)
                }
                state.running = false
                return 0
            },
            checkConfig: { path in
                path.hasSuffix(".kdl") ? 0 : 1
            },
            requestStop: { state.stopRequested = true },
            requestReload: { state.reloadCount += 1 },
            isRunning: { state.running }
        )

        let bridge = EmbeddedCoreBridge(hooks: hooks)
        let ver = await bridge.coreVersion()
        XCTAssertEqual(ver, "0.1.0")
        try await bridge.validateConfiguration(at: "/tmp/valid.kdl")
        do {
            try await bridge.validateConfiguration(at: "/tmp/invalid.txt")
            XCTFail("Expected validationFailed")
        } catch EmbeddedCoreError.validationFailed(let code) {
            XCTAssertEqual(code, 1)
        }

        let launchCfg = PacketTunnelLaunchConfig(configRelativePath: "config.kdl")
        try await bridge.start(launchConfig: launchCfg)
        let runningState = await bridge.currentState()
        XCTAssertEqual(runningState, .running)
        try await bridge.requestReload()
        XCTAssertEqual(state.reloadCount, 1)
        let exitCode = await bridge.stop()
        XCTAssertEqual(exitCode, 0)
        let stoppedState = await bridge.currentState()
        XCTAssertEqual(stoppedState, .idle)
    }
}
