#if os(macOS) || os(iOS)
import Foundation
import Observation
import NexusCoreBridge

/// Workspace, SQLite, Keychain, Daemon, and Wave 30–31 Control API action methods for `NexusAppModel`.
extension NexusAppModel {
    func loadWorkspaceState(rootDirectory: URL? = nil) async {
        if rootDirectory == nil, let pending = elevationSaveTask { await pending.value }
        let baseDir = rootDirectory ?? Self.defaultWorkspaceDirectory()
        let db = rootDirectory.map { NexusClientDatabase(rootDirectory: $0) } ?? clientDatabase
        let wsStore = WorkspaceStore(rootDirectory: baseDir, database: db)
        let hostStore = HostConfigStore(rootDirectory: baseDir, database: db)
        let telStore = TelemetryStore(rootDirectory: baseDir, database: db)
        let saveToken = elevationSaveTask
        let savedMode = await PrivilegedDaemonController.loadSavedElevationMode(from: db)
        if (rootDirectory != nil || elevationSaveTask == saveToken), savedMode != _storedTunElevationMode {
            withMutation(keyPath: \.tunElevationMode) { _storedTunElevationMode = savedMode }
        }
        if let loaded = try? await wsStore.loadOrInit() { workspace = loaded }
        if let loadedHost = try? await hostStore.loadOrInit() {
            hostConfig = loadedHost
            rebuildControlClient(fromListen: loadedHost.controlHttpListen)
        }
        let tel = await telStore.load()
        if !tel.activeProfileId.isEmpty { activeProfileID = tel.activeProfileId }
        if !tel.outboundMode.isEmpty { outboundMode = tel.outboundMode }
        if tel.unreadUnexpectedCrash && !tel.lastCrashReason.isEmpty {
            statusSummary = "上次异常退出: \(tel.lastCrashReason)"
        }
    }

    func saveHostConfig() async {
        let store = HostConfigStore(rootDirectory: Self.defaultWorkspaceDirectory(), database: clientDatabase)
        if let saved = try? await store.save(hostConfig) {
            hostConfig = saved
            rebuildControlClient(fromListen: saved.controlHttpListen)
            statusSummary = "代理设置已保存"
        }
    }

    func saveBearerToken(_ rawToken: String) {
        let trimmed = rawToken.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        if keychainStore.saveToken(trimmed) {
            hasStoredBearerToken = true
            rebuildControlClient(fromListen: hostConfig.controlHttpListen)
            statusSummary = "控制面 Token 已写入 Keychain"
        }
    }

    func clearBearerToken() {
        keychainStore.deleteToken()
        hasStoredBearerToken = false
        rebuildControlClient(fromListen: hostConfig.controlHttpListen)
        statusSummary = "已清除 Keychain 控制面 Token"
    }

    func rebuildControlClient(fromListen listen: String) {
        let trimmed = listen.trimmingCharacters(in: .whitespacesAndNewlines)
        let urlString = trimmed.hasPrefix("http://") || trimmed.hasPrefix("https://")
            ? trimmed
            : "http://\(trimmed.isEmpty ? "127.0.0.1:9090" : trimmed)"
        guard let url = URL(string: urlString) else { return }
        controlEndpoint = url.absoluteString
        let token = keychainStore.loadToken()
        guard url != activeControlURL || token != activeControlToken else { return }
        activeControlURL = url
        activeControlToken = token
        let wasRunning = isRunning
        stopLiveStreams()
        httpControl = HttpControlClient(baseURL: url, bearerToken: token)
        if wasRunning { startLiveStreams() }
    }

    func refreshStatus() async {
        daemonState = daemonController.status()
        loginItemStatus = LoginItemManager.currentStatus()
        await loadWorkspaceState()
        if let snap = try? await httpControl.statusSnapshot() {
            applyStatusSnapshot(snap)
            if let modeSnap = try? await httpControl.fetchMode() {
                outboundMode = modeSnap.mode
            }
            startLiveStreams()
            return
        }
        do {
            let text = try await session.status()
            isRunning = true
            statusSummary = text.trimmingCharacters(in: .whitespacesAndNewlines)
        } catch {
            isRunning = false
            stopLiveStreams()
            statusSummary = "未连接: \(error.localizedDescription)"
        }
    }

    func setOutboundMode(_ mode: String) async {
        outboundMode = mode
        let telStore = TelemetryStore(rootDirectory: Self.defaultWorkspaceDirectory(), database: clientDatabase)
        _ = try? await telStore.setOutboundMode(mode)
        do {
            let updated = try await httpControl.setMode(mode)
            outboundMode = updated.mode
            statusSummary = "已切换为 \(updated.mode.uppercased()) 模式"
        } catch {
            statusSummary = "模式切换失败: \(error.localizedDescription)"
        }
    }

    func reloadConfig() async {
        do {
            try await httpControl.reload()
            statusSummary = "热重载已触发"
        } catch {
            do {
                _ = try await session.reload()
                statusSummary = "热重载成功"
            } catch {
                statusSummary = "热重载失败: \(error.localizedDescription)"
            }
        }
    }

    func applyLogLevel(_ level: String, domain: String = "global") async {
        logLevel = level
        do {
            try await httpControl.setLogLevel(domain: domain, level: level)
        } catch {
            _ = try? await session.setLogLevel(level)
        }
        await refreshLogs()
    }

    func refreshLogs() async {
        if let snap = try? await httpControl.logs(level: "trace", domain: logDomainFilter, search: logSearch, limit: 200) {
            logs = snap.entries
        }
    }

    func clearLogs() { logs = [] }

    func inspectConnection(id: String) async {
        selectedConnectionDetail = try? await httpControl.connectionDetail(id: id)
    }

    func refreshGroupsAndMetrics() async {
        if let fetched = try? await httpControl.outbounds() { groups = fetched }
        if let conns = try? await httpControl.connections() { connections = conns }
        if let snap = try? await httpControl.metrics() {
            metrics = snap
            recordThroughputSample(up: snap.uploadBytes, down: snap.downloadBytes)
        }
        if let diag = try? await httpControl.diagnostics() { diagnostics = diag }
        residentMemoryMiB = TunnelMemoryMonitor.currentResidentMemoryMiB()
    }

    func selectMember(group: String, member: String) async {
        do { try await httpControl.selectGroup(tag: group, member: member) }
        catch { _ = try? await session.selectOutbound(group: group, member: member) }
        await refreshGroupsAndMetrics()
    }

    func resetGroupAuto(group: String) async {
        do { try await httpControl.resetGroupAuto(tag: group) }
        catch { _ = try? await session.resetGroupAuto(group: group) }
        await refreshGroupsAndMetrics()
    }

    func probeGroup(group: String) async {
        try? await httpControl.probeGroup(tag: group)
        lastProbeBanner = "已触发策略组 \(group) 整组测速"
        await refreshGroupsAndMetrics()
    }

    func probeOutbound(tag: String) async {
        probingOutbounds.insert(tag)
        defer { probingOutbounds.remove(tag) }
        do {
            let res = try await httpControl.probeOutbound(tag: tag)
            if let ms = res.latencyMs {
                lastProbeBanner = "\(res.outbound): \(res.state) · \(ms) ms"
            } else {
                lastProbeBanner = "\(res.outbound): \(res.state)"
            }
        } catch {
            lastProbeBanner = "\(tag) 测速失败: \(error.localizedDescription)"
        }
        await refreshGroupsAndMetrics()
    }

    func refreshRules() async {
        if let fetched = try? await httpControl.fetchRules() { rules = fetched }
    }

    func runDnsQuery(name: String, type: String, server: String?) async {
        isQueryingDns = true
        dnsError = nil
        defer { isQueryingDns = false }
        do {
            dnsResponse = try await httpControl.queryDns(name: name, type: type, server: server)
        } catch {
            dnsError = error.localizedDescription
        }
    }

    func flushFakeIpCache() async {
        do {
            let res = try await httpControl.flushFakeIpCache()
            cacheActionMessage = "FakeIP 已刷新 (\(res.flushed) 条)"
            statusSummary = cacheActionMessage ?? statusSummary
        } catch {
            cacheActionMessage = "FakeIP 刷新失败: \(error.localizedDescription)"
        }
    }

    func clearCache(scope: String = "all") async {
        do {
            try await httpControl.clearCache(scope: scope)
            cacheActionMessage = "缓存(\(scope))已清空"
            statusSummary = cacheActionMessage ?? statusSummary
        } catch {
            cacheActionMessage = "清缓存失败: \(error.localizedDescription)"
        }
    }

    func closeConnection(id: String) async {
        try? await httpControl.closeConnection(id: id)
        await refreshGroupsAndMetrics()
    }

    func closeAllConnections() async {
        try? await httpControl.closeAllConnections()
        selectedConnectionDetail = nil
        await refreshGroupsAndMetrics()
    }

    func selectWorkspaceProfile(_ id: String) async {
        activeProfileID = id
        let telStore = TelemetryStore(rootDirectory: Self.defaultWorkspaceDirectory(), database: clientDatabase)
        _ = try? await telStore.setActiveProfileId(id)
    }

    func importShareLink(_ rawURI: String) async {
        do {
            let parsed = try ShareLinkParser.parse(rawURI)
            let existing = Set(workspace.profiles.map(\.id))
            let newID = WorkspaceStore.makeUniqueID(parsed.tag.isEmpty ? parsed.host : parsed.tag, existing: existing)
            let item = WorkspaceProfileItem(
                id: newID,
                remarks: parsed.tag.isEmpty ? "\(parsed.host):\(parsed.port)" : parsed.tag,
                kind: .node,
                node: WorkspaceNodeConfig(
                    protocolName: parsed.scheme.rawValue,
                    server: parsed.host,
                    port: Int(parsed.port),
                    username: parsed.username,
                    password: parsed.secret,
                    method: parsed.method,
                    flow: parsed.flow,
                    tls: WorkspaceTlsConfig(
                        enabled: !parsed.sni.isEmpty || !parsed.realityPublicKey.isEmpty,
                        sni: parsed.sni,
                        fingerprint: parsed.fingerprint,
                        realityPublicKey: parsed.realityPublicKey,
                        realityShortId: parsed.realityShortId
                    ),
                    transport: WorkspaceTransportConfig(
                        type: parsed.transport,
                        host: parsed.transport == "grpc" ? "" : parsed.hostHeader,
                        path: parsed.transport == "grpc" ? "" : parsed.path,
                        serviceName: parsed.transport == "grpc" ? parsed.path : "",
                        authority: parsed.transport == "grpc" ? parsed.hostHeader : ""
                    )
                )
            )
            var next = workspace
            next.profiles.append(item)
            let store = WorkspaceStore(rootDirectory: Self.defaultWorkspaceDirectory(), database: clientDatabase)
            workspace = try await store.save(next)
            statusSummary = "已导入节点 \(item.remarks)"
        } catch {
            statusSummary = "分享链接解析失败: \(error.localizedDescription)"
        }
    }

    func deleteWorkspaceProfile(_ id: String) async {
        var next = workspace
        next.profiles.removeAll { $0.id == id }
        let store = WorkspaceStore(rootDirectory: Self.defaultWorkspaceDirectory(), database: clientDatabase)
        if let saved = try? await store.save(next) {
            workspace = saved
            if activeProfileID == id { activeProfileID = saved.profiles.first?.id ?? "" }
        }
    }

    func compactDatabase() async {
        do {
            try await clientDatabase.shrinkMemory()
            residentMemoryMiB = TunnelMemoryMonitor.currentResidentMemoryMiB()
            statusSummary = "本地存储内存已回收"
        } catch {
            statusSummary = "本地存储内存回收失败: \(error.localizedDescription)"
        }
    }

    func registerDaemon() {
        do {
            try daemonController.register()
            daemonState = daemonController.status()
        } catch {
            statusSummary = "Daemon 注册失败: \(error.localizedDescription)"
        }
    }

    func unregisterDaemon() async {
        do {
            try await daemonController.unregister()
            daemonState = daemonController.status()
        } catch {
            statusSummary = "Daemon 注销失败: \(error.localizedDescription)"
        }
    }

    func registerLoginItem() {
        do {
            try LoginItemManager.register()
            loginItemStatus = LoginItemManager.currentStatus()
        } catch {
            statusSummary = "开机自启注册失败: \(error.localizedDescription)"
        }
    }

    func unregisterLoginItem() async {
        do {
            try await LoginItemManager.unregister()
            loginItemStatus = LoginItemManager.currentStatus()
        } catch {
            statusSummary = "开机自启注销失败: \(error.localizedDescription)"
        }
    }
}
#endif
