#if os(macOS) || os(iOS)
import Foundation
import Observation
import NexusCoreBridge

/// Workspace, Keychain, Daemon, and Control API action methods for `NexusAppModel`
/// with optimistic state rollback and user-facing error reporting.
extension NexusAppModel {
    func loadWorkspaceState(rootDirectory: URL? = nil) async {
        let baseDir = rootDirectory ?? Self.defaultWorkspaceDirectory()
        let db = rootDirectory.map { NexusClientDatabase(rootDirectory: $0) } ?? clientDatabase
        let wsStore = WorkspaceStore(rootDirectory: baseDir, database: db)
        let hostStore = HostConfigStore(rootDirectory: baseDir, database: db)
        let telStore = TelemetryStore(rootDirectory: baseDir, database: db)

        let elevGen = elevationSaveGeneration
        if rootDirectory == nil, let pending = elevationSaveTask { await pending.value }
        let savedMode = await PrivilegedDaemonController.loadSavedElevationMode(from: db)
        if (rootDirectory != nil || elevationSaveGeneration == elevGen), savedMode != _storedTunElevationMode {
            withMutation(keyPath: \.tunElevationMode) { _storedTunElevationMode = savedMode }
        }

        let themeGen = themeSaveGeneration
        if rootDirectory == nil, let pendingTheme = themeSaveTask { await pendingTheme.value }
        let savedTheme = await ThemePreferenceStore.load(from: db)
        if (rootDirectory != nil || themeSaveGeneration == themeGen), savedTheme != themePreset {
            themePreset = savedTheme
        }
        if let loaded = try? await wsStore.loadOrInit() { workspace = loaded }
        if let loadedHost = try? await hostStore.loadOrInit() {
            hostConfig = loadedHost
            rebuildControlClient(fromListen: loadedHost.controlHttpListen)
        }
        let tel = await telStore.load()
        if !tel.activeProfileId.isEmpty { activeProfileID = tel.activeProfileId }
        if !tel.outboundMode.isEmpty, outboundModeTransition.pendingFrom == nil {
            outboundModeTransition.syncConfirmed(tel.outboundMode)
            outboundMode = outboundModeTransition.current
        }
        if tel.unreadUnexpectedCrash && !tel.lastCrashReason.isEmpty {
            actionErrorMessage = "上次异常退出：\(tel.lastCrashReason)"
        }
    }

    func setThemePreset(_ preset: NexusThemePreset) {
        guard preset != themePreset else { return }
        themeSaveGeneration &+= 1
        themePreset = preset
        let db = clientDatabase
        let previous = themeSaveTask
        themeSaveTask = Task {
            _ = await previous?.value
            try? await ThemePreferenceStore.save(preset, to: db)
        }
    }

    func queryDnsForPalette(domain: String) async -> Result<DnsQueryResponse, Error> {
        do {
            let response = try await httpControl.queryDns(name: domain, type: "A", server: nil)
            return .success(response)
        } catch {
            return .failure(error)
        }
    }

    func saveHostConfig() async {
        let store = HostConfigStore(rootDirectory: Self.defaultWorkspaceDirectory(), database: clientDatabase)
        do {
            let saved = try await store.save(hostConfig)
            hostConfig = saved
            rebuildControlClient(fromListen: saved.controlHttpListen)
            actionErrorMessage = nil
            statusSummary = "设置已保存"
        } catch {
            actionErrorMessage = "保存设置失败：\(NexusDisplayCopy.friendlyErrorMessage(error))"
        }
    }

    func saveBearerToken(_ rawToken: String) {
        let trimmed = rawToken.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        if keychainStore.saveToken(trimmed) {
            hasStoredBearerToken = true
            rebuildControlClient(fromListen: hostConfig.controlHttpListen)
            actionErrorMessage = nil
            statusSummary = "访问密钥已安全保存至系统钥匙串"
        } else {
            actionErrorMessage = "保存访问密钥失败，请检查系统钥匙串访问权限"
        }
    }

    func clearBearerToken() {
        keychainStore.deleteToken()
        hasStoredBearerToken = false
        rebuildControlClient(fromListen: hostConfig.controlHttpListen)
        actionErrorMessage = nil
        statusSummary = "已清除系统钥匙串中的访问密钥"
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
            actionErrorMessage = nil
            let modeGen = outboundModeTransition.generation
            if let modeSnap = try? await httpControl.fetchMode(), modeGen == outboundModeTransition.generation {
                outboundModeTransition.syncConfirmed(modeSnap.mode)
                outboundMode = outboundModeTransition.current
            }
            startLiveStreams()
            return
        }
        do {
            let text = try await session.status()
            isRunning = true
            actionErrorMessage = nil
            statusSummary = NexusDisplayCopy.coreStateTitle(text.trimmingCharacters(in: .whitespacesAndNewlines))
        } catch {
            isRunning = false
            stopLiveStreams()
            statusSummary = "未连接"
            actionErrorMessage = NexusDisplayCopy.friendlyErrorMessage(error)
        }
    }

    func setOutboundMode(_ mode: String) async {
        let (_, gen) = outboundModeTransition.begin(to: mode)
        outboundMode = outboundModeTransition.current
        let telStore = TelemetryStore(rootDirectory: Self.defaultWorkspaceDirectory(), database: clientDatabase)
        do {
            let updated = try await httpControl.setMode(mode)
            guard outboundModeTransition.commit(updated.mode, for: gen) else { return }
            outboundMode = outboundModeTransition.current
            _ = try? await telStore.setOutboundMode(updated.mode)
            actionErrorMessage = nil
            let title = NexusDisplayCopy.outboundModeTitle(updated.mode)
            recordSparklineOnset(title)
            statusSummary = "已切换为\(title)模式"
        } catch {
            guard let reverted = outboundModeTransition.rollback(for: gen) else { return }
            outboundMode = reverted
            _ = try? await telStore.setOutboundMode(reverted)
            actionErrorMessage = "切换出站模式失败：\(NexusDisplayCopy.friendlyErrorMessage(error))"
        }
    }

    func reloadConfig() async {
        do {
            try await httpControl.reload()
            actionErrorMessage = nil
            recordSparklineOnset("重载")
            statusSummary = "已触发热重载"
        } catch {
            do {
                _ = try await session.reload()
                actionErrorMessage = nil
                recordSparklineOnset("重载")
                statusSummary = "热重载成功"
            } catch {
                actionErrorMessage = "热重载失败：\(NexusDisplayCopy.friendlyErrorMessage(error))"
            }
        }
    }

    func applyLogLevel(_ level: String, domain: String = "global") async {
        let previous = logLevel
        logLevelGeneration &+= 1
        let gen = logLevelGeneration
        logLevel = level
        do {
            try await httpControl.setLogLevel(domain: domain, level: level)
            guard gen == logLevelGeneration else { return }
            actionErrorMessage = nil
        } catch {
            do {
                _ = try await session.setLogLevel(level)
                guard gen == logLevelGeneration else { return }
                actionErrorMessage = nil
            } catch {
                guard gen == logLevelGeneration else { return }
                logLevel = previous
                actionErrorMessage = "设置日志级别失败：\(NexusDisplayCopy.friendlyErrorMessage(error))"
            }
        }
        guard gen == logLevelGeneration else { return }
        await refreshLogs()
    }

    func refreshLogs() async {
        if let snap = try? await httpControl.logs(level: "trace", domain: logDomainFilter, search: logSearch, limit: 200) {
            logs = snap.entries
        }
    }

    func clearLogs() { logs = [] }

    func inspectConnection(id: String) async {
        if let detail = try? await httpControl.connectionDetail(id: id) {
            selectedConnectionDetail = detail
        } else if let cached = connections.first(where: { $0.id == id }) {
            selectedConnectionDetail = cached
        }
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
        let previousGroups = groups
        groupSelectionGeneration &+= 1
        let gen = groupSelectionGeneration
        if let idx = groups.firstIndex(where: { $0.tag == group }) {
            let current = groups[idx]
            groups[idx] = OutboundGroupSnapshot(
                tag: current.tag,
                mode: current.mode,
                active: member,
                manualOverride: true,
                members: current.members
            )
        }
        do {
            try await httpControl.selectGroup(tag: group, member: member)
            guard gen == groupSelectionGeneration else { return }
            actionErrorMessage = nil
            recordSparklineOnset(member)
        } catch {
            do {
                _ = try await session.selectOutbound(group: group, member: member)
                guard gen == groupSelectionGeneration else { return }
                actionErrorMessage = nil
                recordSparklineOnset(member)
            } catch {
                guard gen == groupSelectionGeneration else { return }
                groups = previousGroups
                actionErrorMessage = "切换节点失败：\(NexusDisplayCopy.friendlyErrorMessage(error))"
            }
        }
        guard gen == groupSelectionGeneration else { return }
        await refreshGroupsAndMetrics()
    }

    func resetGroupAuto(group: String) async {
        do {
            try await httpControl.resetGroupAuto(tag: group)
            actionErrorMessage = nil
            recordSparklineOnset("自动")
        } catch {
            do {
                _ = try await session.resetGroupAuto(group: group)
                actionErrorMessage = nil
                recordSparklineOnset("自动")
            } catch {
                actionErrorMessage = "恢复自动选优失败：\(NexusDisplayCopy.friendlyErrorMessage(error))"
            }
        }
        await refreshGroupsAndMetrics()
    }

    func probeGroup(group: String) async {
        do {
            try await httpControl.probeGroup(tag: group)
            actionErrorMessage = nil
            lastProbeBanner = "已触发策略组 \(group) 整组测速"
        } catch {
            lastProbeBanner = "策略组 \(group) 测速失败：\(NexusDisplayCopy.friendlyErrorMessage(error))"
        }
        await refreshGroupsAndMetrics()
    }

    func probeOutbound(tag: String) async {
        probingOutbounds.insert(tag)
        defer { probingOutbounds.remove(tag) }
        do {
            let res = try await httpControl.probeOutbound(tag: tag)
            if let ms = res.latencyMs {
                lastProbeBanner = "\(res.outbound)：\(NexusDisplayCopy.coreStateTitle(res.state)) · \(ms) ms"
            } else {
                lastProbeBanner = "\(res.outbound)：\(NexusDisplayCopy.coreStateTitle(res.state))"
            }
        } catch {
            lastProbeBanner = "\(tag) 测速失败：\(NexusDisplayCopy.friendlyErrorMessage(error))"
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
            dnsError = NexusDisplayCopy.friendlyErrorMessage(error)
        }
    }

    func flushFakeIpCache() async {
        do {
            let res = try await httpControl.flushFakeIpCache()
            cacheActionMessage = "FakeIP 已刷新（\(res.flushed) 条）"
            actionErrorMessage = nil
        } catch {
            let msg = "FakeIP 刷新失败：\(NexusDisplayCopy.friendlyErrorMessage(error))"
            cacheActionMessage = msg
            actionErrorMessage = msg
        }
    }

    func clearCache(scope: String = "all") async {
        let label = scope == "dns" ? "DNS 缓存" : "全部缓存"
        do {
            try await httpControl.clearCache(scope: scope)
            cacheActionMessage = "\(label)已清空"
            actionErrorMessage = nil
        } catch {
            let msg = "清空\(label)失败：\(NexusDisplayCopy.friendlyErrorMessage(error))"
            cacheActionMessage = msg
            actionErrorMessage = msg
        }
    }

    func closeConnection(id: String) async {
        do {
            try await httpControl.closeConnection(id: id)
            if selectedConnectionDetail?.id == id { selectedConnectionDetail = nil }
            actionErrorMessage = nil
        } catch {
            actionErrorMessage = "断开连接失败：\(NexusDisplayCopy.friendlyErrorMessage(error))"
        }
        await refreshGroupsAndMetrics()
    }

    func closeAllConnections() async {
        do {
            try await httpControl.closeAllConnections()
            selectedConnectionDetail = nil
            actionErrorMessage = nil
        } catch {
            actionErrorMessage = "断开全部连接失败：\(NexusDisplayCopy.friendlyErrorMessage(error))"
        }
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
            actionErrorMessage = nil
            statusSummary = "已导入节点 \(item.remarks)"
        } catch {
            actionErrorMessage = "分享链接解析失败：\(NexusDisplayCopy.friendlyErrorMessage(error))"
        }
    }

    func deleteWorkspaceProfile(_ id: String) async {
        var next = workspace
        next.profiles.removeAll { $0.id == id }
        let store = WorkspaceStore(rootDirectory: Self.defaultWorkspaceDirectory(), database: clientDatabase)
        do {
            let saved = try await store.save(next)
            workspace = saved
            if activeProfileID == id { activeProfileID = saved.profiles.first?.id ?? "" }
            actionErrorMessage = nil
        } catch {
            actionErrorMessage = "删除配置失败：\(NexusDisplayCopy.friendlyErrorMessage(error))"
        }
    }

    func compactDatabase() async {
        do {
            try await clientDatabase.shrinkMemory()
            residentMemoryMiB = TunnelMemoryMonitor.currentResidentMemoryMiB()
            actionErrorMessage = nil
            statusSummary = "本地存储内存已回收"
        } catch {
            actionErrorMessage = "本地存储内存回收失败：\(NexusDisplayCopy.friendlyErrorMessage(error))"
        }
    }

    func registerDaemon() {
        do {
            try daemonController.register()
            daemonState = daemonController.status()
            actionErrorMessage = nil
        } catch {
            actionErrorMessage = "启用后台权限服务失败：\(NexusDisplayCopy.friendlyErrorMessage(error))"
        }
    }

    func unregisterDaemon() async {
        do {
            try await daemonController.unregister()
            daemonState = daemonController.status()
            actionErrorMessage = nil
        } catch {
            actionErrorMessage = "停用后台权限服务失败：\(NexusDisplayCopy.friendlyErrorMessage(error))"
        }
    }

    func registerLoginItem() {
        do {
            try LoginItemManager.register()
            loginItemStatus = LoginItemManager.currentStatus()
            actionErrorMessage = nil
        } catch {
            actionErrorMessage = "注册开机自启失败：\(NexusDisplayCopy.friendlyErrorMessage(error))"
        }
    }

    func unregisterLoginItem() async {
        do {
            try await LoginItemManager.unregister()
            loginItemStatus = LoginItemManager.currentStatus()
            actionErrorMessage = nil
        } catch {
            actionErrorMessage = "取消开机自启失败：\(NexusDisplayCopy.friendlyErrorMessage(error))"
        }
    }
}
#endif
