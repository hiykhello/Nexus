package org.nexus.android.ui

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.nexus.android.bridge.core.CoreProcessSupervisor
import org.nexus.android.bridge.ipc.NexusControlClient
import org.nexus.android.bridge.model.EndpointParser
import org.nexus.android.bridge.model.RuntimeSocketPaths
import org.nexus.android.bridge.model.ShareLinkParser
import org.nexus.android.bridge.profile.SecretFileIO
import org.nexus.android.bridge.workspace.AndroidHostConfig
import org.nexus.android.bridge.workspace.AndroidHostConfigStore
import org.nexus.android.bridge.workspace.ComposeResult
import org.nexus.android.bridge.workspace.DnsConfig
import org.nexus.android.bridge.workspace.NexusClientDatabase
import org.nexus.android.bridge.workspace.ProfileItem
import org.nexus.android.bridge.workspace.ProfileReplacement
import org.nexus.android.bridge.workspace.RoutingRuleItem
import org.nexus.android.bridge.workspace.SubscriptionInfoParser
import org.nexus.android.bridge.workspace.SubscriptionItem
import org.nexus.android.bridge.workspace.TelemetryStore
import org.nexus.android.bridge.workspace.WorkspaceComposer
import org.nexus.android.bridge.workspace.WorkspaceDefaults
import org.nexus.android.bridge.workspace.WorkspaceStore
import org.nexus.android.bridge.workspace.WorkspaceSyncBridge
import java.io.File
import java.net.URL

/**
 * Coordinates unified SQLite 3 (WAL) client storage (`NexusClientDatabase`), Core
 * `nexus workspace compose`, TUN zero-restart live switching, and subscription refresh.
 */
class WorkspaceCoordinator(
    private val filesDir: File,
    private val socketPaths: RuntimeSocketPaths,
    val db: NexusClientDatabase,
    private val supervisor: CoreProcessSupervisor,
    private val controlClient: NexusControlClient,
) {
    val workspaceStore = WorkspaceStore(filesDir, db)
    val hostStore = AndroidHostConfigStore(File(filesDir, "host.json"), db)
    val telemetryStore = TelemetryStore(db)
    val composer = WorkspaceComposer(supervisor)
    private val hostMutex = Mutex()
    private val composeMutex = Mutex()

    @Volatile
    private var lastCompose: ComposeResult = ComposeResult(ok = false)

    suspend fun loadInitialState(): WorkspaceUiState = withContext(Dispatchers.IO) {
        val doc = workspaceStore.loadOrInit()
        val host = hostMutex.withLock { hostStore.load(socketPaths) }
        val telemetry = telemetryStore.load()
        val activeId = telemetry.activeProfileId.takeIf { id -> doc.profiles.any { it.id == id } }
            ?: doc.profiles.firstOrNull()?.id.orEmpty()
        WorkspaceUiState(
            document = doc,
            host = host,
            activeProfileId = activeId,
            outboundMode = telemetry.outboundMode,
            selectorTag = lastCompose.selectorTag,
            selectorMembers = lastCompose.selectorMembers,
            composeWarnings = lastCompose.warnings,
        )
    }

    suspend fun composeForLaunch(activeProfileId: String): ComposeResult = withContext(Dispatchers.IO) {
        composeMutex.withLock {
            val doc = workspaceStore.loadOrInit()
            val resolvedId = activeProfileId.takeIf { id -> doc.profiles.any { it.id == id } }
                ?: doc.profiles.firstOrNull()?.id.orEmpty()
            val composeWsFile = socketPaths.composeWorkspaceFile
            val composeHostFile = socketPaths.composeHostFile
            try {
                workspaceStore.writeCoreInputFile(composeWsFile, doc)
                hostMutex.withLock { hostStore.writeCoreHostFile(composeHostFile, socketPaths) }
                val res = composer.composeWorkspace(
                    workspaceFile = composeWsFile,
                    hostFile = composeHostFile,
                    secretsDir = socketPaths.secretsDir,
                    activeProfileId = resolvedId,
                    emitKdlFile = socketPaths.composedConfigFile,
                )
                if (res.ok) lastCompose = res
                res
            } finally {
                WorkspaceSyncBridge.wipeAndDelete(composeWsFile)
                WorkspaceSyncBridge.wipeAndDelete(composeHostFile)
            }
        }
    }

    suspend fun selectProfile(
        profileId: String,
        running: Boolean,
        onRestartNeeded: () -> Unit,
    ): Pair<WorkspaceUiState, String> {
        val doc = withContext(Dispatchers.IO) { workspaceStore.loadOrInit() }
        val target = doc.profiles.firstOrNull { it.id == profileId }
            ?: return loadInitialState() to "未找到节点档案"
        withContext(Dispatchers.IO) { telemetryStore.setActiveProfileId(target.id) }

        val sanitizedTag = WorkspaceComposer.resolveUnambiguousTag(target, doc.profiles)
        val liveTag = when {
            sanitizedTag.isNotEmpty() && sanitizedTag in lastCompose.selectorMembers -> sanitizedTag
            target.id in lastCompose.selectorMembers -> target.id
            else -> ""
        }
        if (WorkspaceComposer.canHotSwitchViaSelector(running, liveTag, lastCompose.selectorTag, lastCompose.selectorMembers)) {
            val reply = controlClient.selectOutbound(lastCompose.selectorTag, liveTag)
            if (reply.ok) {
                return loadInitialState() to "已热切换至 ${target.remarks.ifBlank { target.id }}（免重启 TUN）"
            }
        }
        val compose = composeForLaunch(target.id)
        if (running) {
            if (compose.ok) {
                val reload = controlClient.reload()
                if (!reload.ok) onRestartNeeded()
                return loadInitialState() to "已切换至 ${target.remarks.ifBlank { target.id }}"
            }
            return loadInitialState() to "组合失败: ${compose.errors.firstOrNull() ?: "未知错误"}"
        }
        return loadInitialState() to "已选中 ${target.remarks.ifBlank { target.id }}"
    }

    suspend fun importShareUri(uri: String, running: Boolean): Pair<WorkspaceUiState, String> {
        val parsed = ShareLinkParser.parse(uri).getOrElse {
            return loadInitialState() to "解析失败: ${it.message}"
        }
        val (savedItem, totalCount) = withContext(Dispatchers.IO) {
            val doc = workspaceStore.loadOrInit()
            val id = WorkspaceStore.makeUniqueId(parsed.tag, doc.profiles.map { it.id }.toSet())
            val item = WorkspaceDefaults.fromParsedOutbound(id = id, parsed = parsed, isFromSub = false)
            val saved = workspaceStore.save(doc.copy(profiles = doc.profiles + item))
            telemetryStore.setActiveProfileId(item.id)
            item to saved.profiles.size
        }
        val compose = composeForLaunch(savedItem.id)
        if (running && compose.ok) controlClient.reload()
        val msg = if (compose.ok) "已导入节点 ${savedItem.remarks}（共 $totalCount 个）"
        else "已保存节点 ${savedItem.remarks}"
        return loadInitialState() to msg
    }

    suspend fun addProfile(profile: ProfileItem, running: Boolean): Pair<WorkspaceUiState, String> {
        val (savedItem, activeId) = withContext(Dispatchers.IO) {
            val doc = workspaceStore.loadOrInit()
            val uniqueId = WorkspaceStore.makeUniqueId(
                profile.id.ifBlank { WorkspaceStore.newProfileId(profile.kind.wire) },
                doc.profiles.map { it.id }.toSet(),
            )
            val item = profile.copy(id = uniqueId)
            val saved = workspaceStore.save(doc.copy(profiles = doc.profiles + item))
            val curActive = telemetryStore.load().activeProfileId
                .takeIf { id -> saved.profiles.any { it.id == id } }
                ?: item.id.also { telemetryStore.setActiveProfileId(it) }
            item to curActive
        }
        if (running) {
            val compose = composeForLaunch(activeId)
            if (compose.ok) {
                controlClient.reload()
            } else {
                val err = compose.errors.firstOrNull().orEmpty()
                return loadInitialState() to "已添加 ${savedItem.remarks.ifBlank { savedItem.id }}，但编译校验失败: $err"
            }
        }
        return loadInitialState() to "已添加 ${savedItem.remarks.ifBlank { savedItem.id }}"
    }

    suspend fun deleteProfile(profileId: String, running: Boolean): Pair<WorkspaceUiState, String> {
        val nextActive = withContext(Dispatchers.IO) {
            val doc = workspaceStore.loadOrInit()
            val filtered = doc.profiles.filterNot { it.id == profileId }
            workspaceStore.save(doc.copy(profiles = filtered))
            val cur = telemetryStore.load().activeProfileId
            val resolved = if (cur == profileId) filtered.firstOrNull()?.id.orEmpty() else cur
            telemetryStore.setActiveProfileId(resolved)
            resolved
        }
        if (running && nextActive.isNotEmpty()) {
            val compose = composeForLaunch(nextActive)
            if (compose.ok) controlClient.reload()
        }
        return loadInitialState() to "已删除档案"
    }

    suspend fun addAndRefreshSubscription(name: String, url: String, running: Boolean): Pair<WorkspaceUiState, String> {
        val sub = withContext(Dispatchers.IO) {
            val doc = workspaceStore.loadOrInit()
            val id = WorkspaceStore.makeUniqueId(name.ifBlank { "sub" }, doc.subscriptions.map { it.id }.toSet())
            val created = SubscriptionItem(id = id, remarks = name.ifBlank { id }, url = url.trim(), enabled = true)
            workspaceStore.save(doc.copy(subscriptions = doc.subscriptions + created))
            created
        }
        return refreshSubscription(sub.id, running)
    }

    suspend fun refreshSubscription(subId: String, running: Boolean): Pair<WorkspaceUiState, String> {
        val result = withContext(Dispatchers.IO) {
            val doc = workspaceStore.loadOrInit()
            val sub = doc.subscriptions.firstOrNull { it.id == subId }
                ?: return@withContext null to "未找到订阅 $subId"
            runCatching {
                val (payload, headers) = SubscriptionHttpFetcher.fetchPayload(sub)
                val parsedHeaders = SubscriptionInfoParser.parseHeaders(headers)
                val lines = SecretFileIO.decodeSubscriptionLines(payload)
                val parsedNodes = lines.mapNotNull { ShareLinkParser.parse(it).getOrNull() }
                    .mapIndexed { idx, p ->
                        WorkspaceDefaults.fromParsedOutbound(
                            id = "${sub.id}-${idx + 1}-${SecretFileIO.sanitizeId(p.tag)}",
                            parsed = p,
                            subscriptionId = sub.id,
                            isFromSub = true,
                        )
                    }
                val filteredNodes = ProfileReplacement.filterNodesByRegex(
                    nodes = parsedNodes,
                    includeRegex = sub.includeRegex,
                    excludeRegex = sub.excludeRegex,
                )
                val curActive = telemetryStore.load().activeProfileId
                val replaced = ProfileReplacement.replaceSubscriptionNodes(doc, sub.id, filteredNodes, curActive)
                if (replaced.abortedEmpty) {
                    return@runCatching null to "订阅未包含匹配的有效节点，已保留现有节点"
                }
                val updatedSub = sub.copy(
                    remarks = parsedHeaders.usage.profileTitle.ifBlank { sub.remarks },
                    autoUpdateMinutes = if (parsedHeaders.updateIntervalMinutes > 0) parsedHeaders.updateIntervalMinutes else sub.autoUpdateMinutes,
                    updatedAtMs = System.currentTimeMillis(),
                    usage = parsedHeaders.usage,
                )
                val nextSubs = replaced.workspace.subscriptions.map { if (it.id == sub.id) updatedSub else it }
                workspaceStore.save(replaced.workspace.copy(subscriptions = nextSubs))
                telemetryStore.setActiveProfileId(replaced.activeProfileId)
                val warnSuffix = if (replaced.orphanedChainRefs.isNotEmpty()) {
                    "（注意：${replaced.orphanedChainRefs.size} 处代理链引用已失效）"
                } else ""
                replaced.activeProfileId to "已更新订阅 ${updatedSub.remarks}：保留 ${replaced.matchedCount}、新增 ${replaced.addedCount} 节点$warnSuffix"
            }.getOrElse { err -> null to "订阅拉取失败: ${err.message}" }
        }
        val activeId = result.first
        if (running && activeId != null) {
            val compose = composeForLaunch(activeId)
            if (compose.ok) controlClient.reload()
        }
        return loadInitialState() to result.second
    }

    suspend fun updateSubscriptionChain(
        subId: String,
        prevId: String,
        nextId: String,
        running: Boolean = false,
    ): Pair<WorkspaceUiState, String> {
        val activeForSub = withContext(Dispatchers.IO) {
            val doc = workspaceStore.loadOrInit()
            val nextSubs = doc.subscriptions.map {
                if (it.id == subId) it.copy(prevProfileId = prevId, nextProfileId = nextId) else it
            }
            val saved = workspaceStore.save(doc.copy(subscriptions = nextSubs))
            val curActiveId = telemetryStore.load().activeProfileId
            val activeItem = saved.profiles.firstOrNull { it.id == curActiveId }
            if (activeItem?.subscriptionId == subId) curActiveId else ""
        }
        if (running && activeForSub.isNotEmpty()) {
            val compose = composeForLaunch(activeForSub)
            if (compose.ok) {
                controlClient.reload()
            } else {
                val err = compose.errors.firstOrNull().orEmpty()
                return loadInitialState() to "已保存链式配置，但编译失败: $err"
            }
        }
        return loadInitialState() to "已更新订阅链式前置/落地配置"
    }

    suspend fun selectRoutingProfile(routingId: String, running: Boolean): Pair<WorkspaceUiState, String> {
        val activeProfile = withContext(Dispatchers.IO) {
            val doc = workspaceStore.loadOrInit()
            val nextRoutings = doc.routingProfiles.map { it.copy(isActive = it.id == routingId) }
            workspaceStore.save(doc.copy(routingProfiles = nextRoutings))
            telemetryStore.load().activeProfileId
        }
        if (running) {
            val compose = composeForLaunch(activeProfile)
            if (compose.ok) controlClient.reload()
        }
        return loadInitialState() to "已切换路由方案"
    }

    suspend fun addRoutingRule(rule: RoutingRuleItem, running: Boolean): Pair<WorkspaceUiState, String> {
        val activeProfile = withContext(Dispatchers.IO) {
            val doc = workspaceStore.loadOrInit()
            val activeRp = doc.activeRoutingProfile()
            val nextRoutings = doc.routingProfiles.map { rp ->
                if (rp.id == activeRp.id) rp.copy(rules = listOf(rule) + rp.rules) else rp
            }
            workspaceStore.save(doc.copy(routingProfiles = nextRoutings))
            telemetryStore.load().activeProfileId
        }
        if (running) {
            val compose = composeForLaunch(activeProfile)
            if (compose.ok) controlClient.reload()
        }
        return loadInitialState() to "已添加分流规则并同步"
    }

    suspend fun toggleRoutingRule(ruleId: String, enabled: Boolean, running: Boolean): Pair<WorkspaceUiState, String> {
        val activeProfile = withContext(Dispatchers.IO) {
            val doc = workspaceStore.loadOrInit()
            val activeRp = doc.activeRoutingProfile()
            val nextRoutings = doc.routingProfiles.map { rp ->
                if (rp.id == activeRp.id) {
                    rp.copy(rules = rp.rules.map { r -> if (r.id == ruleId && !r.locked) r.copy(enabled = enabled) else r })
                } else rp
            }
            workspaceStore.save(doc.copy(routingProfiles = nextRoutings))
            telemetryStore.load().activeProfileId
        }
        if (running) {
            val compose = composeForLaunch(activeProfile)
            if (compose.ok) controlClient.reload()
        }
        return loadInitialState() to if (enabled) "已启用规则" else "已停用规则"
    }

    suspend fun deleteRoutingRule(ruleId: String, running: Boolean): Pair<WorkspaceUiState, String> {
        val activeProfile = withContext(Dispatchers.IO) {
            val doc = workspaceStore.loadOrInit()
            val activeRp = doc.activeRoutingProfile()
            val nextRoutings = doc.routingProfiles.map { rp ->
                if (rp.id == activeRp.id) {
                    rp.copy(rules = rp.rules.filterNot { r -> r.id == ruleId && !r.locked })
                } else rp
            }
            workspaceStore.save(doc.copy(routingProfiles = nextRoutings))
            telemetryStore.load().activeProfileId
        }
        if (running) {
            val compose = composeForLaunch(activeProfile)
            if (compose.ok) controlClient.reload()
        }
        return loadInitialState() to "已删除分流规则"
    }

    suspend fun updateRoutingProfileFlags(
        autoDetectInterface: Boolean,
        findProcess: Boolean,
        running: Boolean,
    ): Pair<WorkspaceUiState, String> {
        val activeProfile = withContext(Dispatchers.IO) {
            val doc = workspaceStore.loadOrInit()
            val activeRp = doc.activeRoutingProfile()
            val nextRoutings = doc.routingProfiles.map { rp ->
                if (rp.id == activeRp.id) {
                    rp.copy(autoDetectInterface = autoDetectInterface, findProcess = findProcess)
                } else rp
            }
            workspaceStore.save(doc.copy(routingProfiles = nextRoutings))
            telemetryStore.load().activeProfileId
        }
        if (running) {
            val compose = composeForLaunch(activeProfile)
            if (compose.ok) controlClient.reload()
        }
        return loadInitialState() to "已更新路由高级选项"
    }

    suspend fun updateDns(dns: DnsConfig, running: Boolean): Pair<WorkspaceUiState, String> {
        val activeProfile = withContext(Dispatchers.IO) {
            val doc = workspaceStore.loadOrInit()
            workspaceStore.save(doc.copy(dns = dns))
            telemetryStore.load().activeProfileId
        }
        if (running) {
            val compose = composeForLaunch(activeProfile)
            if (compose.ok) controlClient.reload()
        }
        return loadInitialState() to "已更新 DNS 方案"
    }

    suspend fun mutateHost(transform: (AndroidHostConfig) -> AndroidHostConfig): Pair<WorkspaceUiState, String> {
        withContext(Dispatchers.IO) {
            hostMutex.withLock {
                val latest = hostStore.load(socketPaths)
                val bound = transform(latest).boundToPaths(socketPaths)
                hostStore.save(bound)
            }
        }
        return loadInitialState() to "已保存本机网络与 VPN 设置"
    }

    suspend fun updateHost(nextHost: AndroidHostConfig): Pair<WorkspaceUiState, String> =
        mutateHost { nextHost }

    suspend fun switchOutboundMode(mode: String, running: Boolean): Pair<WorkspaceUiState, String> {
        withContext(Dispatchers.IO) { telemetryStore.setOutboundMode(mode) }
        val label = when (mode) {
            "global" -> "全局代理"
            "direct" -> "直连放行"
            else -> "规则分流"
        }
        if (running) {
            val reply = controlClient.setOutboundMode(mode, lastCompose.selectorTag.ifBlank { "proxy" })
            val suffix = if (reply.ok) "（实时生效）" else "（已记录模式）"
            return loadInitialState() to "已切换至$label$suffix"
        }
        return loadInitialState() to "已切换至$label"
    }

    fun exportPortableWorkspaceJson(): String = workspaceStore.exportPortableJson()

    suspend fun importPortableWorkspaceJson(raw: String, running: Boolean): Pair<WorkspaceUiState, String> {
        val result = withContext(Dispatchers.IO) {
            runCatching {
                val imported = workspaceStore.importPortableJson(raw)
                val firstId = imported.profiles.firstOrNull()?.id.orEmpty()
                if (firstId.isNotEmpty()) telemetryStore.setActiveProfileId(firstId)
                firstId to "已导入便携工作区（${imported.profiles.size} 个档案）"
            }.getOrElse { err -> null to "工作区 JSON 无效: ${err.message}" }
        }
        if (running && result.first != null) {
            val compose = composeForLaunch(result.first!!)
            if (compose.ok) controlClient.reload()
        }
        return loadInitialState() to result.second
    }

    companion object {
        fun buildRuleFromConnection(
            targetHost: String,
            action: String,
            outbound: String,
        ): RoutingRuleItem {
            val clean = EndpointParser.stripPortAndBrackets(targetHost)
            val targetType = when {
                action == "reject" -> "block"
                action == "bypass" || outbound.equals("direct", ignoreCase = true) -> "direct"
                else -> "proxy"
            }
            val isV4 = EndpointParser.isIpv4Literal(clean)
            val isV6 = EndpointParser.isIpv6Literal(clean)
            val isIp = isV4 || isV6
            val cidr = when {
                isV4 -> "$clean/32"
                isV6 -> "$clean/128"
                else -> ""
            }
            return RoutingRuleItem(
                id = WorkspaceStore.newProfileId("conn"),
                enabled = true,
                scope = if (isIp) "routing_only" else "both",
                targetType = targetType,
                domains = if (!isIp && clean.isNotEmpty()) listOf("domain:$clean") else emptyList(),
                ips = if (cidr.isNotEmpty()) listOf(cidr) else emptyList(),
            )
        }

        internal fun urlOriginKey(url: URL): String = SubscriptionHttpFetcher.urlOriginKey(url)
        internal fun sanitizeHeaderValue(raw: String): String = SubscriptionHttpFetcher.sanitizeHeaderValue(raw)
        internal fun sanitizeRequestHeaders(headers: Map<String, String>): Map<String, String> =
            SubscriptionHttpFetcher.sanitizeRequestHeaders(headers)
    }
}
