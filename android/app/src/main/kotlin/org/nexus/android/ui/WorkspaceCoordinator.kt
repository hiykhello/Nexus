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
import org.nexus.android.bridge.workspace.HostRuntimeAction
import org.nexus.android.bridge.workspace.NexusClientDatabase
import org.nexus.android.bridge.workspace.ProfileItem
import org.nexus.android.bridge.workspace.ProfileKind
import org.nexus.android.bridge.workspace.ProfileReplacement
import org.nexus.android.bridge.workspace.RoutingRuleItem
import org.nexus.android.bridge.workspace.SubscriptionInfoParser
import org.nexus.android.bridge.workspace.SubscriptionItem
import org.nexus.android.bridge.workspace.TelemetryStore
import org.nexus.android.bridge.workspace.WorkspaceComposer
import org.nexus.android.bridge.workspace.WorkspaceDefaults
import org.nexus.android.bridge.workspace.WorkspaceDocument
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
    internal val controlClient: NexusControlClient,
) {
    val workspaceStore = WorkspaceStore(filesDir, db)
    val hostStore = AndroidHostConfigStore(File(filesDir, "host.json"), db)
    val telemetryStore = TelemetryStore(db)
    val composer = WorkspaceComposer(supervisor)
    private val hostMutex = Mutex()
    private val composeMutex = Mutex()

    @Volatile
    private var lastCompose: ComposeResult = ComposeResult(ok = false)

    private fun loadOrSeedWorkspaceLocked(): WorkspaceDocument {
        val loaded = workspaceStore.loadOrInit()
        if (loaded.profiles.isNotEmpty()) return loaded
        val seed = WorkspaceDefaults.defaultDirectProfile()
        val seeded = workspaceStore.save(loaded.copy(profiles = listOf(seed)), bumpRevision = false)
        if (telemetryStore.load().activeProfileId.isBlank()) {
            telemetryStore.setActiveProfileId(seed.id)
        }
        return seeded
    }

    internal suspend fun reloadActiveIfRunning(activeId: String) {
        if (activeId.isEmpty()) return
        val compose = composeForLaunch(activeId)
        if (compose.ok) controlClient.reload()
    }

    internal suspend fun reloadCurrentRunning() {
        val activeId = withContext(Dispatchers.IO) { telemetryStore.load().activeProfileId }
        reloadActiveIfRunning(activeId)
    }

    suspend fun loadInitialState(): WorkspaceUiState = withContext(Dispatchers.IO) {
        val doc = loadOrSeedWorkspaceLocked()
        val host = hostMutex.withLock { hostStore.load(socketPaths) }
        val telemetry = telemetryStore.load()
        val activeId = telemetry.activeProfileId.takeIf { id -> doc.profiles.any { it.id == id } }
            ?: doc.profiles.firstOrNull()?.id.orEmpty()
        WorkspaceUiState(doc, host, activeId, telemetry.outboundMode, lastCompose.selectorTag, lastCompose.selectorMembers, lastCompose.warnings)
    }

    suspend fun composeForLaunch(activeProfileId: String): ComposeResult = withContext(Dispatchers.IO) {
        composeMutex.withLock {
            val doc = loadOrSeedWorkspaceLocked()
            val resolvedId = activeProfileId.takeIf { id -> doc.profiles.any { it.id == id } } ?: doc.profiles.firstOrNull()?.id.orEmpty()
            val composeWsFile = socketPaths.composeWorkspaceFile
            val composeHostFile = socketPaths.composeHostFile
            try {
                workspaceStore.writeCoreInputFile(composeWsFile, doc)
                hostMutex.withLock { hostStore.writeCoreHostFile(composeHostFile, socketPaths) }
                composer.composeWorkspace(composeWsFile, composeHostFile, socketPaths.secretsDir, resolvedId, socketPaths.composedConfigFile)
                    .also { if (it.ok) lastCompose = it }
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
            return loadInitialState() to "配置生成失败: ${compose.errors.firstOrNull() ?: "未知错误"}"
        }
        return loadInitialState() to "已选中 ${target.remarks.ifBlank { target.id }}"
    }

    suspend fun importCustomConfig(rawConfig: String, running: Boolean): Pair<WorkspaceUiState, String> {
        val trimmed = rawConfig.trim()
        if (trimmed.isEmpty()) return loadInitialState() to "配置内容为空"
        val (savedItem, prevActiveId) = withContext(Dispatchers.IO) {
            val doc = loadOrSeedWorkspaceLocked()
            val prevActive = telemetryStore.load().activeProfileId
            val item = ProfileItem(id = WorkspaceStore.newProfileId("custom"), remarks = "自定义配置", kind = ProfileKind.FULL_CUSTOM_KDL, fullCustomKdl = trimmed)
            workspaceStore.save(doc.copy(profiles = doc.profiles + item))
            telemetryStore.setActiveProfileId(item.id)
            item to prevActive
        }
        val compose = composeForLaunch(savedItem.id)
        if (!compose.ok) {
            withContext(Dispatchers.IO) {
                val cur = workspaceStore.loadOrInit()
                workspaceStore.save(cur.copy(profiles = cur.profiles.filterNot { it.id == savedItem.id }), bumpRevision = false)
                telemetryStore.setActiveProfileId(prevActiveId)
            }
            return loadInitialState() to "拒绝导入无效配置: ${compose.errors.firstOrNull() ?: "格式校验未通过"}"
        }
        if (running) controlClient.reload()
        return loadInitialState() to "已导入并启用自定义配置"
    }

    suspend fun importShareUri(uri: String, running: Boolean): Pair<WorkspaceUiState, String> {
        val lines = SecretFileIO.decodeSubscriptionLines(uri).ifEmpty { listOf(uri.trim()) }
        val parsedList = lines.mapNotNull { ShareLinkParser.parse(it).getOrNull() }
        if (parsedList.isEmpty()) {
            val singleErr = ShareLinkParser.parse(uri).exceptionOrNull()?.message ?: "无有效节点链接"
            return loadInitialState() to "解析失败: $singleErr"
        }
        val (lastItem, addedCount, totalCount) = withContext(Dispatchers.IO) {
            val doc = workspaceStore.loadOrInit()
            val ids = doc.profiles.map { it.id }.toMutableSet()
            val added = parsedList.map { parsed ->
                val id = WorkspaceStore.makeUniqueId(parsed.tag, ids)
                ids.add(id)
                WorkspaceDefaults.fromParsedOutbound(id = id, parsed = parsed, isFromSub = false)
            }
            val saved = workspaceStore.save(doc.copy(profiles = doc.profiles + added))
            val last = added.last()
            telemetryStore.setActiveProfileId(last.id)
            Triple(last, added.size, saved.profiles.size)
        }
        val compose = composeForLaunch(lastItem.id)
        if (running && compose.ok) controlClient.reload()
        val msg = if (addedCount > 1) "已批量导入 $addedCount 个节点（共 $totalCount 个）"
        else "已导入节点 ${lastItem.remarks}（共 $totalCount 个）"
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
                return loadInitialState() to "已添加 ${savedItem.remarks.ifBlank { savedItem.id }}，但配置校验失败: $err"
            }
        }
        return loadInitialState() to "已添加 ${savedItem.remarks.ifBlank { savedItem.id }}"
    }

    suspend fun deleteProfile(profileId: String, running: Boolean): Pair<WorkspaceUiState, String> {
        val (nextActive, switched) = withContext(Dispatchers.IO) {
            val doc = workspaceStore.loadOrInit()
            val cur = telemetryStore.load().activeProfileId
            val filtered = doc.profiles.filterNot { it.id == profileId }
            val savedDoc = if (filtered.isEmpty()) {
                workspaceStore.save(doc.copy(profiles = emptyList()))
                loadOrSeedWorkspaceLocked()
            } else {
                workspaceStore.save(doc.copy(profiles = filtered))
            }
            val wasActive = (cur == profileId)
            val resolved = if (wasActive || savedDoc.profiles.none { it.id == cur }) {
                savedDoc.profiles.firstOrNull()?.id.orEmpty()
            } else cur
            telemetryStore.setActiveProfileId(resolved)
            resolved to wasActive
        }
        if (running && switched && nextActive.isNotEmpty()) reloadActiveIfRunning(nextActive)
        return loadInitialState() to if (switched) "已删除原活动配置并自动切换" else "已删除配置"
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
        if (running && activeId != null) reloadActiveIfRunning(activeId)
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
        if (running && activeForSub.isNotEmpty()) reloadActiveIfRunning(activeForSub)
        return loadInitialState() to "已更新订阅链式前置/落地配置"
    }

    suspend fun mutateHost(
        running: Boolean = false,
        onRestartNeeded: (() -> Unit)? = null,
        transform: (AndroidHostConfig) -> AndroidHostConfig,
    ): Pair<WorkspaceUiState, String> {
        val (action, notice, activeId) = withContext(Dispatchers.IO) {
            hostMutex.withLock {
                val prev = hostStore.load(socketPaths)
                val (normalized, warn) = AndroidHostConfig.normalizeForSave(transform(prev))
                val bound = normalized.boundToPaths(socketPaths)
                hostStore.save(bound)
                val act = AndroidHostConfig.classifyRuntimeAction(prev, bound)
                val curActive = telemetryStore.load().activeProfileId
                Triple(act, warn, curActive)
            }
        }
        if (!running) {
            val msg = notice ?: when (action) {
                HostRuntimeAction.NONE -> "已更新界面与本机偏好"
                else -> "已保存入站与网络设置（连接时生效）"
            }
            return loadInitialState() to msg
        }
        return when (action) {
            HostRuntimeAction.NONE -> loadInitialState() to (notice ?: "设置已实时生效")
            HostRuntimeAction.RELOAD_CORE -> {
                val compose = composeForLaunch(activeId)
                if (compose.ok && controlClient.reload().ok) {
                    loadInitialState() to (notice ?: "已热重载本地入站配置（零断流生效）")
                } else {
                    onRestartNeeded?.invoke()
                    loadInitialState() to (notice ?: "已保存入站配置并平滑重连隧道")
                }
            }
            HostRuntimeAction.RESTART_VPN -> {
                onRestartNeeded?.invoke()
                loadInitialState() to (notice ?: "已应用网络参数并平滑重连隧道")
            }
        }
    }

    suspend fun updateHost(
        nextHost: AndroidHostConfig,
        running: Boolean = false,
        onRestartNeeded: (() -> Unit)? = null,
    ): Pair<WorkspaceUiState, String> = mutateHost(running = running, onRestartNeeded = onRestartNeeded) { nextHost }

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
            }.getOrElse { err -> null to "工作区数据格式无效: ${err.message}" }
        }
        if (running && result.first != null) reloadActiveIfRunning(result.first!!)
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
