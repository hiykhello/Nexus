package org.nexus.android.ui

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.nexus.android.bridge.workspace.DnsConfig
import org.nexus.android.bridge.workspace.FullTemplateConfig
import org.nexus.android.bridge.workspace.ProfileItem
import org.nexus.android.bridge.workspace.RoutingProfileItem
import org.nexus.android.bridge.workspace.RoutingRuleItem
import org.nexus.android.bridge.workspace.RuleSetAsset
import org.nexus.android.bridge.workspace.SubscriptionItem
import org.nexus.android.bridge.workspace.WorkspaceStore

/**
 * Extended full-capability mutations for [WorkspaceCoordinator]:
 * - In-place profile edit (`saveProfile`), full subscription CRUD & batch refresh
 * - Routing preset creation + `domainStrategy` / `defaultOutbound`
 * - `RuleSetAsset` (`nxmm` / `srs`) CRUD & `FullTemplateConfig` persistence
 */
suspend fun WorkspaceCoordinator.saveProfile(
    profile: ProfileItem,
    isEdit: Boolean,
    running: Boolean,
): Pair<WorkspaceUiState, String> {
    if (!isEdit) return addProfile(profile, running)
    val (updatedItem, activeId) = withContext(Dispatchers.IO) {
        val doc = workspaceStore.loadOrInit()
        val exists = doc.profiles.any { it.id == profile.id }
        val nextList = if (exists) {
            doc.profiles.map { if (it.id == profile.id) profile.copy(isFromSub = it.isFromSub) else it }
        } else {
            val uid = WorkspaceStore.makeUniqueId(profile.id.ifBlank { WorkspaceStore.newProfileId(profile.kind.wire) }, doc.profiles.map { it.id }.toSet())
            doc.profiles + profile.copy(id = uid)
        }
        val saved = workspaceStore.save(doc.copy(profiles = nextList))
        val curActive = telemetryStore.load().activeProfileId
            .takeIf { id -> saved.profiles.any { it.id == id } }
            ?: profile.id.also { telemetryStore.setActiveProfileId(it) }
        profile to curActive
    }
    if (running) reloadActiveIfRunning(activeId)
    return loadInitialState() to "已保存配置 ${updatedItem.remarks.ifBlank { updatedItem.id }}"
}

suspend fun WorkspaceCoordinator.saveSubscription(
    sub: SubscriptionItem,
    fetchNow: Boolean,
    running: Boolean,
): Pair<WorkspaceUiState, String> {
    val savedSub = withContext(Dispatchers.IO) {
        val doc = workspaceStore.loadOrInit()
        val existing = doc.subscriptions.firstOrNull { it.id == sub.id }
        val resolved = if (existing != null) {
            sub.copy(updatedAtMs = existing.updatedAtMs, usage = existing.usage)
        } else {
            val uid = WorkspaceStore.makeUniqueId(sub.remarks.ifBlank { "sub" }, doc.subscriptions.map { it.id }.toSet())
            sub.copy(id = uid, remarks = sub.remarks.ifBlank { uid })
        }
        val nextSubs = if (existing != null) {
            doc.subscriptions.map { if (it.id == resolved.id) resolved else it }
        } else {
            doc.subscriptions + resolved
        }
        workspaceStore.save(doc.copy(subscriptions = nextSubs))
        resolved
    }
    if (fetchNow && savedSub.url.isNotBlank()) {
        return refreshSubscription(savedSub.id, running)
    }
    if (running) reloadCurrentRunning()
    return loadInitialState() to "已保存订阅分组 ${savedSub.remarks}"
}

suspend fun WorkspaceCoordinator.deleteSubscription(
    subId: String,
    running: Boolean,
): Pair<WorkspaceUiState, String> {
    val activeId = withContext(Dispatchers.IO) {
        val doc = workspaceStore.loadOrInit()
        val nextSubs = doc.subscriptions.filterNot { it.id == subId }
        val nextProfiles = doc.profiles.filterNot { it.subscriptionId == subId }
        val finalProfiles = nextProfiles.ifEmpty { listOf(org.nexus.android.bridge.workspace.WorkspaceDefaults.defaultDirectProfile()) }
        workspaceStore.save(doc.copy(subscriptions = nextSubs, profiles = finalProfiles))
        val curActive = telemetryStore.load().activeProfileId
        val resolved = curActive.takeIf { id -> finalProfiles.any { it.id == id } } ?: finalProfiles.first().id
        telemetryStore.setActiveProfileId(resolved)
        resolved
    }
    if (running) reloadActiveIfRunning(activeId)
    return loadInitialState() to "已删除订阅分组及其节点"
}

suspend fun WorkspaceCoordinator.refreshAllSubscriptions(
    running: Boolean,
): Pair<WorkspaceUiState, String> {
    val subs = withContext(Dispatchers.IO) {
        workspaceStore.loadOrInit().subscriptions.filter { it.enabled && it.url.isNotBlank() }
    }
    if (subs.isEmpty()) {
        return loadInitialState() to "暂无已启用的远端订阅链接"
    }
    var okCount = 0
    var lastMsg = ""
    for (sub in subs) {
        val (_, msg) = refreshSubscription(sub.id, running = false)
        lastMsg = msg
        if (!msg.contains("失败") && !msg.contains("未找到")) okCount++
    }
    if (running && okCount > 0) reloadCurrentRunning()
    val summary = if (okCount > 0) "已批量更新 $okCount/${subs.size} 个订阅分组" else lastMsg.ifBlank { "订阅更新失败" }
    return loadInitialState() to summary
}

suspend fun WorkspaceCoordinator.saveRoutingStrategy(
    newPresetName: String,
    domainStrategy: String,
    defaultOutbound: String,
    autoDetectInterface: Boolean,
    findProcess: Boolean,
    running: Boolean,
): Pair<WorkspaceUiState, String> {
    val note = withContext(Dispatchers.IO) {
        val doc = workspaceStore.loadOrInit()
        val trimmedNew = newPresetName.trim()
        if (trimmedNew.isNotEmpty()) {
            val newId = WorkspaceStore.makeUniqueId("rp-$trimmedNew", doc.routingProfiles.map { it.id }.toSet())
            val created = RoutingProfileItem(
                id = newId,
                name = trimmedNew,
                isActive = true,
                domainStrategy = domainStrategy,
                defaultOutbound = defaultOutbound,
                autoDetectInterface = autoDetectInterface,
                findProcess = findProcess,
            )
            val deactivated = doc.routingProfiles.map { it.copy(isActive = false) }
            workspaceStore.save(doc.copy(routingProfiles = deactivated + created))
            "已新建并启用路由方案 $trimmedNew"
        } else {
            val activeRp = doc.activeRoutingProfile()
            val next = doc.routingProfiles.map { rp ->
                if (rp.id == activeRp.id) {
                    rp.copy(
                        domainStrategy = domainStrategy,
                        defaultOutbound = defaultOutbound,
                        autoDetectInterface = autoDetectInterface,
                        findProcess = findProcess,
                    )
                } else rp
            }
            workspaceStore.save(doc.copy(routingProfiles = next))
            "已保存路由策略 (${domainStrategy} · 默认 $defaultOutbound)"
        }
    }
    if (running) reloadCurrentRunning()
    return loadInitialState() to note
}

suspend fun WorkspaceCoordinator.saveRuleSetAsset(
    asset: RuleSetAsset,
    running: Boolean,
): Pair<WorkspaceUiState, String> {
    val tag = asset.tag.trim()
    if (tag.isEmpty()) return loadInitialState() to "规则集标签不能为空"
    withContext(Dispatchers.IO) {
        val doc = workspaceStore.loadOrInit()
        val filtered = doc.ruleSetAssets.filterNot { it.tag == tag }
        workspaceStore.save(doc.copy(ruleSetAssets = filtered + asset.copy(tag = tag)))
    }
    if (running) reloadCurrentRunning()
    return loadInitialState() to "已保存规则集资源 @$tag (${asset.format})"
}

suspend fun WorkspaceCoordinator.deleteRuleSetAsset(
    tag: String,
    running: Boolean,
): Pair<WorkspaceUiState, String> {
    withContext(Dispatchers.IO) {
        val doc = workspaceStore.loadOrInit()
        workspaceStore.save(doc.copy(ruleSetAssets = doc.ruleSetAssets.filterNot { it.tag == tag }))
    }
    if (running) reloadCurrentRunning()
    return loadInitialState() to "已删除规则集资源 @$tag"
}

suspend fun WorkspaceCoordinator.updateFullTemplate(
    tpl: FullTemplateConfig,
    running: Boolean,
): Pair<WorkspaceUiState, String> {
    withContext(Dispatchers.IO) {
        val doc = workspaceStore.loadOrInit()
        workspaceStore.save(doc.copy(fullTemplate = tpl))
    }
    if (running) reloadCurrentRunning()
    return loadInitialState() to if (tpl.enabled) "已启用并保存全局配置模板" else "已保存全局配置模板设置"
}

suspend fun WorkspaceCoordinator.selectRoutingProfile(routingId: String, running: Boolean): Pair<WorkspaceUiState, String> {
    withContext(Dispatchers.IO) {
        val doc = workspaceStore.loadOrInit()
        workspaceStore.save(doc.copy(routingProfiles = doc.routingProfiles.map { it.copy(isActive = it.id == routingId) }))
    }
    if (running) reloadCurrentRunning()
    return loadInitialState() to "已切换路由方案"
}

suspend fun WorkspaceCoordinator.addRoutingRule(rule: RoutingRuleItem, running: Boolean): Pair<WorkspaceUiState, String> {
    withContext(Dispatchers.IO) {
        val doc = workspaceStore.loadOrInit()
        val activeRp = doc.activeRoutingProfile()
        val next = doc.routingProfiles.map { rp -> if (rp.id == activeRp.id) rp.copy(rules = listOf(rule) + rp.rules) else rp }
        workspaceStore.save(doc.copy(routingProfiles = next))
    }
    if (running) reloadCurrentRunning()
    return loadInitialState() to "已添加分流规则并同步"
}

suspend fun WorkspaceCoordinator.toggleRoutingRule(ruleId: String, enabled: Boolean, running: Boolean): Pair<WorkspaceUiState, String> {
    withContext(Dispatchers.IO) {
        val doc = workspaceStore.loadOrInit()
        val activeRp = doc.activeRoutingProfile()
        val next = doc.routingProfiles.map { rp ->
            if (rp.id == activeRp.id) rp.copy(rules = rp.rules.map { r -> if (r.id == ruleId && !r.locked) r.copy(enabled = enabled) else r }) else rp
        }
        workspaceStore.save(doc.copy(routingProfiles = next))
    }
    if (running) reloadCurrentRunning()
    return loadInitialState() to if (enabled) "已启用规则" else "已停用规则"
}

suspend fun WorkspaceCoordinator.deleteRoutingRule(ruleId: String, running: Boolean): Pair<WorkspaceUiState, String> {
    withContext(Dispatchers.IO) {
        val doc = workspaceStore.loadOrInit()
        val activeRp = doc.activeRoutingProfile()
        val next = doc.routingProfiles.map { rp ->
            if (rp.id == activeRp.id) rp.copy(rules = rp.rules.filterNot { r -> r.id == ruleId && !r.locked }) else rp
        }
        workspaceStore.save(doc.copy(routingProfiles = next))
    }
    if (running) reloadCurrentRunning()
    return loadInitialState() to "已删除分流规则"
}

suspend fun WorkspaceCoordinator.updateRoutingProfileFlags(
    autoDetectInterface: Boolean,
    findProcess: Boolean,
    running: Boolean,
): Pair<WorkspaceUiState, String> {
    withContext(Dispatchers.IO) {
        val doc = workspaceStore.loadOrInit()
        val activeRp = doc.activeRoutingProfile()
        val next = doc.routingProfiles.map { rp ->
            if (rp.id == activeRp.id) rp.copy(autoDetectInterface = autoDetectInterface, findProcess = findProcess) else rp
        }
        workspaceStore.save(doc.copy(routingProfiles = next))
    }
    if (running) reloadCurrentRunning()
    return loadInitialState() to "已更新路由高级选项"
}

suspend fun WorkspaceCoordinator.updateDns(dns: DnsConfig, running: Boolean): Pair<WorkspaceUiState, String> {
    withContext(Dispatchers.IO) {
        val doc = workspaceStore.loadOrInit()
        workspaceStore.save(doc.copy(dns = dns))
    }
    if (running) reloadCurrentRunning()
    return loadInitialState() to "已更新 DNS 方案"
}
