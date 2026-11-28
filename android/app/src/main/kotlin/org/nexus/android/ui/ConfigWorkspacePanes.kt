package org.nexus.android.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import org.nexus.android.R
import org.nexus.android.bridge.ipc.OutboundGroupSnapshot
import org.nexus.android.bridge.workspace.ProfileItem
import org.nexus.android.bridge.workspace.ProfileKind
import org.nexus.android.bridge.workspace.WorkspaceDefaults
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

internal fun deriveLiveLatencies(groups: List<OutboundGroupSnapshot>): Map<String, Long> =
    buildMap {
        groups.forEach { g ->
            g.members.forEach { m -> if (m.latencyMs > 0L) put(m.name, m.latencyMs) }
        }
    }

@Composable
internal fun ProfileKindBadge(profile: ProfileItem, modifier: Modifier = Modifier) {
    val ext = NexusTheme.colors
    val badge = shortProtocolBadge(profile)
    val (bg, fg) = when (profile.kind) {
        ProfileKind.NODE -> ext.telemetryDownloadContainer to ext.telemetryDownload
        ProfileKind.POLICY_GROUP -> MaterialTheme.colorScheme.primaryContainer to MaterialTheme.colorScheme.onPrimaryContainer
        ProfileKind.PROXY_CHAIN -> ext.telemetryUploadContainer to ext.telemetryUpload
        ProfileKind.CUSTOM_OUTBOUND -> ext.warningContainer to ext.warning
        ProfileKind.FULL_CUSTOM_KDL -> ext.successContainer to ext.success
    }
    StatusPill(text = badge, containerColor = bg, contentColor = fg, mono = true, modifier = modifier)
}

internal fun filterAndSortProfiles(
    profiles: List<ProfileItem>,
    selectedSubTab: String,
    knownSubIds: Set<String>,
    searchQuery: String,
    sortMode: String,
    latencies: Map<String, Long> = emptyMap(),
): List<ProfileItem> {
    val q = searchQuery.trim().lowercase()
    val filtered = profiles.filter { p ->
        val effSub = p.subscriptionId.ifBlank { "manual" }
        val subOk = when (selectedSubTab) {
            "", "all" -> true
            "manual" -> effSub == "manual" || effSub !in knownSubIds
            else -> effSub == selectedSubTab
        }
        if (!subOk) return@filter false
        if (q.isEmpty()) return@filter true
        val hay = buildString {
            append(p.remarks).append(' ').append(p.id).append(' ').append(shortProtocolBadge(p))
            p.node?.let { append(' ').append(it.server).append(':').append(it.port) }
        }.lowercase()
        hay.contains(q)
    }
    return when (sortMode) {
        "latency" -> filtered.sortedBy { latencies[it.id]?.takeIf { ms -> ms > 0L } ?: Long.MAX_VALUE }
        "name" -> filtered.sortedBy { it.remarks.ifBlank { it.id }.lowercase() }
        "protocol" -> filtered.sortedBy { shortProtocolBadge(it) }
        else -> filtered
    }
}

/**
 * Flattened `LazyListScope` emitter for the Server & Subscription Console:
 * - Subscription Group Filter Tab Bar (`[全部] [手动配置] [<Sub>...]`)
 * - Search + Latency/Name Sort + Probe All + 1-click Update Subscription + Clipboard Import + `+ 新建`
 * - Two-tier FlClash-style virtualized `ProfileListRow` cards with full remarks, RTT, endpoint & true edit pencil icon
 */
internal fun LazyListScope.profilesPillarItems(
    state: WorkspaceUiState,
    actions: WorkspaceUiActions,
    scope: CoroutineScope,
    context: Context,
    selectedSubTab: String,
    onSelectSubTab: (String) -> Unit,
    searchQuery: String,
    onSearchChange: (String) -> Unit,
    sortMode: String,
    onCycleSort: () -> Unit,
    profileLatencies: Map<String, Long> = emptyMap(),
    isProbingProfiles: Boolean = false,
    onProbeProfiles: () -> Unit = {},
    showSubDrawer: Boolean,
    onToggleSubDrawer: () -> Unit,
    onCreateProfile: () -> Unit,
    onEditProfile: (ProfileItem) -> Unit,
    onImportClipboard: () -> Unit,
    onFeedback: (String) -> Unit,
) {
    val knownSubIds = state.document.subscriptions.map { it.id }.toSet()
    val subNames = state.document.subscriptions.associate { it.id to it.remarks.ifBlank { it.id } }
    val filtered = filterAndSortProfiles(state.document.profiles, selectedSubTab, knownSubIds, searchQuery, sortMode, profileLatencies)

    item(key = "server_console_toolbar", contentType = "profiles_header") {
        ServerConsoleToolbarCard(
            state = state,
            selectedSubTab = selectedSubTab,
            onSelectSubTab = onSelectSubTab,
            searchQuery = searchQuery,
            onSearchChange = onSearchChange,
            sortMode = sortMode,
            onCycleSort = onCycleSort,
            isProbing = isProbingProfiles,
            onProbeProfiles = onProbeProfiles,
            showSubDrawer = showSubDrawer,
            onToggleSubDrawer = onToggleSubDrawer,
            onCreateProfile = onCreateProfile,
            onImportClipboard = onImportClipboard,
            onRefreshSubs = {
                scope.launch {
                    val msg = if (selectedSubTab != "all" && selectedSubTab != "manual" && selectedSubTab in knownSubIds) {
                        actions.onRefreshSubscription(selectedSubTab)
                    } else {
                        actions.onRefreshAllSubscriptions()
                    }
                    onFeedback(msg)
                }
            },
        )
    }

    if (showSubDrawer) {
        item(key = "sub_drawer", contentType = "subs_drawer") {
            SubscriptionsPillarPane(
                state = state,
                actions = actions,
                onFeedback = onFeedback,
            )
        }
    }

    if (filtered.isEmpty()) {
        item(key = "profiles_empty", contentType = "empty") {
            OpticalCard(cornerRadius = 12.dp) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("暂无节点", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                    Text(
                        text = "点击「新建配置」或「剪贴板导入」添加节点。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    } else {
        items(
            items = filtered,
            key = { it.id },
            contentType = { "profile_item" },
        ) { profile ->
            val rtt = profileLatencies[profile.id]
                ?: profileLatencies[profile.remarks]
                ?: -1L
            ProfileListRow(
                profile = profile,
                subLabel = subNames[profile.subscriptionId].orEmpty(),
                latencyMs = rtt,
                active = profile.id == state.activeProfileId,
                onSelect = { scope.launch { onFeedback(actions.onSelectProfile(profile.id)) } },
                onEdit = { onEditProfile(profile) },
                onExportShare = {
                    scope.launch {
                        val (uri, note) = actions.onExportShareUri(profile.id)
                        if (!uri.isNullOrBlank()) {
                            context.getSystemService(ClipboardManager::class.java)
                                ?.setPrimaryClip(ClipData.newPlainText("nexus-share", uri))
                        }
                        onFeedback(note)
                    }
                },
                onDelete = { scope.launch { onFeedback(actions.onDeleteProfile(profile.id)) } },
            )
        }
    }
}

@Composable
private fun ServerConsoleToolbarCard(
    state: WorkspaceUiState,
    selectedSubTab: String,
    onSelectSubTab: (String) -> Unit,
    searchQuery: String,
    onSearchChange: (String) -> Unit,
    sortMode: String,
    onCycleSort: () -> Unit,
    isProbing: Boolean,
    onProbeProfiles: () -> Unit,
    showSubDrawer: Boolean,
    onToggleSubDrawer: () -> Unit,
    onCreateProfile: () -> Unit,
    onImportClipboard: () -> Unit,
    onRefreshSubs: () -> Unit,
) {
    val knownSubIds = state.document.subscriptions.map { it.id }.toSet()
    val manualCount = state.document.profiles.count { it.subscriptionId.isBlank() || it.subscriptionId !in knownSubIds }
    val sortLabel = when (sortMode) {
        "latency" -> "按延迟"
        "name" -> "按名称"
        "protocol" -> "按协议"
        else -> "默认序"
    }

    OpticalCard(cornerRadius = 12.dp) {
        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = onSearchChange,
                    placeholder = { Text("搜索别名、域名或协议…", maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    shape = RoundedCornerShape(8.dp),
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
                EditorChoiceChip(if (isProbing) "测速中" else "测速", selected = isProbing, onClick = onProbeProfiles)
                EditorChoiceChip(sortLabel, selected = sortMode != "default", onClick = onCycleSort)
            }

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onCreateProfile, shape = RoundedCornerShape(8.dp), contentPadding = PaddingValues(horizontal = 10.dp, vertical = 10.dp), modifier = Modifier.weight(1f).heightIn(min = 48.dp)) {
                    Icon(painterResource(R.drawable.ic_add), null, Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("新建配置", fontWeight = FontWeight.Bold, maxLines = 1)
                }
                FilledTonalButton(onClick = onImportClipboard, shape = RoundedCornerShape(8.dp), contentPadding = PaddingValues(horizontal = 10.dp, vertical = 10.dp), modifier = Modifier.weight(1f).heightIn(min = 48.dp)) {
                    Icon(painterResource(R.drawable.ic_paste), null, Modifier.size(15.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("剪贴板导入", maxLines = 1)
                }
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(enabled = !state.isRefreshingSub, onClick = onRefreshSubs, shape = RoundedCornerShape(8.dp), contentPadding = PaddingValues(horizontal = 10.dp, vertical = 10.dp), modifier = Modifier.weight(1f).heightIn(min = 48.dp)) {
                    Icon(painterResource(R.drawable.ic_refresh), null, Modifier.size(15.dp))
                    Spacer(Modifier.width(4.dp))
                    Text(if (state.isRefreshingSub) "更新中…" else "更新订阅", maxLines = 1)
                }
                OutlinedButton(onClick = onToggleSubDrawer, shape = RoundedCornerShape(8.dp), contentPadding = PaddingValues(horizontal = 10.dp, vertical = 10.dp), modifier = Modifier.weight(1f).heightIn(min = 48.dp)) {
                    Text(if (showSubDrawer) "收起分组" else "订阅分组 (${state.document.subscriptions.size})", maxLines = 1)
                }
            }

            Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                EditorChoiceChip("全部 (${state.document.profiles.size})", selected = selectedSubTab == "all" || selectedSubTab.isEmpty()) { onSelectSubTab("all") }
                EditorChoiceChip("手动配置 ($manualCount)", selected = selectedSubTab == "manual") { onSelectSubTab("manual") }
                state.document.subscriptions.forEach { sub ->
                    val cnt = state.document.profiles.count { it.subscriptionId == sub.id }
                    EditorChoiceChip("${sub.remarks.ifBlank { sub.id }} ($cnt)", selected = selectedSubTab == sub.id) { onSelectSubTab(sub.id) }
                }
            }
        }
    }
}

/**
 * Two-tier Server Card:
 * - Row 1: Active dot + Full Remarks + Right-aligned semantic RTT badge
 * - Row 2: Protocol badge + Full `server:port · transport+tls` + 48dp-accessible Edit & Overflow actions
 */
@Composable
private fun ProfileListRow(
    profile: ProfileItem,
    subLabel: String,
    latencyMs: Long,
    active: Boolean,
    onSelect: () -> Unit,
    onEdit: () -> Unit,
    onExportShare: () -> Unit,
    onDelete: () -> Unit,
) {
    val ext = NexusTheme.colors
    val primary = MaterialTheme.colorScheme.primary
    val haptic = LocalHapticFeedback.current
    var menuOpen by remember { mutableStateOf(false) }
    val canShare = profile.kind != ProfileKind.FULL_CUSTOM_KDL
    val canDelete = profile.id != WorkspaceDefaults.DEFAULT_DIRECT_PROFILE_ID

    Surface(
        onClick = { haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove); onSelect() },
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        color = if (active) primary.copy(alpha = if (ext.isDark) 0.16f else 0.07f) else ext.cardSurface,
        border = BorderStroke(if (active) 1.5.dp else 1.dp, if (active) primary.copy(alpha = 0.80f) else ext.hairline),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(start = 12.dp, end = 6.dp, top = 10.dp, bottom = 6.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(end = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Box(Modifier.size(8.dp).background(if (active) ext.success else ext.muted.copy(alpha = 0.45f), CircleShape))
                Text(
                    text = profile.remarks.ifBlank { profile.id },
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = if (active) FontWeight.Bold else FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                if (subLabel.isNotEmpty()) {
                    StatusPill(subLabel, ext.wellSurface, MaterialTheme.colorScheme.onSurfaceVariant)
                }
                LatencyReadoutText(latencyMs = latencyMs, state = if (latencyMs > 0L) "healthy" else "unknown")
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                ProfileKindBadge(profile)
                val meta = when (profile.kind) {
                    ProfileKind.NODE -> profile.node?.let { n ->
                        "${n.server}:${n.port} · ${formatNodeTransportSummary(n)}"
                    }.orEmpty()
                    ProfileKind.POLICY_GROUP -> profile.policyGroup?.let { g ->
                        val dyn = if (g.dynamicSubId.isNotEmpty()) " · 动态正则" else ""
                        val cut = if (g.interruptExistConnections) " · 切线断旧" else ""
                        "${g.strategy} · ${g.memberIds.size} 成员$dyn$cut"
                    }.orEmpty()
                    ProfileKind.PROXY_CHAIN -> "${profile.proxyChain?.hopIds?.size ?: 0} 跳链式代理"
                    ProfileKind.CUSTOM_OUTBOUND -> if (profile.id == WorkspaceDefaults.DEFAULT_DIRECT_PROFILE_ID) "内置直连出站" else "自定义出站配置"
                    ProfileKind.FULL_CUSTOM_KDL -> "完整自定义配置"
                }
                Text(
                    text = meta,
                    style = NexusNumericStyles.monoBadge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                if (profile.id != WorkspaceDefaults.DEFAULT_DIRECT_PROFILE_ID) {
                    CompactRowIconBtn(R.drawable.ic_edit, "编辑配置", MaterialTheme.colorScheme.onSurfaceVariant, onEdit)
                }
                if (canShare || canDelete) {
                    Box {
                        CompactRowIconBtn(R.drawable.ic_more_vert, "更多操作", MaterialTheme.colorScheme.onSurfaceVariant) { menuOpen = true }
                        DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                            if (canShare) {
                                DropdownMenuItem(
                                    text = { Text("复制分享链接") },
                                    leadingIcon = { Icon(painterResource(R.drawable.ic_share), null, Modifier.size(16.dp)) },
                                    onClick = { menuOpen = false; onExportShare() },
                                )
                            }
                            if (canDelete) {
                                DropdownMenuItem(
                                    text = { Text("删除配置") },
                                    leadingIcon = { Icon(painterResource(R.drawable.ic_delete), null, Modifier.size(16.dp)) },
                                    onClick = { menuOpen = false; onDelete() },
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun CompactRowIconBtn(
    iconRes: Int,
    contentDesc: String,
    tint: Color,
    onClick: () -> Unit,
) {
    Box(
        modifier = Modifier
            .minimumInteractiveComponentSize()
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Box(
            modifier = Modifier
                .size(32.dp)
                .clip(RoundedCornerShape(6.dp))
                .background(NexusTheme.colors.wellSurface),
            contentAlignment = Alignment.Center,
        ) {
            Icon(painterResource(iconRes), contentDesc, tint = tint, modifier = Modifier.size(16.dp))
        }
    }
}
