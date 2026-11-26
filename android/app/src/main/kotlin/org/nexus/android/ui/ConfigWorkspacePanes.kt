package org.nexus.android.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import org.nexus.android.R
import org.nexus.android.bridge.workspace.PolicyGroupConfig
import org.nexus.android.bridge.workspace.ProfileItem
import org.nexus.android.bridge.workspace.ProfileKind
import org.nexus.android.bridge.workspace.ProxyChainConfig
import org.nexus.android.bridge.workspace.WorkspaceDefaults
import org.nexus.android.bridge.workspace.WorkspaceJsonCodec
import org.nexus.android.bridge.workspace.WorkspaceStore
import org.nexus.android.bridge.workspace.WorkspaceSyncBridge
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

@Composable
internal fun ProfileKindBadge(kind: ProfileKind, modifier: Modifier = Modifier) {
    val ext = NexusTheme.colors
    val (bg, fg, label) = when (kind) {
        ProfileKind.NODE -> Triple(ext.telemetryDownloadContainer, ext.telemetryDownload, "节点")
        ProfileKind.POLICY_GROUP -> Triple(MaterialTheme.colorScheme.primaryContainer, MaterialTheme.colorScheme.onPrimaryContainer, "策略组")
        ProfileKind.PROXY_CHAIN -> Triple(ext.telemetryUploadContainer, ext.telemetryUpload, "代理链")
        ProfileKind.CUSTOM_OUTBOUND -> Triple(ext.warningContainer, ext.warning, "自定义出站")
        ProfileKind.FULL_CUSTOM_KDL -> Triple(ext.successContainer, ext.success, "自定义配置")
    }
    StatusPill(text = label, containerColor = bg, contentColor = fg, modifier = modifier)
}

/**
 * Flattened `LazyListScope` emitter for the Profiles pillar so 100+ subscription profiles stay
 * fully virtualized inside `ConfigScreen`'s `LazyColumn` instead of nesting an eager `Column`.
 */
internal fun LazyListScope.profilesPillarItems(
    state: WorkspaceUiState,
    actions: WorkspaceUiActions,
    scope: CoroutineScope,
    context: Context,
    onFeedback: (String) -> Unit,
    onQuickShareImport: (String) -> Unit,
) {
    item(key = "profiles_header", contentType = "profiles_header") {
        ProfilesHeaderCard(
            state = state,
            actions = actions,
            onFeedback = onFeedback,
            onQuickShareImport = onQuickShareImport,
        )
    }
    val profiles = state.document.profiles
    if (profiles.isEmpty()) {
        item(key = "profiles_empty", contentType = "empty") {
            val ext = NexusTheme.colors
            Surface(
                shape = RoundedCornerShape(14.dp),
                color = ext.wellSurface,
                border = BorderStroke(1.dp, ext.hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text = "暂无节点档案。粘贴 nexus:// 分享包、节点链接或拉取订阅即可开始。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(14.dp),
                )
            }
        }
    } else {
        items(
            items = profiles,
            key = { it.id },
            contentType = { "profile_item" },
        ) { profile ->
            ProfileListRow(
                profile = profile,
                active = profile.id == state.activeProfileId,
                onSelect = { scope.launch { onFeedback(actions.onSelectProfile(profile.id)) } },
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
private fun ProfilesHeaderCard(
    state: WorkspaceUiState,
    actions: WorkspaceUiActions,
    onFeedback: (String) -> Unit,
    onQuickShareImport: (String) -> Unit,
) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val haptic = LocalHapticFeedback.current
    val ext = NexusTheme.colors
    var shareUri by rememberSaveable { mutableStateOf("") }
    var interruptOnSwitch by rememberSaveable { mutableStateOf(false) }

    OpticalCard(cornerRadius = 20.dp) {
        Column(modifier = Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text("节点与多态档案", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                StatusPill("${state.document.profiles.size} 项", ext.insetSurface, MaterialTheme.colorScheme.onSurfaceVariant, mono = true)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = shareUri,
                    onValueChange = { shareUri = it },
                    placeholder = { Text("粘贴 nexus:// 或节点分享链接", maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    shape = RoundedCornerShape(14.dp),
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
                FilledTonalButton(
                    enabled = shareUri.isNotBlank(),
                    shape = RoundedCornerShape(999.dp),
                    onClick = {
                        val raw = shareUri.trim()
                        shareUri = ""
                        if (raw.startsWith(WorkspaceSyncBridge.SHARE_URI_PREFIX)) {
                            scope.launch { onFeedback(actions.onImportShareUri(raw)) }
                        } else {
                            onQuickShareImport(raw)
                        }
                    },
                ) { Text("导入") }
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                OutlinedButton(
                    onClick = {
                        val nodes = state.document.profiles.filter { it.kind == ProfileKind.NODE }.take(4).map { it.id }
                        val item = ProfileItem(
                            id = WorkspaceStore.newProfileId("grp"),
                            remarks = "自动测速组",
                            kind = ProfileKind.POLICY_GROUP,
                            policyGroup = PolicyGroupConfig(
                                strategy = "url-test",
                                memberIds = nodes,
                                interruptExistConnections = interruptOnSwitch,
                            ),
                        )
                        scope.launch { onFeedback(actions.onAddProfile(item)) }
                    },
                    shape = RoundedCornerShape(999.dp),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 10.dp),
                    modifier = Modifier.weight(1f),
                ) { Text("+ 策略组", maxLines = 1) }
                OutlinedButton(
                    onClick = {
                        val hops = state.document.profiles.filter { it.kind == ProfileKind.NODE }.take(2).map { it.id }
                        val item = ProfileItem(
                            id = WorkspaceStore.newProfileId("chain"),
                            remarks = "双跳代理链",
                            kind = ProfileKind.PROXY_CHAIN,
                            proxyChain = ProxyChainConfig(hopIds = hops),
                        )
                        scope.launch { onFeedback(actions.onAddProfile(item)) }
                    },
                    shape = RoundedCornerShape(999.dp),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 10.dp),
                    modifier = Modifier.weight(1f),
                ) { Text("+ 代理链", maxLines = 1) }
            }
            FilterChip(
                selected = interruptOnSwitch,
                onClick = { interruptOnSwitch = !interruptOnSwitch },
                label = { Text("新建策略组切换时断开旧连接") },
            )
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                OutlinedButton(
                    onClick = {
                        val json = WorkspaceJsonCodec.encode(state.document)
                        context.getSystemService(ClipboardManager::class.java)
                            ?.setPrimaryClip(ClipData.newPlainText("nexus-workspace", json))
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onFeedback("已复制工作区备份（不含本机端口与凭据）")
                    },
                    shape = RoundedCornerShape(999.dp),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 10.dp),
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(painterResource(R.drawable.ic_copy), null, Modifier.size(14.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("导出工作区", maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                OutlinedButton(
                    onClick = {
                        val raw = context.getSystemService(ClipboardManager::class.java)
                            ?.primaryClip?.getItemAt(0)?.coerceToText(context)?.toString()?.trim().orEmpty()
                        when {
                            raw.isEmpty() -> onFeedback("剪贴板为空")
                            raw.startsWith(WorkspaceSyncBridge.SHARE_URI_PREFIX) ->
                                scope.launch { onFeedback(actions.onImportShareUri(raw)) }
                            else -> scope.launch { onFeedback(actions.onImportWorkspaceJson(raw)) }
                        }
                    },
                    shape = RoundedCornerShape(999.dp),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 10.dp),
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(painterResource(R.drawable.ic_paste), null, Modifier.size(14.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("导入 nexus://", maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
        }
    }
}

@Composable
private fun ProfileListRow(
    profile: ProfileItem,
    active: Boolean,
    onSelect: () -> Unit,
    onExportShare: () -> Unit,
    onDelete: () -> Unit,
) {
    val ext = NexusTheme.colors
    val primary = MaterialTheme.colorScheme.primary
    val haptic = LocalHapticFeedback.current

    Surface(
        onClick = {
            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
            onSelect()
        },
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        color = if (active) primary.copy(alpha = if (ext.isDark) 0.18f else 0.10f) else ext.cardGradientTop,
        border = BorderStroke(
            if (active) 1.3.dp else 1.dp,
            if (active) primary.copy(alpha = 0.78f) else ext.hairline,
        ),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(start = 12.dp, end = 4.dp, top = 8.dp, bottom = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Box(
                modifier = Modifier.size(7.dp).background(
                    if (active) primary else ext.muted.copy(alpha = 0.5f),
                    CircleShape,
                ),
            )
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    text = profile.remarks.ifBlank { profile.id },
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = if (active) FontWeight.Bold else FontWeight.Medium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                val subMeta = when (profile.kind) {
                    ProfileKind.NODE -> profile.node?.let { n ->
                        val mux = if (n.multiplex.enabled && n.multiplex.protocol.isNotEmpty()) " · ${n.multiplex.protocol}" else ""
                        val frag = if (n.tls.fragment) " · frag" else ""
                        "${n.protocol.uppercase()} · ${n.server}:${n.port}$mux$frag"
                    }.orEmpty()
                    ProfileKind.POLICY_GROUP -> profile.policyGroup?.let { g ->
                        val cut = if (g.interruptExistConnections) " · 切线断旧" else ""
                        "${g.strategy} · ${g.memberIds.size} 成员$cut"
                    }.orEmpty()
                    ProfileKind.PROXY_CHAIN -> "${profile.proxyChain?.hopIds?.size ?: 0} 跳链路"
                    ProfileKind.CUSTOM_OUTBOUND -> if (profile.id == WorkspaceDefaults.DEFAULT_DIRECT_PROFILE_ID) "内置直连兜底" else "高级自定义出站"
                    ProfileKind.FULL_CUSTOM_KDL -> "高级自定义配置"
                }
                if (subMeta.isNotEmpty()) {
                    Text(subMeta, style = NexusNumericStyles.monoBadge, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
            ProfileKindBadge(profile.kind)
            if (profile.kind != ProfileKind.FULL_CUSTOM_KDL) {
                IconButton(onClick = onExportShare) {
                    Icon(painterResource(R.drawable.ic_share), "分享 nexus://", tint = primary, modifier = Modifier.size(18.dp))
                }
            }
            if (!active) {
                IconButton(onClick = onDelete) {
                    Icon(painterResource(R.drawable.ic_delete), "删除", tint = ext.muted, modifier = Modifier.size(18.dp))
                }
            }
        }
    }
}
