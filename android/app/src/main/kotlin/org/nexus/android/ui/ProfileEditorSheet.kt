package org.nexus.android.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.nexus.android.R
import org.nexus.android.bridge.workspace.NodeConfig
import org.nexus.android.bridge.workspace.PolicyGroupConfig
import org.nexus.android.bridge.workspace.ProfileItem
import org.nexus.android.bridge.workspace.ProfileKind
import org.nexus.android.bridge.workspace.ProxyChainConfig
import org.nexus.android.bridge.workspace.WorkspaceStore
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

private val PROFILE_KINDS = listOf(
    ProfileKind.NODE to "代理节点",
    ProfileKind.POLICY_GROUP to "策略组",
    ProfileKind.PROXY_CHAIN to "链式代理",
    ProfileKind.CUSTOM_OUTBOUND to "自定义出站",
    ProfileKind.FULL_CUSTOM_KDL to "完整配置",
)

private val GROUP_STRATEGIES = listOf(
    "selector" to "手动选择 (selector)",
    "url-test" to "自动测速 (url-test)",
    "fallback" to "故障转移 (fallback)",
    "load-balance" to "负载均衡 (load-balance)",
)

/**
 * Unified Create & Edit Profile Modal Sheet supporting all 5 `ProfileKind`s:
 * - `NODE`: 13 protocols + TLS/REALITY/ECH/PQ-KEM/Fragment + Transports + Multiplex
 * - `POLICY_GROUP`: 4 strategies, static member multi-select, dynamic subscription regex, `interruptExistConnections`
 * - `PROXY_CHAIN`: Ordered multi-hop node picker
 * - `CUSTOM_OUTBOUND` & `FULL_CUSTOM_KDL`: Monospace raw configuration editor
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
internal fun ProfileEditorSheet(
    editingProfile: ProfileItem?,
    defaultSubId: String,
    workspaceState: WorkspaceUiState,
    workspaceActions: WorkspaceUiActions,
    onFeedback: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    val isEdit = editingProfile != null
    val scope = rememberCoroutineScope()
    val haptic = LocalHapticFeedback.current
    val ext = NexusTheme.colors
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    var kind by remember(editingProfile) { mutableStateOf(editingProfile?.kind ?: ProfileKind.NODE) }
    var remarks by remember(editingProfile) { mutableStateOf(editingProfile?.remarks ?: "") }
    var subId by remember(editingProfile, defaultSubId) {
        mutableStateOf(editingProfile?.subscriptionId ?: defaultSubId.takeIf { it != "all" && it != "manual" }.orEmpty())
    }
    var nodeDraft by remember(editingProfile) { mutableStateOf(editingProfile?.node ?: NodeConfig()) }
    var groupDraft by remember(editingProfile) {
        mutableStateOf(editingProfile?.policyGroup ?: PolicyGroupConfig(strategy = "url-test"))
    }
    var chainDraft by remember(editingProfile) {
        mutableStateOf(editingProfile?.proxyChain ?: ProxyChainConfig())
    }
    var kdlText by remember(editingProfile) {
        mutableStateOf(
            when (editingProfile?.kind) {
                ProfileKind.FULL_CUSTOM_KDL -> editingProfile.fullCustomKdl
                ProfileKind.CUSTOM_OUTBOUND -> editingProfile.customOutboundKdl
                else -> """outbound "{{tag}}" type="vless" server="edge.example.com" port=443 uuid="00000000-0000-0000-0000-000000000000""""
            },
        )
    }
    var errorMsg by remember { mutableStateOf("") }
    var saving by remember { mutableStateOf(false) }

    val candidateNodes = remember(workspaceState.document.profiles, editingProfile) {
        workspaceState.document.profiles.filter {
            it.id != editingProfile?.id && (it.kind == ProfileKind.NODE || it.kind == ProfileKind.POLICY_GROUP)
        }
    }

    ModalBottomSheet(
        onDismissRequest = { if (!saving) onDismiss() },
        sheetState = sheetState,
        shape = RoundedCornerShape(topStart = 20.dp, topEnd = 20.dp),
        containerColor = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .imePadding()
                .padding(horizontal = 18.dp)
                .padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = editingProfile?.let { "编辑配置 · ${it.remarks.ifBlank { it.id }}" } ?: "新建代理配置",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f),
                )
                IconButton(onClick = { if (!saving) onDismiss() }) {
                    Icon(painterResource(R.drawable.ic_close), "关闭", Modifier.size(20.dp))
                }
            }

            if (!isEdit) {
                Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    PROFILE_KINDS.forEach { (k, label) ->
                        EditorChoiceChip(label, selected = kind == k) { kind = k; errorMsg = "" }
                    }
                }
            }

            OutlinedTextField(
                value = remarks,
                onValueChange = { remarks = it; errorMsg = "" },
                label = { Text("配置别名 (Remarks)") },
                placeholder = { Text("例如 HK-01 香港高速 / Auto 测速组") },
                shape = RoundedCornerShape(8.dp),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            if (workspaceState.document.subscriptions.isNotEmpty()) {
                Text("所属订阅分组", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    EditorChoiceChip("手动配置", selected = subId.isEmpty()) { subId = "" }
                    workspaceState.document.subscriptions.forEach { s ->
                        EditorChoiceChip(s.remarks.ifBlank { s.id }, selected = subId == s.id) { subId = s.id }
                    }
                }
            }

            when (kind) {
                ProfileKind.NODE -> NodeProtocolFields(node = nodeDraft, onChange = { nodeDraft = it; errorMsg = "" })

                ProfileKind.POLICY_GROUP -> {
                    Text("调度策略", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    FlowRow(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        GROUP_STRATEGIES.forEach { (s, label) ->
                            EditorChoiceChip(label, selected = groupDraft.strategy == s) { groupDraft = groupDraft.copy(strategy = s) }
                        }
                    }

                    if (candidateNodes.isNotEmpty()) {
                        Text("静态成员节点（点按多选，已选 ${groupDraft.memberIds.size} 项）", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        FlowRow(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            candidateNodes.forEach { p ->
                                val picked = p.id in groupDraft.memberIds
                                EditorChoiceChip(p.remarks.ifBlank { p.id }, selected = picked) {
                                    val next = if (picked) groupDraft.memberIds - p.id else groupDraft.memberIds + p.id
                                    groupDraft = groupDraft.copy(memberIds = next)
                                }
                            }
                        }
                    }

                    if (workspaceState.document.subscriptions.isNotEmpty()) {
                        Text("动态绑定订阅分组（可选，自动筛选订阅节点）", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            EditorChoiceChip("不绑定", groupDraft.dynamicSubId.isEmpty()) { groupDraft = groupDraft.copy(dynamicSubId = "") }
                            workspaceState.document.subscriptions.forEach { s ->
                                EditorChoiceChip(s.remarks.ifBlank { s.id }, groupDraft.dynamicSubId == s.id) { groupDraft = groupDraft.copy(dynamicSubId = s.id) }
                            }
                        }
                    }

                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(groupDraft.includeRegex, { groupDraft = groupDraft.copy(includeRegex = it) }, label = { Text("包含正则 (如 HK|SG)") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(1f))
                        OutlinedTextField(groupDraft.excludeRegex, { groupDraft = groupDraft.copy(excludeRegex = it) }, label = { Text("排除正则 (如 倍率|到期)") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(1f))
                    }
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(groupDraft.probeUrl, { groupDraft = groupDraft.copy(probeUrl = it) }, label = { Text("测速 URL") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.55f))
                        OutlinedTextField("${groupDraft.probeIntervalMs / 1000}", { raw -> groupDraft = groupDraft.copy(probeIntervalMs = (raw.filter(Char::isDigit).toLongOrNull() ?: 300L) * 1000L) }, label = { Text("间隔(秒)") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.23f))
                        OutlinedTextField("${groupDraft.toleranceMs}", { raw -> groupDraft = groupDraft.copy(toleranceMs = raw.filter(Char::isDigit).toIntOrNull() ?: 50) }, label = { Text("容差ms") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.22f))
                    }
                    Surface(shape = RoundedCornerShape(8.dp), color = ext.wellSurface, modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(12.dp)) {
                            EditorSwitchRow("切换成员时立即断开旧连接 (interruptExistConnections)", groupDraft.interruptExistConnections) {
                                groupDraft = groupDraft.copy(interruptExistConnections = it)
                            }
                        }
                    }
                }

                ProfileKind.PROXY_CHAIN -> {
                    Text("按序点选跳点（入口 #1 → 落地 #N，至少 2 跳）", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    if (chainDraft.hopIds.isNotEmpty()) {
                        Surface(shape = RoundedCornerShape(8.dp), color = ext.wellSurface, modifier = Modifier.fillMaxWidth()) {
                            Text(
                                text = chainDraft.hopIds.mapIndexed { idx, id ->
                                    val name = candidateNodes.firstOrNull { it.id == id }?.remarks?.ifBlank { id } ?: id
                                    "#${idx + 1} $name"
                                }.joinToString("  →  "),
                                style = NexusNumericStyles.monoBadge,
                                modifier = Modifier.padding(12.dp),
                            )
                        }
                    }
                    FlowRow(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        candidateNodes.forEach { p ->
                            val idx = chainDraft.hopIds.indexOf(p.id)
                            val prefix = if (idx >= 0) "#${idx + 1} " else ""
                            EditorChoiceChip("$prefix${p.remarks.ifBlank { p.id }}", selected = idx >= 0) {
                                val next = if (idx >= 0) chainDraft.hopIds - p.id else chainDraft.hopIds + p.id
                                chainDraft = ProxyChainConfig(hopIds = next)
                            }
                        }
                    }
                }

                ProfileKind.CUSTOM_OUTBOUND, ProfileKind.FULL_CUSTOM_KDL -> {
                    OutlinedTextField(
                        value = kdlText,
                        onValueChange = { kdlText = it; errorMsg = "" },
                        label = { Text(if (kind == ProfileKind.CUSTOM_OUTBOUND) "自定义出站配置 (支持 {{tag}})" else "完整自定义配置文件") },
                        textStyle = NexusNumericStyles.codeBlock,
                        shape = RoundedCornerShape(8.dp),
                        minLines = 6,
                        maxLines = 12,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }

            if (errorMsg.isNotEmpty()) {
                Surface(shape = RoundedCornerShape(8.dp), color = ext.dangerContainer, modifier = Modifier.fillMaxWidth()) {
                    Text(errorMsg, style = MaterialTheme.typography.bodySmall, color = ext.danger, modifier = Modifier.padding(10.dp))
                }
            }

            Spacer(Modifier.height(2.dp))
            Button(
                enabled = !saving,
                shape = RoundedCornerShape(10.dp),
                modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp),
                onClick = {
                    when (kind) {
                        ProfileKind.NODE -> if (nodeDraft.server.isBlank() || nodeDraft.port !in 1..65535) {
                            errorMsg = "请填写有效的服务器地址与端口 (1-65535)"; return@Button
                        }
                        ProfileKind.POLICY_GROUP -> if (groupDraft.memberIds.isEmpty() && groupDraft.dynamicSubId.isBlank()) {
                            errorMsg = "策略组需至少选择 1 个静态成员或绑定动态订阅分组"; return@Button
                        }
                        ProfileKind.PROXY_CHAIN -> if (chainDraft.hopIds.size < 2) {
                            errorMsg = "链式代理至少需要按序选择 2 个跳点"; return@Button
                        }
                        else -> if (kdlText.isBlank()) {
                            errorMsg = "请填写自定义配置内容"; return@Button
                        }
                    }
                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                    saving = true
                    val finalRemarks = remarks.trim().ifEmpty {
                        when (kind) {
                            ProfileKind.NODE -> "${nodeDraft.protocol.uppercase()}-${nodeDraft.server}"
                            ProfileKind.POLICY_GROUP -> "策略组-${groupDraft.strategy}"
                            ProfileKind.PROXY_CHAIN -> "代理链-${chainDraft.hopIds.size}跳"
                            else -> "自定义配置"
                        }
                    }
                    val built = ProfileItem(
                        id = editingProfile?.id ?: WorkspaceStore.newProfileId(kind.wire),
                        remarks = finalRemarks,
                        subscriptionId = subId,
                        isFromSub = editingProfile?.isFromSub ?: false,
                        kind = kind,
                        node = if (kind == ProfileKind.NODE) nodeDraft else null,
                        policyGroup = if (kind == ProfileKind.POLICY_GROUP) groupDraft else null,
                        proxyChain = if (kind == ProfileKind.PROXY_CHAIN) chainDraft else null,
                        customOutboundKdl = if (kind == ProfileKind.CUSTOM_OUTBOUND) kdlText.trim() else "",
                        fullCustomKdl = if (kind == ProfileKind.FULL_CUSTOM_KDL) kdlText.trim() else "",
                    )
                    scope.launch {
                        val msg = workspaceActions.onSaveProfile(built, isEdit)
                        saving = false
                        onFeedback(msg)
                        onDismiss()
                    }
                },
            ) {
                Text(if (saving) "正在保存…" else if (isEdit) "保存修改并生效" else "创建配置并生效", fontWeight = FontWeight.Bold)
            }
        }
    }
}
