package org.nexus.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.nexus.android.R
import org.nexus.android.bridge.ipc.DnsQueryResult
import org.nexus.android.bridge.ipc.FakeIpFlushResult
import org.nexus.android.bridge.ipc.LiveRuleSnapshot
import org.nexus.android.bridge.workspace.RoutingRuleItem
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

private val DNS_QTYPES = listOf("A", "AAAA", "HTTPS", "TXT", "SRV")

/**
 * Wave 30-31 Diagnostics & Live Control Sheet:
 * - Live compiled rules (`GET /v1/rules`) + editable workspace rules (toggle/delete)
 * - Live DNS Query (`GET /v1/dns/query`)
 * - FakeIP Flush (`POST /v1/cache/fakeip/flush`, graceful 409 handling) & Granular Cache Clear (`POST /v1/state/clear-cache`)
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
internal fun DiagnosticsSheet(
    running: Boolean,
    workspaceState: WorkspaceUiState,
    workspaceActions: WorkspaceUiActions,
    onFetchLiveRules: suspend () -> List<LiveRuleSnapshot>,
    onQueryDns: suspend (name: String, type: String, server: String) -> DnsQueryResult,
    onFlushFakeIp: suspend () -> FakeIpFlushResult,
    onClearCacheTarget: suspend (target: String) -> Boolean,
    onFeedback: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val haptic = LocalHapticFeedback.current
    val ext = NexusTheme.colors
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    var tab by rememberSaveable { mutableStateOf("rules") }
    var liveRules by remember { mutableStateOf<List<LiveRuleSnapshot>>(emptyList()) }
    var ruleFilter by rememberSaveable { mutableStateOf("") }
    var loadingRules by remember { mutableStateOf(false) }

    var dnsName by rememberSaveable { mutableStateOf("www.gstatic.com") }
    var dnsType by rememberSaveable { mutableStateOf("A") }
    var dnsServer by rememberSaveable { mutableStateOf("") }
    var queryingDns by remember { mutableStateOf(false) }
    var dnsResult by remember { mutableStateOf<DnsQueryResult?>(null) }

    var cacheBusy by remember { mutableStateOf(false) }
    var cacheNote by remember { mutableStateOf("") }

    LaunchedEffect(tab, running) {
        if (tab == "rules" && running) {
            loadingRules = true
            liveRules = onFetchLiveRules()
            loadingRules = false
        }
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp),
        containerColor = MaterialTheme.colorScheme.surfaceContainer,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .imePadding()
                .padding(horizontal = 18.dp)
                .padding(bottom = 22.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Icon(painterResource(R.drawable.ic_rule), null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(18.dp))
                Text("内核诊断与规则视图", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                IconButton(onClick = onDismiss) {
                    Icon(painterResource(R.drawable.ic_close), "关闭", Modifier.size(20.dp))
                }
            }

            OpticalSegmentedControl(
                options = listOf("rules" to "实时规则", "dns" to "DNS 探测", "cache" to "缓存清理"),
                selectedKey = tab,
                onSelect = { tab = it },
                modifier = Modifier.fillMaxWidth(),
            )

            when (tab) {
                "dns" -> {
                    OutlinedTextField(
                        value = dnsName,
                        onValueChange = { dnsName = it },
                        label = { Text("查询域名") },
                        placeholder = { Text("例如 example.com") },
                        singleLine = true,
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(7.dp),
                    ) {
                        DNS_QTYPES.forEach { qt ->
                            val selected = dnsType == qt
                            val accent = MaterialTheme.colorScheme.primary
                            Surface(
                                onClick = { dnsType = qt },
                                modifier = Modifier.minimumInteractiveComponentSize().heightIn(min = 38.dp),
                                shape = RoundedCornerShape(999.dp),
                                color = if (selected) accent.copy(alpha = if (ext.isDark) 0.26f else 0.14f) else ext.wellSurface,
                                border = BorderStroke(1.dp, if (selected) accent.copy(alpha = 0.72f) else ext.hairline),
                            ) {
                                Text(
                                    text = qt,
                                    style = NexusNumericStyles.monoBadge,
                                    color = if (selected) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(horizontal = 13.dp, vertical = 9.dp),
                                )
                            }
                        }
                    }
                    OutlinedTextField(
                        value = dnsServer,
                        onValueChange = { dnsServer = it },
                        label = { Text("指定 DNS 服务器（可选）") },
                        placeholder = { Text("留空走默认路由，或填 remote-dns-0 / direct-dns-0") },
                        singleLine = true,
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    FilledTonalButton(
                        enabled = running && !queryingDns && dnsName.isNotBlank(),
                        onClick = {
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                            scope.launch {
                                queryingDns = true
                                dnsResult = onQueryDns(dnsName.trim(), dnsType, dnsServer.trim())
                                queryingDns = false
                            }
                        },
                        shape = RoundedCornerShape(999.dp),
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                    ) {
                        if (queryingDns) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                            Spacer(Modifier.width(8.dp))
                            Text("正在解析…")
                        } else {
                            Text(if (running) "执行实时 DNS 查询" else "请先启动隧道后再查询")
                        }
                    }
                    dnsResult?.let { res ->
                        DnsResultCard(res)
                    }
                }

                "cache" -> {
                    Surface(
                        shape = RoundedCornerShape(14.dp),
                        color = ext.wellSurface,
                        border = BorderStroke(1.dp, ext.hairline),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text("FakeIP 与精细缓存清理", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                            Text(
                                text = "按需清理内核 DNS 缓存、规则集缓存或未固定 FakeIP 映射。",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            FilledTonalButton(
                                enabled = running && !cacheBusy,
                                onClick = {
                                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                    scope.launch {
                                        cacheBusy = true
                                        val res = onFlushFakeIp()
                                        cacheNote = res.message
                                        onFeedback(res.message)
                                        cacheBusy = false
                                    }
                                },
                                shape = RoundedCornerShape(999.dp),
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Text("刷新 FakeIP 池")
                            }
                            FlowRow(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                listOf(
                                    "dns" to "清 DNS 缓存",
                                    "rulesets" to "清规则集缓存",
                                    "fakeip" to "清 FakeIP",
                                    "all" to "清空全部缓存",
                                ).forEach { (target, label) ->
                                    OutlinedButton(
                                        enabled = running && !cacheBusy,
                                        shape = RoundedCornerShape(999.dp),
                                        onClick = {
                                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                            scope.launch {
                                                cacheBusy = true
                                                val ok = onClearCacheTarget(target)
                                                cacheNote = if (ok) "已执行: $label" else "$label 失败"
                                                onFeedback(cacheNote)
                                                cacheBusy = false
                                            }
                                        },
                                    ) { Text(label) }
                                }
                            }
                        }
                    }
                    if (cacheNote.isNotEmpty()) {
                        Surface(
                            shape = RoundedCornerShape(12.dp),
                            color = ext.wellSurface,
                            border = BorderStroke(1.dp, ext.hairline),
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(cacheNote, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(10.dp))
                        }
                    }
                }

                else -> {
                    val activeRules = workspaceState.document.activeRoutingProfile().rules
                    if (activeRules.isNotEmpty()) {
                        Text("工作区规则 (${activeRules.size})", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold)
                        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            activeRules.take(20).forEach { rule ->
                                WorkspaceRuleManageRow(
                                    rule = rule,
                                    onToggle = { next ->
                                        scope.launch { onFeedback(workspaceActions.onToggleRoutingRule(rule.id, next)) }
                                    },
                                    onDelete = {
                                        scope.launch { onFeedback(workspaceActions.onDeleteRoutingRule(rule.id)) }
                                    },
                                )
                            }
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text("内核已编译规则 (${liveRules.size})", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                        IconButton(
                            enabled = running && !loadingRules,
                            onClick = {
                                scope.launch {
                                    loadingRules = true
                                    liveRules = onFetchLiveRules()
                                    loadingRules = false
                                }
                            },
                        ) {
                            Icon(painterResource(R.drawable.ic_refresh), "刷新规则", Modifier.size(18.dp))
                        }
                    }
                    OutlinedTextField(
                        value = ruleFilter,
                        onValueChange = { ruleFilter = it },
                        placeholder = { Text("筛选已编译规则…") },
                        singleLine = true,
                        shape = RoundedCornerShape(999.dp),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    val q = ruleFilter.trim().lowercase()
                    val matched = remember(liveRules, q) {
                        if (q.isEmpty()) liveRules.take(60)
                        else liveRules.filter {
                            it.type.lowercase().contains(q) ||
                                it.action.lowercase().contains(q) ||
                                it.target.lowercase().contains(q) ||
                                it.summary.lowercase().contains(q)
                        }.take(60)
                    }
                    if (!running) {
                        Text("隧道未运行时无法读取内核实时编译规则。", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    } else if (loadingRules) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                            Text("正在读取 /v1/rules …", style = MaterialTheme.typography.bodySmall)
                        }
                    } else if (matched.isEmpty()) {
                        Text("未匹配到内核规则。", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    } else {
                        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            matched.forEach { r ->
                                Surface(
                                    shape = RoundedCornerShape(12.dp),
                                    color = ext.wellSurface,
                                    border = BorderStroke(1.dp, ext.hairline),
                                    modifier = Modifier.fillMaxWidth(),
                                ) {
                                    Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                                            StatusPill("#${r.index}", ext.insetSurface, MaterialTheme.colorScheme.onSurfaceVariant, mono = true)
                                            StatusPill(r.type.ifBlank { "rule" }, ext.telemetryDownloadContainer, ext.telemetryDownload, mono = true)
                                            StatusPill("${r.action}→${r.target}", MaterialTheme.colorScheme.primaryContainer, MaterialTheme.colorScheme.onPrimaryContainer)
                                        }
                                        if (r.summary.isNotBlank()) {
                                            Text(r.summary, style = NexusNumericStyles.monoBadge, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun WorkspaceRuleManageRow(
    rule: RoutingRuleItem,
    onToggle: (Boolean) -> Unit,
    onDelete: () -> Unit,
) {
    val ext = NexusTheme.colors
    val summary = buildString {
        if (rule.domains.isNotEmpty()) append(rule.domains.take(2).joinToString(", "))
        if (rule.ips.isNotEmpty()) {
            if (isNotEmpty()) append(" · ")
            append(rule.ips.take(2).joinToString(", "))
        }
        if (rule.androidPackages.isNotEmpty()) {
            if (isNotEmpty()) append(" · ")
            append(rule.androidPackages.take(2).joinToString(", "))
        }
        if (rule.ruleSets.isNotEmpty()) {
            if (isNotEmpty()) append(" · ")
            append(rule.ruleSets.joinToString(", "))
        }
    }.ifBlank { rule.id }

    Surface(
        shape = RoundedCornerShape(12.dp),
        color = ext.wellSurface,
        border = BorderStroke(1.dp, ext.hairline),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(start = 10.dp, end = 4.dp, top = 6.dp, bottom = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(5.dp), verticalAlignment = Alignment.CenterVertically) {
                    StatusPill(rule.targetType.uppercase(), MaterialTheme.colorScheme.primaryContainer, MaterialTheme.colorScheme.onPrimaryContainer)
                    if (rule.tlsFragment) {
                        StatusPill("分片", ext.warningContainer, ext.warning)
                    }
                    if (rule.locked) {
                        StatusPill("内置", ext.mutedContainer, ext.muted)
                    }
                }
                Text(summary, style = NexusNumericStyles.monoBadge, color = MaterialTheme.colorScheme.onSurface, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            if (!rule.locked) {
                Switch(checked = rule.enabled, onCheckedChange = onToggle)
                IconButton(onClick = onDelete) {
                    Icon(painterResource(R.drawable.ic_delete), "删除规则", tint = ext.muted, modifier = Modifier.size(18.dp))
                }
            }
        }
    }
}

@Composable
private fun DnsResultCard(res: DnsQueryResult) {
    val ext = NexusTheme.colors
    Surface(
        shape = RoundedCornerShape(14.dp),
        color = if (res.ok) ext.wellSurface else ext.dangerContainer,
        border = BorderStroke(1.dp, if (res.ok) ext.hairline else ext.danger.copy(alpha = 0.45f)),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            if (!res.ok) {
                Text("查询失败: ${res.errorMessage}", style = MaterialTheme.typography.bodySmall, color = ext.danger)
            } else {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                    StatusPill(res.rcodeName.ifBlank { "RCODE ${res.rcode}" }, if (res.rcode == 0) ext.successContainer else ext.warningContainer, if (res.rcode == 0) ext.success else ext.warning, mono = true)
                    StatusPill("${res.elapsedMs} ms", ext.insetSurface, MaterialTheme.colorScheme.onSurfaceVariant, mono = true)
                    StatusPill("TTL ${res.ttl}s", ext.insetSurface, MaterialTheme.colorScheme.onSurfaceVariant, mono = true)
                }
                if (res.answers.isEmpty()) {
                    Text("无应答记录（空 Answer 段）", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    res.answers.forEach { a ->
                        Text("${a.type}  ${a.data}  (TTL ${a.ttl}s)", style = NexusNumericStyles.codeBlock, color = MaterialTheme.colorScheme.onSurface)
                    }
                }
            }
        }
    }
}
