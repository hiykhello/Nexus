package org.nexus.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.nexus.android.R
import org.nexus.android.bridge.ipc.DnsQueryResult
import org.nexus.android.bridge.ipc.OutboundGroupSnapshot
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

/**
 * Signature Move #2 — Quick Command & Inline Domain Diagnostic Sheet:
 * - `0ms` instant open & instant filtering (zero stagger/shimmer)
 * - Compact phone: `ModalBottomSheet`; Foldable/Tablet: centered `Dialog` (`max 560.dp`)
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun QuickCommandSheet(
    initialQuery: String,
    running: Boolean,
    outboundMode: String,
    groups: List<OutboundGroupSnapshot>,
    windowSizeClass: NexusWindowSizeClass,
    onDismiss: () -> Unit,
    onSwitchMode: (String) -> Unit,
    onSelectNode: (groupTag: String, memberName: String) -> Unit,
    onProbeAll: () -> Unit,
    onFlushFakeIp: () -> Unit,
    onClearCache: () -> Unit,
    onOpenSplitTunnel: () -> Unit,
    onCreateRuleForHost: (host: String, action: String, outbound: String) -> Unit,
    onExplainRule: (suspend (target: String, routeMode: String) -> RuleExplainSummary?)? = null,
    onQueryDns: (suspend (host: String) -> DnsQueryResult)? = null,
    previewExplain: RuleExplainSummary? = null,
    previewDns: DnsQueryResult? = null,
) {
    val body: @Composable () -> Unit = {
        QuickCommandContent(
            initialQuery, running, outboundMode, groups, onDismiss, onSwitchMode,
            onSelectNode, onProbeAll, onFlushFakeIp, onClearCache, onOpenSplitTunnel,
            onCreateRuleForHost, onExplainRule, onQueryDns, previewExplain, previewDns,
        )
    }

    if (windowSizeClass == NexusWindowSizeClass.COMPACT) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ModalBottomSheet(
            onDismissRequest = onDismiss,
            sheetState = sheetState,
            shape = RoundedCornerShape(topStart = 20.dp, topEnd = 20.dp),
            containerColor = MaterialTheme.colorScheme.surfaceContainer,
        ) { body() }
    } else {
        Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = MaterialTheme.colorScheme.surfaceContainer,
                border = BorderStroke(1.dp, NexusTheme.colors.hairlineStrong),
                modifier = Modifier.padding(24.dp).widthIn(max = 560.dp).fillMaxWidth(),
            ) { body() }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun QuickCommandContent(
    initialQuery: String,
    running: Boolean,
    outboundMode: String,
    groups: List<OutboundGroupSnapshot>,
    onDismiss: () -> Unit,
    onSwitchMode: (String) -> Unit,
    onSelectNode: (groupTag: String, memberName: String) -> Unit,
    onProbeAll: () -> Unit,
    onFlushFakeIp: () -> Unit,
    onClearCache: () -> Unit,
    onOpenSplitTunnel: () -> Unit,
    onCreateRuleForHost: (host: String, action: String, outbound: String) -> Unit,
    onExplainRule: (suspend (target: String, routeMode: String) -> RuleExplainSummary?)? = null,
    onQueryDns: (suspend (host: String) -> DnsQueryResult)? = null,
    previewExplain: RuleExplainSummary? = null,
    previewDns: DnsQueryResult? = null,
) {
    val ext = NexusTheme.colors
    val haptic = LocalHapticFeedback.current
    val scope = rememberCoroutineScope()
    val focusRequester = remember { FocusRequester() }

    var query by remember(initialQuery) { mutableStateOf(initialQuery) }
    var diagLoading by remember { mutableStateOf(false) }
    var explainResult by remember(previewExplain) { mutableStateOf(previewExplain) }
    var dnsResult by remember(previewDns) { mutableStateOf(previewDns) }

    val isDomain = remember(query) { looksLikeDomainOrHost(query) }
    val diagHost = remember(query) { extractDiagnosticHost(query) }
    val nodeMatches = remember(groups, query) { filterCommandNodes(groups, query, limit = 10) }
    val matchedActions = remember(query, running, outboundMode) { filterQuickCommandActions(query, running, outboundMode) }
    val commandMode = query.trim().isEmpty() || query.trim().startsWith(">")

    fun runAction(id: QuickCommandActionId) {
        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
        when (id) {
            QuickCommandActionId.MODE_RULE -> onSwitchMode("rule")
            QuickCommandActionId.MODE_GLOBAL -> onSwitchMode("global")
            QuickCommandActionId.MODE_DIRECT -> onSwitchMode("direct")
            QuickCommandActionId.PROBE_ALL -> onProbeAll()
            QuickCommandActionId.FLUSH_FAKEIP -> onFlushFakeIp()
            QuickCommandActionId.CLEAR_CACHE -> onClearCache()
            QuickCommandActionId.SPLIT_TUNNEL -> onOpenSplitTunnel()
        }
        onDismiss()
    }

    fun executePrimaryMatch(): Boolean {
        if (commandMode && matchedActions.isNotEmpty()) {
            runAction(matchedActions.first().id)
            return true
        }
        if (nodeMatches.isNotEmpty()) {
            val top = nodeMatches.first()
            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
            scope.launch { onSelectNode(top.groupTag, top.member.name); onDismiss() }
            return true
        }
        return false
    }

    LaunchedEffect(Unit) {
        if (previewExplain == null && previewDns == null) runCatching { focusRequester.requestFocus() }
    }

    LaunchedEffect(query, running, outboundMode, previewExplain, previewDns) {
        if (previewExplain != null || previewDns != null) return@LaunchedEffect
        explainResult = null
        dnsResult = null
        if (!isDomain) {
            diagLoading = false
            return@LaunchedEffect
        }
        diagLoading = true
        try {
            delay(220L)
            coroutineScope {
                val explainDeferred = async {
                    runCatching { onExplainRule?.invoke(normalizeExplainTarget(query), outboundMode) }
                        .onFailure { if (it is CancellationException) throw it }
                        .getOrNull()
                }
                val dnsDeferred = async {
                    if (!running) null else runCatching { onQueryDns?.invoke(diagHost) }
                        .onFailure { if (it is CancellationException) throw it }
                        .getOrNull()
                }
                explainResult = explainDeferred.await()
                dnsResult = dnsDeferred.await()
            }
        } finally {
            diagLoading = false
        }
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .imePadding()
            .onPreviewKeyEvent { ev ->
                if (ev.type != KeyEventType.KeyDown) return@onPreviewKeyEvent false
                when (ev.key) {
                    Key.Escape -> { onDismiss(); true }
                    Key.Enter, Key.NumPadEnter -> executePrimaryMatch()
                    else -> false
                }
            }
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                placeholder = { Text("搜节点、输入域名诊断或 > 命令…", maxLines = 1, overflow = TextOverflow.Ellipsis) },
                leadingIcon = { Icon(painterResource(R.drawable.ic_search), null, Modifier.size(18.dp)) },
                trailingIcon = {
                    if (query.isNotEmpty()) {
                        IconButton(onClick = { query = "" }) {
                            Icon(painterResource(R.drawable.ic_close), "清除", Modifier.size(18.dp))
                        }
                    }
                },
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Go),
                keyboardActions = KeyboardActions(onGo = { executePrimaryMatch() }),
                shape = RoundedCornerShape(999.dp),
                modifier = Modifier.weight(1f).focusRequester(focusRequester),
            )
            IconButton(onClick = onDismiss) {
                Icon(painterResource(R.drawable.ic_close), "关闭", Modifier.size(20.dp))
            }
        }

        if (isDomain) {
            DomainDiagnosticCard(
                host = diagHost,
                running = running,
                loading = diagLoading,
                explain = explainResult,
                dns = dnsResult,
                onFlushFakeIp = {
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    onFlushFakeIp()
                    onDismiss()
                },
                onCreateRule = { action, outbound ->
                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                    onCreateRuleForHost(diagHost, action, outbound)
                    onDismiss()
                },
            )
        }

        if (commandMode) {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("快捷操作", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (matchedActions.isNotEmpty()) {
                    FlowRow(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(7.dp),
                        verticalArrangement = Arrangement.spacedBy(7.dp),
                    ) {
                        matchedActions.forEach { spec ->
                            CommandActionChip(spec.label, spec.selected) { runAction(spec.id) }
                        }
                    }
                } else {
                    Text(
                        text = "未匹配到命令；试试 > 规则、> 全局、> 直连、> 测速、> FakeIP、> 缓存 或 > 分应用",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        if (nodeMatches.isNotEmpty()) {
            Text(
                text = if (query.isBlank()) "快捷切点" else "匹配节点 (${nodeMatches.size})",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            LazyColumn(
                modifier = Modifier.fillMaxWidth().heightIn(max = 260.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
                contentPadding = PaddingValues(bottom = 8.dp),
            ) {
                items(items = nodeMatches, key = { "${it.groupTag}:${it.member.name}" }) { match ->
                    val sel = match.member.selected
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = if (sel) MaterialTheme.colorScheme.primaryContainer else ext.wellSurface,
                        border = BorderStroke(1.dp, if (sel) MaterialTheme.colorScheme.primary else ext.hairline),
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp))
                            .clickable {
                                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                scope.launch { onSelectNode(match.groupTag, match.member.name); onDismiss() }
                            },
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(horizontal = 12.dp, vertical = 9.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Box(Modifier.size(7.dp).background(if (sel) ext.success else ext.muted.copy(alpha = 0.45f), CircleShape))
                            Text(
                                text = match.member.name,
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = if (sel) FontWeight.Bold else FontWeight.Medium,
                                color = if (sel) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurface,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.weight(1f),
                            )
                            StatusPill(match.groupTag, ext.insetSurface, MaterialTheme.colorScheme.onSurfaceVariant)
                            SignalBarsIndicator(match.member.latencyMs, match.member.state)
                            LatencyBadge(match.member.latencyMs, match.member.state)
                        }
                    }
                }
            }
        } else if (!isDomain && !commandMode) {
            Text(
                text = "未匹配到节点；输入完整域名（如 github.com）可实时诊断路由与 DNS。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(vertical = 8.dp),
            )
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun DomainDiagnosticCard(
    host: String,
    running: Boolean,
    loading: Boolean,
    explain: RuleExplainSummary?,
    dns: DnsQueryResult?,
    onFlushFakeIp: () -> Unit,
    onCreateRule: (action: String, outbound: String) -> Unit,
) {
    val ext = NexusTheme.colors
    val hasFakeIp = dns?.answers?.any { isFakeIpAddress(it.data) } == true
    val pillPad = PaddingValues(horizontal = 10.dp, vertical = 6.dp)
    Surface(
        shape = RoundedCornerShape(12.dp),
        color = ext.wellSurface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.40f)),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = host,
                    style = NexusNumericStyles.rateReadout,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                if (loading) CircularProgressIndicator(Modifier.size(14.dp), strokeWidth = 2.dp)
                else if (!running) StatusPill("核心未运行 · 仅本地匹配", ext.mutedContainer, ext.muted)
            }
            if (explain != null) {
                FlowRow(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    StatusPill(explain.routeRule, ext.insetSurface, MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.align(Alignment.CenterVertically))
                    Text("→", style = MaterialTheme.typography.labelSmall, color = ext.muted, modifier = Modifier.align(Alignment.CenterVertically))
                    StatusPill(
                        text = "${explain.action} · ${explain.outbound}",
                        containerColor = if (explain.action == "拦截") ext.dangerContainer else MaterialTheme.colorScheme.primaryContainer,
                        contentColor = if (explain.action == "拦截") ext.danger else MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.align(Alignment.CenterVertically),
                    )
                    StatusPill(explain.dnsPolicy, ext.insetSurface, MaterialTheme.colorScheme.onSurfaceVariant, mono = true, modifier = Modifier.align(Alignment.CenterVertically))
                }
            } else if (!loading && dns == null) {
                Text(
                    text = if (running) "暂未返回规则/DNS 诊断，可直接创建分流规则" else "核心未运行，可先创建分流规则或启动后实时查询 DNS",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (dns != null) {
                HorizontalDivider(color = ext.hairline)
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    val answerText = when {
                        !dns.ok -> dns.errorMessage.ifEmpty { "解析失败" }
                        dns.answers.isEmpty() -> "无记录 (${dns.rcodeName.ifEmpty { "NOERROR" }})"
                        else -> dns.answers.take(2).joinToString(", ") { it.data }
                    }
                    Text(answerText, style = NexusNumericStyles.monoBadge, color = if (dns.ok) MaterialTheme.colorScheme.onSurface else ext.danger, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                    if (hasFakeIp) StatusPill("FakeIP", ext.telemetryUploadContainer, ext.telemetryUpload, mono = true)
                    if (dns.elapsedMs > 0L) Text("${dns.elapsedMs} ms", style = NexusNumericStyles.monoBadge, color = ext.success)
                }
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { onCreateRule("route", "direct") }, shape = RoundedCornerShape(999.dp), contentPadding = pillPad, modifier = Modifier.weight(1f).heightIn(min = 40.dp)) { Text("设为直连", maxLines = 1) }
                FilledTonalButton(
                    onClick = { onCreateRule("route", "proxy") },
                    shape = RoundedCornerShape(999.dp),
                    colors = ButtonDefaults.filledTonalButtonColors(containerColor = MaterialTheme.colorScheme.primaryContainer, contentColor = MaterialTheme.colorScheme.onPrimaryContainer),
                    contentPadding = pillPad,
                    modifier = Modifier.weight(1f).heightIn(min = 40.dp),
                ) { Text("设为代理", maxLines = 1) }
                if (hasFakeIp && running) {
                    OutlinedButton(onClick = onFlushFakeIp, shape = RoundedCornerShape(999.dp), contentPadding = pillPad, modifier = Modifier.heightIn(min = 40.dp)) { Text("刷新 FakeIP", maxLines = 1) }
                }
            }
        }
    }
}

@Composable
private fun CommandActionChip(label: String, selected: Boolean, onClick: () -> Unit) {
    val ext = NexusTheme.colors
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(999.dp),
        color = if (selected) MaterialTheme.colorScheme.primaryContainer else ext.wellSurface,
        border = BorderStroke(1.dp, if (selected) MaterialTheme.colorScheme.primary else ext.hairline),
        modifier = Modifier.minimumInteractiveComponentSize().heightIn(min = 40.dp),
    ) {
        Box(Modifier.padding(horizontal = 13.dp, vertical = 9.dp), contentAlignment = Alignment.Center) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
                color = if (selected) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                softWrap = false,
            )
        }
    }
}
