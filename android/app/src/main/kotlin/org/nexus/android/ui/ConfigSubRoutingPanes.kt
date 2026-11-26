package org.nexus.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
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
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.nexus.android.R
import org.nexus.android.bridge.workspace.ProfileItem
import org.nexus.android.bridge.workspace.ProfileKind
import org.nexus.android.bridge.workspace.SubscriptionItem
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
internal fun SubscriptionsPillarPane(
    state: WorkspaceUiState,
    actions: WorkspaceUiActions,
    onFeedback: (String) -> Unit,
) {
    val scope = rememberCoroutineScope()
    var subName by rememberSaveable { mutableStateOf("") }
    var subUrl by rememberSaveable { mutableStateOf("") }
    val chainCandidates = remember(state.document.profiles) {
        state.document.profiles.filter { it.kind == ProfileKind.NODE || it.kind == ProfileKind.POLICY_GROUP }
    }

    OpticalCard(cornerRadius = 16.dp) {
        Column(modifier = Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("订阅与链式前置/落地", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = subName,
                    onValueChange = { subName = it },
                    placeholder = { Text("订阅名称", maxLines = 1) },
                    shape = RoundedCornerShape(14.dp),
                    singleLine = true,
                    modifier = Modifier.weight(0.42f),
                )
                OutlinedTextField(
                    value = subUrl,
                    onValueChange = { subUrl = it },
                    placeholder = { Text("HTTPS 订阅地址", maxLines = 1) },
                    shape = RoundedCornerShape(14.dp),
                    singleLine = true,
                    modifier = Modifier.weight(0.58f),
                )
            }
            FilledTonalButton(
                enabled = subUrl.isNotBlank() && !state.isRefreshingSub,
                shape = RoundedCornerShape(999.dp),
                onClick = {
                    val n = subName.trim().ifEmpty { "订阅" }
                    val u = subUrl.trim()
                    subName = ""
                    subUrl = ""
                    scope.launch { onFeedback(actions.onAddSubscription(n, u)) }
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(painterResource(R.drawable.ic_add), null, Modifier.size(16.dp))
                Spacer(Modifier.width(6.dp))
                Text("添加并拉取订阅")
            }

            state.document.subscriptions.forEach { sub ->
                key(sub.id) {
                    SubscriptionItemCard(
                        sub = sub,
                        chainCandidates = chainCandidates,
                        busy = state.isRefreshingSub,
                        onRefresh = { scope.launch { onFeedback(actions.onRefreshSubscription(sub.id)) } },
                        onUpdateChain = { prev, next ->
                            scope.launch { onFeedback(actions.onUpdateSubscriptionChain(sub.id, prev, next)) }
                        },
                    )
                }
            }
            if (state.document.subscriptions.isEmpty()) {
                Text("尚无订阅。更新订阅仅替换对应节点并保留路由、DNS 与本机设置。", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun SubscriptionItemCard(
    sub: SubscriptionItem,
    chainCandidates: List<ProfileItem>,
    busy: Boolean,
    onRefresh: () -> Unit,
    onUpdateChain: (prevId: String, nextId: String) -> Unit,
) {
    val ext = NexusTheme.colors
    var prevMenu by remember { mutableStateOf(false) }
    var nextMenu by remember { mutableStateOf(false) }
    val prevName = chainCandidates.firstOrNull { it.id == sub.prevProfileId }?.remarks?.ifBlank { sub.prevProfileId } ?: "无前置"
    val nextName = chainCandidates.firstOrNull { it.id == sub.nextProfileId }?.remarks?.ifBlank { sub.nextProfileId } ?: "无落地"

    Surface(
        shape = RoundedCornerShape(12.dp),
        color = ext.wellSurface,
        border = BorderStroke(1.dp, ext.hairline),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(sub.usage.profileTitle.ifBlank { sub.remarks.ifBlank { sub.id } }, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    if (sub.usage.expireUnixSec > 0L) {
                        val dateStr = remember(sub.usage.expireUnixSec) {
                            SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date(sub.usage.expireUnixSec * 1000L))
                        }
                        Text("到期 $dateStr", style = NexusNumericStyles.monoBadge, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                OutlinedButton(enabled = !busy, onClick = onRefresh, shape = RoundedCornerShape(999.dp), contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp)) {
                    Icon(painterResource(R.drawable.ic_refresh), null, Modifier.size(14.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("更新")
                }
            }
            if (sub.usage.hasQuota) {
                val used = sub.usage.usedBytes
                val rem = (sub.usage.totalBytes - used).coerceAtLeast(0L)
                NexusProportionBar(used, rem, MaterialTheme.colorScheme.primary, ext.insetSurface)
                Text(
                    text = "已用 ${formatTrafficBytes(used)} / 总计 ${formatTrafficBytes(sub.usage.totalBytes)}",
                    style = NexusNumericStyles.monoBadge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                ChainPickerPill("前置: $prevName", prevMenu, { prevMenu = it }, chainCandidates, { onUpdateChain(it, sub.nextProfileId) }, Modifier.weight(1f))
                ChainPickerPill("落地: $nextName", nextMenu, { nextMenu = it }, chainCandidates, { onUpdateChain(sub.prevProfileId, it) }, Modifier.weight(1f))
            }
        }
    }
}

@Composable
private fun ChainPickerPill(
    label: String,
    expanded: Boolean,
    onExpandedChange: (Boolean) -> Unit,
    candidates: List<ProfileItem>,
    onPick: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    var query by remember(expanded) { mutableStateOf("") }
    val shown = remember(candidates, query) {
        val q = query.trim().lowercase()
        val list = if (q.isEmpty()) candidates else candidates.filter {
            it.remarks.lowercase().contains(q) || it.id.lowercase().contains(q)
        }
        list.take(30)
    }

    Box(modifier = modifier) {
        Surface(
            onClick = { onExpandedChange(true) },
            shape = RoundedCornerShape(999.dp),
            color = ext.insetSurface,
            border = BorderStroke(1.dp, ext.hairline),
            modifier = Modifier.fillMaxWidth().minimumInteractiveComponentSize().heightIn(min = 40.dp),
        ) {
            Box(
                modifier = Modifier.padding(horizontal = 10.dp, vertical = 9.dp),
                contentAlignment = Alignment.CenterStart,
            ) {
                Text(
                    text = "$label ▾",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        DropdownMenu(expanded = expanded, onDismissRequest = { onExpandedChange(false) }) {
            if (candidates.size > 8) {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    placeholder = { Text("筛选节点…", maxLines = 1) },
                    singleLine = true,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                )
            }
            DropdownMenuItem(text = { Text("不设置") }, onClick = { onExpandedChange(false); onPick("") })
            shown.forEach { item ->
                DropdownMenuItem(
                    text = { Text(item.remarks.ifBlank { item.id }, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    onClick = { onExpandedChange(false); onPick(item.id) },
                )
            }
            if (candidates.size > shown.size && query.isEmpty()) {
                DropdownMenuItem(
                    enabled = false,
                    text = { Text("共 ${candidates.size} 项，输入关键字筛选", style = MaterialTheme.typography.labelSmall) },
                    onClick = {},
                )
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun RoutingDnsPillarPane(
    state: WorkspaceUiState,
    actions: WorkspaceUiActions,
    onOpenRuleDnsModal: () -> Unit,
    onOpenDiagnostics: (() -> Unit)? = null,
    onFeedback: (String) -> Unit,
) {
    val scope = rememberCoroutineScope()
    val ext = NexusTheme.colors
    val activeRouting = state.document.activeRoutingProfile()
    val dns = state.document.dns

    OpticalCard(cornerRadius = 16.dp) {
        Column(modifier = Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("路由方案", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            FlowRow(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(7.dp),
                verticalArrangement = Arrangement.spacedBy(7.dp),
            ) {
                state.document.routingProfiles.forEach { rp ->
                    val selected = rp.id == activeRouting.id
                    val accent = MaterialTheme.colorScheme.primary
                    Surface(
                        onClick = { scope.launch { onFeedback(actions.onSelectRoutingProfile(rp.id)) } },
                        modifier = Modifier.minimumInteractiveComponentSize().heightIn(min = 38.dp),
                        shape = RoundedCornerShape(999.dp),
                        color = if (selected) accent.copy(alpha = if (ext.isDark) 0.25f else 0.14f) else ext.wellSurface,
                        border = BorderStroke(1.dp, if (selected) accent.copy(alpha = 0.72f) else ext.hairline),
                    ) {
                        Text(
                            text = rp.name,
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
                            color = if (selected) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 9.dp),
                        )
                    }
                }
            }
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = ext.wellSurface,
                border = BorderStroke(1.dp, ext.hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        text = "当前规则: ${activeRouting.rules.size} 条 · 默认出站: ${activeRouting.defaultOutbound}",
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.SemiBold,
                    )
                    val dnsDesc = if (dns.mode == "raw_kdl") {
                        "DNS 模式: 高级自定义"
                    } else {
                        val fakeText = if (dns.simple.fakeIpEnabled) "FakeIP (${dns.simple.fakeIpV4Pool} / ${dns.simple.fakeIpV6Pool})" else "标准解析"
                        "DNS 模式: 简易 · $fakeText · ${dns.simple.strategy}"
                    }
                    Text(dnsDesc, style = NexusNumericStyles.monoBadge, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            FilledTonalButton(
                onClick = onOpenRuleDnsModal,
                shape = RoundedCornerShape(999.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(painterResource(R.drawable.ic_rule), null, Modifier.size(16.dp))
                Spacer(Modifier.width(6.dp))
                Text("编辑路由规则与 DNS 方案")
            }
            if (onOpenDiagnostics != null) {
                OutlinedButton(
                    onClick = onOpenDiagnostics,
                    shape = RoundedCornerShape(999.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(painterResource(R.drawable.ic_search), null, Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("实时规则视图 · DNS 探测 · 缓存清理")
                }
            }
        }
    }
}
