package org.nexus.android.ui

import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
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
import org.nexus.android.bridge.workspace.RuleSetAsset
import org.nexus.android.bridge.workspace.SubscriptionItem
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val DOMAIN_STRATEGIES = listOf(
    "as-is" to "as-is (域名直判)",
    "prefer_ipv4" to "prefer_ipv4",
    "prefer_ipv6" to "prefer_ipv6",
    "ipv4_only" to "ipv4_only",
    "ipv6_only" to "ipv6_only",
)

private val DEFAULT_OUTBOUNDS = listOf("proxy" to "默认走代理", "direct" to "默认直连", "block" to "默认阻断")

/**
 * Subscription Group Manager Card (supports URL, regex filter, auto-update interval, User-Agent,
 * prev/next chain hops, quota bar, refresh, and delete).
 */
@Composable
internal fun SubscriptionsPillarPane(
    state: WorkspaceUiState,
    actions: WorkspaceUiActions,
    onFeedback: (String) -> Unit,
) {
    val scope = rememberCoroutineScope()
    var subName by rememberSaveable { mutableStateOf("") }
    var subUrl by rememberSaveable { mutableStateOf("") }
    var autoMin by rememberSaveable { mutableStateOf("0") }
    var incRegex by rememberSaveable { mutableStateOf("") }
    var excRegex by rememberSaveable { mutableStateOf("") }
    var userAgent by rememberSaveable { mutableStateOf("") }

    val chainCandidates = remember(state.document.profiles) {
        state.document.profiles.filter { it.kind == ProfileKind.NODE || it.kind == ProfileKind.POLICY_GROUP }
    }

    OpticalCard(cornerRadius = 12.dp) {
        Column(modifier = Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("订阅分组管理与链式前置/落地", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(subName, { subName = it }, label = { Text("分组名称") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.4f))
                OutlinedTextField(subUrl, { subUrl = it }, label = { Text("HTTPS 订阅链接 (留空为本地组)") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.6f))
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(incRegex, { incRegex = it }, label = { Text("包含正则") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.36f))
                OutlinedTextField(excRegex, { excRegex = it }, label = { Text("排除正则") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.36f))
                OutlinedTextField(autoMin, { autoMin = it.filter(Char::isDigit) }, label = { Text("自动分") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.28f))
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(userAgent, { userAgent = it }, label = { Text("自定义 User-Agent (可选)") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(1f))
                Button(
                    enabled = (subName.isNotBlank() || subUrl.isNotBlank()) && !state.isRefreshingSub,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.heightIn(min = 48.dp),
                    onClick = {
                        val item = SubscriptionItem(
                            id = "",
                            remarks = subName.trim().ifEmpty { "订阅分组" },
                            url = subUrl.trim(),
                            enabled = true,
                            autoUpdateMinutes = autoMin.toIntOrNull() ?: 0,
                            userAgent = userAgent.trim(),
                            includeRegex = incRegex.trim(),
                            excludeRegex = excRegex.trim(),
                        )
                        subName = ""; subUrl = ""; incRegex = ""; excRegex = ""; userAgent = ""
                        scope.launch { onFeedback(actions.onSaveSubscription(item, item.url.isNotBlank())) }
                    },
                ) { Text("保存订阅") }
            }

            state.document.subscriptions.forEach { sub ->
                key(sub.id) {
                    SubscriptionItemWell(
                        sub = sub,
                        chainCandidates = chainCandidates,
                        busy = state.isRefreshingSub,
                        onRefresh = { scope.launch { onFeedback(actions.onRefreshSubscription(sub.id)) } },
                        onDelete = { scope.launch { onFeedback(actions.onDeleteSubscription(sub.id)) } },
                        onUpdateChain = { prev, next -> scope.launch { onFeedback(actions.onUpdateSubscriptionChain(sub.id, prev, next)) } },
                    )
                }
            }
        }
    }
}

@Composable
private fun SubscriptionItemWell(
    sub: SubscriptionItem,
    chainCandidates: List<ProfileItem>,
    busy: Boolean,
    onRefresh: () -> Unit,
    onDelete: () -> Unit,
    onUpdateChain: (prevId: String, nextId: String) -> Unit,
) {
    val ext = NexusTheme.colors
    var prevMenu by remember { mutableStateOf(false) }
    var nextMenu by remember { mutableStateOf(false) }
    val prevName = chainCandidates.firstOrNull { it.id == sub.prevProfileId }?.remarks?.ifBlank { sub.prevProfileId } ?: "无前置"
    val nextName = chainCandidates.firstOrNull { it.id == sub.nextProfileId }?.remarks?.ifBlank { sub.nextProfileId } ?: "无落地"

    Surface(shape = RoundedCornerShape(8.dp), color = ext.wellSurface, modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(sub.usage.profileTitle.ifBlank { sub.remarks.ifBlank { sub.id } }, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    val meta = buildList {
                        if (sub.usage.expireUnixSec > 0L) add("到期 " + SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date(sub.usage.expireUnixSec * 1000L)))
                        if (sub.autoUpdateMinutes > 0) add("每 ${sub.autoUpdateMinutes}m 自动更新")
                        if (sub.includeRegex.isNotEmpty()) add("含:${sub.includeRegex}")
                    }.joinToString(" · ")
                    if (meta.isNotEmpty()) Text(meta, style = NexusNumericStyles.monoBadge, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                if (sub.url.isNotBlank()) {
                    OutlinedButton(enabled = !busy, onClick = onRefresh, shape = RoundedCornerShape(8.dp), contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp)) {
                        Text("更新")
                    }
                }
                IconButton(onClick = onDelete) {
                    Icon(painterResource(R.drawable.ic_delete), "删除订阅", tint = ext.muted, modifier = Modifier.size(18.dp))
                }
            }
            if (sub.usage.hasQuota) {
                val used = sub.usage.usedBytes
                val rem = (sub.usage.totalBytes - used).coerceAtLeast(0L)
                NexusProportionBar(used, rem, MaterialTheme.colorScheme.primary, ext.insetSurface)
                Text("已用 ${formatTrafficBytes(used)} / ${formatTrafficBytes(sub.usage.totalBytes)}", style = NexusNumericStyles.monoBadge, color = MaterialTheme.colorScheme.onSurfaceVariant)
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
    Box(modifier = modifier) {
        Surface(
            onClick = { onExpandedChange(true) },
            shape = RoundedCornerShape(8.dp),
            color = ext.insetSurface,
            modifier = Modifier.fillMaxWidth().minimumInteractiveComponentSize().heightIn(min = 40.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 9.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(label, style = MaterialTheme.typography.labelSmall, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                Icon(painterResource(R.drawable.ic_chevron_down), null, tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(16.dp))
            }
        }
        DropdownMenu(expanded = expanded, onDismissRequest = { onExpandedChange(false) }) {
            DropdownMenuItem(text = { Text("不设置") }, onClick = { onExpandedChange(false); onPick("") })
            candidates.take(30).forEach { item ->
                DropdownMenuItem(text = { Text(item.remarks.ifBlank { item.id }, maxLines = 1) }, onClick = { onExpandedChange(false); onPick(item.id) })
            }
        }
    }
}

/**
 * Routing Sets, Rules Table & `RuleSetAsset` (`nxmm` / `srs`) Manager Pane.
 */
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

    var newPresetName by rememberSaveable { mutableStateOf("") }
    var rsTag by rememberSaveable { mutableStateOf("") }
    var rsSource by rememberSaveable { mutableStateOf("remote") }
    var rsFormat by rememberSaveable { mutableStateOf("srs") }
    var rsLocation by rememberSaveable { mutableStateOf("") }
    var rsIntervalMin by rememberSaveable { mutableStateOf("1440") }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        OpticalCard(cornerRadius = 12.dp) {
            Column(modifier = Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("路由集与全局分流策略", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                FlowRow(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    state.document.routingProfiles.forEach { rp ->
                        EditorChoiceChip("${rp.name} (${rp.rules.size})", selected = rp.id == activeRouting.id) {
                            scope.launch { onFeedback(actions.onSelectRoutingProfile(rp.id)) }
                        }
                    }
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(newPresetName, { newPresetName = it }, placeholder = { Text("新建路由方案名称…") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(1f))
                    FilledTonalButton(
                        enabled = newPresetName.isNotBlank(),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.heightIn(min = 48.dp),
                        onClick = {
                            val n = newPresetName.trim(); newPresetName = ""
                            scope.launch { onFeedback(actions.onSaveRoutingStrategy(n, activeRouting.domainStrategy, activeRouting.defaultOutbound, activeRouting.autoDetectInterface, activeRouting.findProcess)) }
                        },
                    ) { Text("新建方案") }
                }

                Text("域名解析策略 (domain_strategy)", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                FlowRow(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    DOMAIN_STRATEGIES.forEach { (k, l) ->
                        EditorChoiceChip(l, activeRouting.domainStrategy.ifBlank { "as-is" } == k) {
                            scope.launch { onFeedback(actions.onSaveRoutingStrategy("", k, activeRouting.defaultOutbound, activeRouting.autoDetectInterface, activeRouting.findProcess)) }
                        }
                    }
                }

                FlowRow(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    DEFAULT_OUTBOUNDS.forEach { (k, l) ->
                        EditorChoiceChip(l, activeRouting.defaultOutbound.ifBlank { "proxy" } == k) {
                            scope.launch { onFeedback(actions.onSaveRoutingStrategy("", activeRouting.domainStrategy, k, activeRouting.autoDetectInterface, activeRouting.findProcess)) }
                        }
                    }
                }

                Surface(shape = RoundedCornerShape(8.dp), color = ext.wellSurface, modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        EditorSwitchRow("自动探测默认物理网卡 (auto_detect_interface)", activeRouting.autoDetectInterface) { next ->
                            scope.launch { onFeedback(actions.onUpdateRoutingFlags(next, activeRouting.findProcess)) }
                        }
                        HorizontalDivider(color = ext.hairline)
                        EditorSwitchRow("启用进程与应用包名识别 (find_process)", activeRouting.findProcess) { next ->
                            scope.launch { onFeedback(actions.onUpdateRoutingFlags(activeRouting.autoDetectInterface, next)) }
                        }
                    }
                }

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = onOpenRuleDnsModal, shape = RoundedCornerShape(8.dp), modifier = Modifier.weight(1f).heightIn(min = 46.dp)) {
                        Icon(painterResource(R.drawable.ic_add), null, Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("添加分流规则")
                    }
                    if (onOpenDiagnostics != null) {
                        OutlinedButton(onClick = onOpenDiagnostics, shape = RoundedCornerShape(8.dp), modifier = Modifier.weight(1f).heightIn(min = 46.dp)) {
                            Icon(painterResource(R.drawable.ic_search), null, Modifier.size(15.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("规则模拟诊断")
                        }
                    }
                }

                activeRouting.rules.forEachIndexed { idx, r ->
                    if (idx > 0) HorizontalDivider(color = ext.hairline)
                    val matchSummary = when {
                        r.domains.isNotEmpty() -> r.domains.joinToString(", ")
                        r.ips.isNotEmpty() -> r.ips.joinToString(", ")
                        r.ruleSets.isNotEmpty() -> "@" + r.ruleSets.joinToString(", @")
                        r.androidPackages.isNotEmpty() -> "pkg:" + r.androidPackages.joinToString(",")
                        r.ports.isNotEmpty() -> "port:" + r.ports.joinToString(",")
                        r.protocols.isNotEmpty() -> "proto:" + r.protocols.joinToString(",")
                        else -> r.networks.joinToString(",")
                    }
                    val tgt = if (r.targetType == "profile_id" && r.targetProfileId.isNotEmpty()) "@${r.targetProfileId}" else r.targetType
                    Row(modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Switch(
                            checked = r.enabled,
                            enabled = !r.locked,
                            onCheckedChange = { en -> scope.launch { onFeedback(actions.onToggleRoutingRule(r.id, en)) } },
                        )
                        Column(modifier = Modifier.weight(1f)) {
                            Text(matchSummary.ifBlank { r.id }, style = NexusNumericStyles.monoBadge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text("范围: ${r.scope}" + if (r.tlsFragment) " · TLS分片" else "", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        StatusPill(tgt, ext.wellSurface, MaterialTheme.colorScheme.primary, mono = true)
                        if (!r.locked) {
                            IconButton(onClick = { scope.launch { onFeedback(actions.onDeleteRoutingRule(r.id)) } }) {
                                Icon(painterResource(R.drawable.ic_delete), "删除规则", tint = ext.muted, modifier = Modifier.size(18.dp))
                            }
                        }
                    }
                }
            }
        }

        OpticalCard(cornerRadius = 12.dp) {
            Column(modifier = Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("规则集资源 (Rule-Set Assets · nxmm / srs)", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    EditorChoiceChip("远程 URL", rsSource == "remote") { rsSource = "remote" }
                    EditorChoiceChip("本地路径", rsSource == "local") { rsSource = "local" }
                    EditorChoiceChip("srs", rsFormat == "srs") { rsFormat = "srs" }
                    EditorChoiceChip("nxmm (零拷贝)", rsFormat == "nxmm") { rsFormat = "nxmm" }
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(rsTag, { rsTag = it }, label = { Text("规则集标签") }, placeholder = { Text("geosite-cn") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.42f))
                    OutlinedTextField(rsLocation, { rsLocation = it }, label = { Text(if (rsSource == "remote") "HTTPS 规则集 URL" else "本地文件路径") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.58f))
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(rsIntervalMin, { rsIntervalMin = it.filter(Char::isDigit) }, label = { Text("更新间隔(分钟)") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.45f))
                    FilledTonalButton(
                        enabled = rsTag.isNotBlank() && rsLocation.isNotBlank(),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.weight(0.55f).heightIn(min = 48.dp),
                        onClick = {
                            val asset = RuleSetAsset(
                                tag = rsTag.trim(),
                                sourceType = rsSource,
                                format = rsFormat,
                                path = if (rsSource == "local") rsLocation.trim() else "",
                                url = if (rsSource == "remote") rsLocation.trim() else "",
                                updateIntervalMs = (rsIntervalMin.toLongOrNull() ?: 1440L) * 60_000L,
                            )
                            rsTag = ""; rsLocation = ""
                            scope.launch { onFeedback(actions.onSaveRuleSetAsset(asset)) }
                        },
                    ) { Text("添加规则集") }
                }

                state.document.ruleSetAssets.forEachIndexed { idx, rs ->
                    if (idx > 0) HorizontalDivider(color = ext.hairline)
                    Row(modifier = Modifier.fillMaxWidth().heightIn(min = 46.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        StatusPill("@${rs.tag}", ext.telemetryDownloadContainer, ext.telemetryDownload, mono = true)
                        Column(modifier = Modifier.weight(1f)) {
                            Text(if (rs.sourceType == "remote") rs.url else rs.path, style = NexusNumericStyles.monoBadge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text("${rs.format} · ${rs.sourceType}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        IconButton(onClick = { scope.launch { onFeedback(actions.onDeleteRuleSetAsset(rs.tag)) } }) {
                            Icon(painterResource(R.drawable.ic_delete), "删除", tint = ext.muted, modifier = Modifier.size(18.dp))
                        }
                    }
                }
            }
        }
    }
}
