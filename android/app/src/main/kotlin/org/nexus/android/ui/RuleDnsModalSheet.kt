package org.nexus.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
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
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.nexus.android.R
import org.nexus.android.bridge.workspace.DnsConfig
import org.nexus.android.bridge.workspace.RoutingRuleItem
import org.nexus.android.bridge.workspace.SimpleDnsConfig
import org.nexus.android.bridge.workspace.WorkspaceStore
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

private val ROUTE_MATCH_OPTIONS = listOf(
    "domain-suffix" to "域名后缀",
    "domain" to "完整域名",
    "ip-cidr" to "IP CIDR",
    "android_packages" to "应用包名",
)

private val DNS_STRATEGIES = listOf(
    "prefer_ipv4" to "优先 IPv4",
    "prefer_ipv6" to "优先 IPv6",
    "ipv4_only" to "仅 IPv4",
)

/**
 * Focused Rules & DNS Modal Bottom Sheet backed by Layer 1 `WorkspaceDocument`:
 * - Single system bar inset handling (no redundant `.navigationBarsPadding()`)
 * - Semantic MaterialTheme primary CTA colors & 48dp touch targets
 * - Exposes Wave 30-31 `tlsFragment`, `autoDetectInterface`, `findProcess`, and `blockSvcbHttps`
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun RuleDnsModalSheet(
    workspaceState: WorkspaceUiState = WorkspaceUiState(),
    workspaceActions: WorkspaceUiActions = WorkspaceUiActions(),
    onResultFeedback: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val haptic = LocalHapticFeedback.current
    val ext = NexusTheme.colors
    val primary = MaterialTheme.colorScheme.primary
    val onPrimary = MaterialTheme.colorScheme.onPrimary
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    val activeRp = workspaceState.document.activeRoutingProfile()
    var activeTab by rememberSaveable { mutableStateOf("route") }
    var routeMatchType by rememberSaveable { mutableStateOf("domain-suffix") }
    var routePattern by rememberSaveable { mutableStateOf("") }
    var routeTargetType by rememberSaveable { mutableStateOf("proxy") }
    var routeTlsFragment by rememberSaveable { mutableStateOf(false) }
    var targetProfileId by rememberSaveable {
        mutableStateOf(workspaceState.document.profiles.firstOrNull()?.id.orEmpty())
    }
    var autoDetectInterface by rememberSaveable(activeRp.id) { mutableStateOf(activeRp.autoDetectInterface) }
    var findProcess by rememberSaveable(activeRp.id) { mutableStateOf(activeRp.findProcess) }

    val curDns = workspaceState.document.dns
    var dnsMode by rememberSaveable { mutableStateOf(curDns.mode) }
    var directDnsText by rememberSaveable { mutableStateOf(curDns.simple.directDns.joinToString(", ")) }
    var remoteDnsText by rememberSaveable { mutableStateOf(curDns.simple.remoteDns.joinToString(", ")) }
    var dnsStrategy by rememberSaveable { mutableStateOf(curDns.simple.strategy) }
    var fakeIpEnabled by rememberSaveable { mutableStateOf(curDns.simple.fakeIpEnabled) }
    var blockAaaa by rememberSaveable { mutableStateOf(curDns.simple.blockAaaa) }
    var blockSvcbHttps by rememberSaveable { mutableStateOf(curDns.simple.blockSvcbHttps) }
    var rawDnsKdl by rememberSaveable { mutableStateOf(curDns.rawKdl) }

    var busy by remember { mutableStateOf(false) }
    var inlineError by remember { mutableStateOf("") }

    ModalBottomSheet(
        onDismissRequest = { if (!busy) onDismiss() },
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
                Icon(painterResource(R.drawable.ic_rule), null, tint = primary, modifier = Modifier.size(18.dp))
                Text("路由规则与 DNS 方案", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                IconButton(onClick = { if (!busy) onDismiss() }) {
                    Icon(painterResource(R.drawable.ic_close), "关闭", Modifier.size(20.dp))
                }
            }

            OpticalSegmentedControl(
                options = listOf("route" to "路由规则", "dns" to "DNS 方案"),
                selectedKey = activeTab,
                onSelect = { activeTab = it; inlineError = "" },
                modifier = Modifier.fillMaxWidth(),
            )

            if (activeTab == "route") {
                Text("匹配方式", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                    ROUTE_MATCH_OPTIONS.forEach { (key, label) ->
                        ModalSelectPill(label, routeMatchType == key) { routeMatchType = key; inlineError = "" }
                    }
                }

                val hint = when (routeMatchType) {
                    "ip-cidr" -> "例如 192.168.1.0/24 或 1.1.1.1/32"
                    "android_packages" -> "例如 com.android.chrome, org.mozilla.firefox"
                    "domain" -> "例如 api.github.com"
                    else -> "例如 openai.com"
                }
                OutlinedTextField(
                    value = routePattern,
                    onValueChange = { routePattern = it; inlineError = "" },
                    label = { Text(if (routeMatchType == "android_packages") "Android 应用包名" else "匹配目标", maxLines = 1) },
                    placeholder = { Text(hint, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    shape = RoundedCornerShape(14.dp),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )

                Text("分流目标", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                    ModalSelectPill("走代理", routeTargetType == "proxy") { routeTargetType = "proxy" }
                    ModalSelectPill("直连放行", routeTargetType == "direct") { routeTargetType = "direct" }
                    ModalSelectPill("拦截拒绝", routeTargetType == "block") { routeTargetType = "block" }
                    if (workspaceState.document.profiles.isNotEmpty()) {
                        ModalSelectPill("指定档案", routeTargetType == "profile_id") { routeTargetType = "profile_id" }
                    }
                }
                if (routeTargetType == "profile_id" && workspaceState.document.profiles.isNotEmpty()) {
                    Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                        workspaceState.document.profiles.take(8).forEach { p ->
                            ModalSelectPill(p.remarks.ifBlank { p.id }, targetProfileId == p.id) { targetProfileId = p.id }
                        }
                    }
                }
                ModalToggleWell(
                    title = "TLS ClientHello 分片 (tls_fragment)",
                    subtitle = "对此条规则匹配的直连/代理 TLS 握手启用分片",
                    checked = routeTlsFragment,
                    onCheckedChange = { routeTlsFragment = it },
                )
                ModalToggleWell(
                    title = "自动探测默认出口网卡 (auto_detect_interface)",
                    subtitle = "路由方案级开关，跨平台工作区同步保留",
                    checked = autoDetectInterface,
                    onCheckedChange = { next ->
                        autoDetectInterface = next
                        scope.launch { onResultFeedback(workspaceActions.onUpdateRoutingFlags(next, findProcess)) }
                    },
                )
                ModalToggleWell(
                    title = "进程/应用归属识别 (find_process)",
                    subtitle = "开启路由引擎进程匹配与连接归属解析",
                    checked = findProcess,
                    onCheckedChange = { next ->
                        findProcess = next
                        scope.launch { onResultFeedback(workspaceActions.onUpdateRoutingFlags(autoDetectInterface, next)) }
                    },
                )
            } else {
                OpticalSegmentedControl(
                    options = listOf("simple" to "简易 DNS", "raw_kdl" to "Raw KDL"),
                    selectedKey = dnsMode,
                    onSelect = { dnsMode = it; inlineError = "" },
                    modifier = Modifier.fillMaxWidth(),
                )
                if (dnsMode == "simple") {
                    OutlinedTextField(
                        value = directDnsText,
                        onValueChange = { directDnsText = it },
                        label = { Text("直连 DNS（逗号分隔）") },
                        shape = RoundedCornerShape(14.dp),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = remoteDnsText,
                        onValueChange = { remoteDnsText = it },
                        label = { Text("远程代理 DNS（逗号分隔）") },
                        shape = RoundedCornerShape(14.dp),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Text("解析策略", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                        DNS_STRATEGIES.forEach { (key, label) ->
                            ModalSelectPill(label, dnsStrategy == key) { dnsStrategy = key }
                        }
                    }
                    ModalToggleWell(
                        title = "启用 FakeIP",
                        subtitle = "IPv4 198.18.0.0/16 · IPv6 fc00::/18",
                        checked = fakeIpEnabled,
                        onCheckedChange = { fakeIpEnabled = it },
                    )
                    ModalToggleWell(
                        title = "屏蔽 AAAA (IPv6) 解析",
                        subtitle = "对 AAAA 查询返回 NOERROR 空应答",
                        checked = blockAaaa,
                        onCheckedChange = { blockAaaa = it },
                    )
                    ModalToggleWell(
                        title = "屏蔽 HTTPS / SVCB 记录",
                        subtitle = "避免浏览器通过 HTTPS RR 绕过规则或降级 ECH",
                        checked = blockSvcbHttps,
                        onCheckedChange = { blockSvcbHttps = it },
                    )
                } else {
                    OutlinedTextField(
                        value = rawDnsKdl,
                        onValueChange = { rawDnsKdl = it },
                        label = { Text("Raw DNS KDL 块") },
                        textStyle = NexusNumericStyles.codeBlock,
                        shape = RoundedCornerShape(14.dp),
                        minLines = 5,
                        maxLines = 8,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }

            if (inlineError.isNotEmpty()) {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = ext.dangerContainer,
                    border = BorderStroke(1.dp, ext.danger.copy(alpha = 0.45f)),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(inlineError, style = MaterialTheme.typography.bodySmall, color = ext.danger, modifier = Modifier.padding(10.dp))
                }
            }

            Spacer(Modifier.height(2.dp))
            val submitEnabled = !busy && (activeTab == "dns" || routePattern.trim().isNotEmpty())
            LiquidGlassButton(
                onClick = {
                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                    busy = true
                    inlineError = ""
                    scope.launch {
                        val note = if (activeTab == "route") {
                            val items = routePattern.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                            if (items.isEmpty()) {
                                busy = false
                                inlineError = "请输入匹配目标"
                                return@launch
                            }
                            val rule = RoutingRuleItem(
                                id = WorkspaceStore.newProfileId("rule"),
                                enabled = true,
                                scope = if (routeMatchType == "android_packages") "routing_only" else "both",
                                targetType = routeTargetType,
                                targetProfileId = if (routeTargetType == "profile_id") targetProfileId else "",
                                domains = when (routeMatchType) {
                                    "domain-suffix" -> items.map { "domain:${it.removePrefix(".")}" }
                                    "domain" -> items.map { "full:$it" }
                                    else -> emptyList()
                                },
                                ips = if (routeMatchType == "ip-cidr") items else emptyList(),
                                androidPackages = if (routeMatchType == "android_packages") items else emptyList(),
                                tlsFragment = routeTlsFragment,
                            )
                            workspaceActions.onAddRoutingRule(rule)
                        } else {
                            val nextDns = DnsConfig(
                                mode = dnsMode,
                                simple = curDns.simple.copy(
                                    directDns = directDnsText.split(',').map { it.trim() }.filter { it.isNotEmpty() }.ifEmpty { listOf("local") },
                                    remoteDns = remoteDnsText.split(',').map { it.trim() }.filter { it.isNotEmpty() }.ifEmpty { listOf("https://1.1.1.1/dns-query") },
                                    strategy = dnsStrategy,
                                    fakeIpEnabled = fakeIpEnabled,
                                    fakeIpV4Pool = curDns.simple.fakeIpV4Pool.ifBlank { SimpleDnsConfig().fakeIpV4Pool },
                                    fakeIpV6Pool = curDns.simple.fakeIpV6Pool.ifBlank { SimpleDnsConfig().fakeIpV6Pool },
                                    blockAaaa = blockAaaa,
                                    blockSvcbHttps = blockSvcbHttps,
                                ),
                                rawKdl = rawDnsKdl,
                            )
                            workspaceActions.onUpdateDns(nextDns)
                        }
                        busy = false
                        onResultFeedback(note.ifBlank { "配置已更新" })
                        onDismiss()
                    }
                },
                tint = if (submitEnabled) primary else ext.insetSurface,
                surfaceBase = if (submitEnabled) lerp(primary, Color.Black, if (ext.isDark) 0.14f else 0.08f) else ext.wellSurface,
                contentColor = if (submitEnabled) onPrimary else MaterialTheme.colorScheme.onSurfaceVariant,
                enabled = submitEnabled,
                cornerRadius = 999.dp,
                isDark = ext.isDark,
                modifier = Modifier.fillMaxWidth().height(48.dp),
            ) {
                Text(
                    text = if (busy) "正在应用..." else if (activeTab == "route") "保存路由规则" else "保存 DNS 方案",
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold,
                    color = if (submitEnabled) onPrimary else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun ModalToggleWell(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    val ext = NexusTheme.colors
    Surface(
        shape = RoundedCornerShape(14.dp),
        color = ext.wellSurface,
        border = BorderStroke(1.dp, ext.hairline),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                Text(subtitle, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Switch(checked = checked, onCheckedChange = onCheckedChange)
        }
    }
}

@Composable
private fun ModalSelectPill(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    val ext = NexusTheme.colors
    val accent = MaterialTheme.colorScheme.primary
    Surface(
        onClick = onClick,
        modifier = Modifier.minimumInteractiveComponentSize().heightIn(min = 38.dp),
        shape = RoundedCornerShape(999.dp),
        color = if (selected) accent.copy(alpha = if (ext.isDark) 0.26f else 0.14f) else ext.wellSurface,
        border = BorderStroke(if (selected) 1.2.dp else 1.dp, if (selected) accent.copy(alpha = 0.72f) else ext.hairline),
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
            color = if (selected) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            softWrap = false,
            modifier = Modifier.padding(horizontal = 13.dp, vertical = 9.dp),
        )
    }
}
