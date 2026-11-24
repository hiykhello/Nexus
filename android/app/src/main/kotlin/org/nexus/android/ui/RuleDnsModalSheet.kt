package org.nexus.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
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
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.nexus.android.R
import org.nexus.android.bridge.model.AndroidKdlOps
import org.nexus.android.bridge.model.AndroidRuleOps
import org.nexus.android.ui.theme.NexusTheme

private val ROUTE_MATCH_OPTIONS = listOf(
    "domain-suffix" to "域名后缀",
    "domain" to "完整域名",
    "domain-keyword" to "关键词",
    "ip-cidr" to "IP CIDR",
)

private val DNS_MATCH_OPTIONS = listOf(
    "domain-suffix" to "域名后缀",
    "domain" to "完整域名",
    "domain-keyword" to "关键词",
    "source-ip-cidr" to "源 IP",
)

/**
 * Focused Rules & DNS Modal Bottom Sheet launched from `档案` (`ConfigScreen`).
 * Lets Android users append routing & DNS rules with automatic validation and hot-reload
 * without ever exposing raw config syntax.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun RuleDnsModalSheet(
    kdlText: String,
    onApplyConfig: suspend (String) -> Pair<Boolean, String>,
    onResultFeedback: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val haptic = LocalHapticFeedback.current
    val ext = NexusTheme.colors
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    val outbounds = remember(kdlText) { AndroidRuleOps.extractOutboundTargets(kdlText) }
    val dnsServers = remember(kdlText) { AndroidRuleOps.extractDnsServers(kdlText) }
    val defaultProxy = remember(kdlText) { AndroidKdlOps.extractProxyGroupName(kdlText) }

    var activeTab by rememberSaveable { mutableStateOf("route") }
    var routeMatchType by rememberSaveable { mutableStateOf("domain-suffix") }
    var routePattern by rememberSaveable { mutableStateOf("") }
    var routeAction by rememberSaveable { mutableStateOf("proxy") }
    var selectedOutbound by rememberSaveable { mutableStateOf(defaultProxy) }

    var dnsMatchType by rememberSaveable { mutableStateOf("domain-suffix") }
    var dnsPattern by rememberSaveable { mutableStateOf("") }
    var dnsAction by rememberSaveable { mutableStateOf("route") }
    var selectedDnsServer by rememberSaveable { mutableStateOf(dnsServers.firstOrNull() ?: "local") }

    var busy by remember { mutableStateOf(false) }
    var inlineError by remember { mutableStateOf("") }

    val effectiveOutbound = when (routeAction) {
        "direct" -> "direct"
        "proxy" -> selectedOutbound.ifBlank { defaultProxy }
        else -> ""
    }

    ModalBottomSheet(
        onDismissRequest = { if (!busy) onDismiss() },
        sheetState = sheetState,
        shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp),
        containerColor = MaterialTheme.colorScheme.surfaceContainer,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .imePadding()
                .navigationBarsPadding()
                .padding(horizontal = 18.dp)
                .padding(bottom = 18.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Icon(
                    painter = painterResource(R.drawable.ic_rule),
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(18.dp),
                )
                Text(
                    text = "路由与 DNS 规则",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.weight(1f),
                )
                IconButton(onClick = { if (!busy) onDismiss() }, modifier = Modifier.size(32.dp)) {
                    Icon(
                        painter = painterResource(R.drawable.ic_close),
                        contentDescription = "关闭",
                        modifier = Modifier.size(18.dp),
                    )
                }
            }

            OpticalSegmentedControl(
                options = listOf("route" to "路由规则", "dns" to "DNS 规则"),
                selectedKey = activeTab,
                onSelect = {
                    activeTab = it
                    inlineError = ""
                },
                modifier = Modifier.fillMaxWidth(),
            )

            val matchOptions = if (activeTab == "route") ROUTE_MATCH_OPTIONS else DNS_MATCH_OPTIONS
            val currentMatch = if (activeTab == "route") routeMatchType else dnsMatchType

            Text(
                text = "匹配方式",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(
                modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(7.dp),
            ) {
                matchOptions.forEach { (key, label) ->
                    ModalSelectPill(
                        label = label,
                        selected = currentMatch == key,
                        onClick = {
                            if (activeTab == "route") routeMatchType = key else dnsMatchType = key
                            inlineError = ""
                        },
                    )
                }
            }

            val patternVal = if (activeTab == "route") routePattern else dnsPattern
            val hintText = when (currentMatch) {
                "ip-cidr", "source-ip-cidr" -> "例如 192.168.1.0/24 或 1.1.1.1"
                "domain-keyword" -> "例如 google"
                "domain" -> "例如 api.github.com"
                else -> if (activeTab == "route") "例如 openai.com" else "例如 internal.corp"
            }
            OutlinedTextField(
                value = patternVal,
                onValueChange = {
                    if (activeTab == "route") routePattern = it else dnsPattern = it
                    inlineError = ""
                },
                label = { Text("匹配目标", maxLines = 1, overflow = TextOverflow.Ellipsis) },
                placeholder = { Text(hintText, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                shape = RoundedCornerShape(14.dp),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            Text(
                text = if (activeTab == "route") "分流动作" else "解析策略",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (activeTab == "route") {
                Row(
                    modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(7.dp),
                ) {
                    ModalSelectPill("走代理", routeAction == "proxy") { routeAction = "proxy" }
                    ModalSelectPill("直连放行", routeAction == "direct") { routeAction = "direct" }
                    ModalSelectPill("拦截拒绝", routeAction == "reject") { routeAction = "reject" }
                }
                if (routeAction == "proxy" && outbounds.isNotEmpty()) {
                    Row(
                        modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(7.dp),
                    ) {
                        outbounds.filter { it != "direct" }.forEach { tag ->
                            ModalSelectPill(
                                label = "出口: $tag",
                                selected = selectedOutbound == tag,
                                onClick = { selectedOutbound = tag },
                            )
                        }
                    }
                }
            } else {
                Row(
                    modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(7.dp),
                ) {
                    ModalSelectPill("指定 DNS 服务器", dnsAction == "route") { dnsAction = "route" }
                    ModalSelectPill("拒绝解析", dnsAction == "reject") { dnsAction = "reject" }
                }
                if (dnsAction == "route") {
                    Row(
                        modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(7.dp),
                    ) {
                        dnsServers.forEach { tag ->
                            ModalSelectPill(
                                label = "DNS: $tag",
                                selected = selectedDnsServer == tag,
                                onClick = { selectedDnsServer = tag },
                            )
                        }
                    }
                }
            }

            if (inlineError.isNotEmpty()) {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = ext.dangerContainer,
                    border = BorderStroke(1.dp, ext.danger.copy(alpha = 0.45f)),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        text = inlineError,
                        style = MaterialTheme.typography.bodySmall,
                        color = ext.danger,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                    )
                }
            }

            val summaryText = remember(
                activeTab, routeMatchType, routePattern, routeAction, effectiveOutbound,
                dnsMatchType, dnsPattern, dnsAction, selectedDnsServer,
            ) {
                val label = matchOptions.firstOrNull { it.first == currentMatch }?.second ?: currentMatch
                val target = patternVal.trim().ifEmpty { "待输入" }
                if (activeTab == "route") {
                    val dest = when (routeAction) {
                        "direct" -> "直连"
                        "reject" -> "拦截"
                        else -> "代理 ($effectiveOutbound)"
                    }
                    "$label · $target  →  $dest"
                } else {
                    val dest = if (dnsAction == "reject") "拒绝解析" else "DNS ($selectedDnsServer)"
                    "$label · $target  →  $dest"
                }
            }
            Surface(
                shape = RoundedCornerShape(14.dp),
                color = ext.wellSurface,
                border = BorderStroke(1.dp, ext.hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text = summaryText,
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.Medium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 9.dp),
                )
            }

            Spacer(Modifier.height(2.dp))
            val submitEnabled = !busy && patternVal.trim().isNotEmpty()
            LiquidGlassButton(
                onClick = {
                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                    val built = if (activeTab == "route") {
                        val action = if (routeAction == "reject") "reject" else "route"
                        AndroidRuleOps.buildCustomRouteRule(
                            matchType = routeMatchType,
                            pattern = routePattern,
                            action = action,
                            outbound = effectiveOutbound,
                        )
                    } else {
                        AndroidRuleOps.buildDnsRule(
                            matchType = dnsMatchType,
                            pattern = dnsPattern,
                            action = dnsAction,
                            server = selectedDnsServer,
                        )
                    }
                    if (!built.first) {
                        inlineError = built.second
                        return@LiquidGlassButton
                    }
                    val merged = if (activeTab == "route") {
                        AndroidKdlOps.insertRouteRule(kdlText, built.second)
                    } else {
                        AndroidRuleOps.insertDnsRule(kdlText, built.second)
                    }
                    if (!merged.first) {
                        inlineError = merged.second
                        return@LiquidGlassButton
                    }
                    busy = true
                    inlineError = ""
                    scope.launch {
                        val (ok, note) = onApplyConfig(merged.second)
                        busy = false
                        if (ok) {
                            onResultFeedback(note.ifBlank { "规则已添加并热重载" })
                            onDismiss()
                        } else {
                            inlineError = note.ifBlank { "规则校验失败" }
                        }
                    }
                },
                tint = if (submitEnabled) Color(0xFF2563EB) else ext.insetSurface,
                surfaceBase = if (submitEnabled) Color(0xFF1D4ED8) else ext.wellSurface,
                contentColor = if (submitEnabled) Color.White else MaterialTheme.colorScheme.onSurfaceVariant,
                enabled = submitEnabled,
                cornerRadius = 999.dp,
                isDark = ext.isDark,
                modifier = Modifier.fillMaxWidth().height(46.dp),
            ) {
                Text(
                    text = if (busy) "正在应用规则..." else "校验并添加到配置",
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold,
                )
            }
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
        shape = RoundedCornerShape(999.dp),
        color = if (selected) accent.copy(alpha = if (ext.isDark) 0.26f else 0.14f) else ext.wellSurface,
        border = BorderStroke(
            width = if (selected) 1.2.dp else 1.dp,
            color = if (selected) accent.copy(alpha = 0.72f) else ext.hairline,
        ),
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
            color = if (selected) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            softWrap = false,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 7.dp),
        )
    }
}
