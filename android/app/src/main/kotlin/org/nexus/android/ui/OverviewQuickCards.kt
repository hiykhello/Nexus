package org.nexus.android.ui

import android.content.ClipboardManager
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.nexus.android.R
import org.nexus.android.bridge.ipc.OutboundMemberSnapshot
import org.nexus.android.bridge.workspace.NodeConfig
import org.nexus.android.bridge.workspace.ProfileItem
import org.nexus.android.bridge.workspace.ProfileKind
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

/**
 * Right-aligned semantic tabular RTT readout (`42 ms` / `超时` / `--`).
 */
@Composable
internal fun LatencyReadoutText(
    latencyMs: Long,
    state: String,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val isFailed = state == "timeout" || state == "error" || state == "circuit_open" || latencyMs == 0L
    val color = when {
        isFailed -> ext.danger
        latencyMs < 0L -> ext.muted
        latencyMs < 80L -> ext.success
        latencyMs < 180L -> MaterialTheme.colorScheme.primary
        latencyMs < 350L -> ext.warning
        else -> ext.danger
    }
    Text(
        text = when {
            isFailed -> "超时"
            latencyMs > 0L -> "$latencyMs ms"
            else -> "--"
        },
        style = if (isFailed) MaterialTheme.typography.labelSmall else NexusNumericStyles.monoBadge,
        fontWeight = FontWeight.Bold,
        color = color,
        maxLines = 1,
        softWrap = false,
        textAlign = TextAlign.End,
        modifier = modifier,
    )
}

internal fun shortProtocolBadge(profile: ProfileItem): String = when (profile.kind) {
    ProfileKind.POLICY_GROUP -> "GROUP"
    ProfileKind.PROXY_CHAIN -> "CHAIN"
    ProfileKind.CUSTOM_OUTBOUND -> "OUT"
    ProfileKind.FULL_CUSTOM_KDL -> "RAW"
    ProfileKind.NODE -> when (val p = profile.node?.protocol?.lowercase().orEmpty()) {
        "hysteria2" -> "HY2"
        "shadowsocks" -> "SS"
        "wireguard" -> "WG"
        "http-connect", "http" -> "HTTP"
        "" -> "NODE"
        else -> p.uppercase()
    }
}

internal fun formatNodeTransportSummary(n: NodeConfig): String = when (n.protocol.lowercase()) {
    "wireguard" -> "wg · mtu ${n.extra.wgMtu.takeIf { it > 0 } ?: 1420}"
    "masque" -> "h3 · ${n.extra.masqueMode.ifBlank { "connect-udp" }}"
    "hysteria2" -> buildString {
        append("quic+tls")
        if (n.extra.hy2Ports.isNotEmpty()) append(" · hop:${n.extra.hy2Ports}")
        if (n.extra.hy2SalamanderPassword.isNotEmpty()) append(" · obfs")
    }
    "tuic" -> "quic+tls · ${n.extra.tuicCongestionControl.ifBlank { "bbr" }}"
    "ssh" -> "ssh"
    "naive" -> "${n.extra.naiveProtocol.ifBlank { "h2" }}+tls"
    "shadowsocks" -> buildString {
        append(n.method.ifBlank { "aead" })
        if (n.multiplex.enabled) append("+${n.multiplex.protocol.ifBlank { "mux" }}")
    }
    "snell" -> buildString {
        append("v${n.extra.snellVersion.takeIf { it > 0 } ?: 4}")
        if (n.extra.snellObfs.isNotEmpty() && n.extra.snellObfs != "none") append("+${n.extra.snellObfs}")
    }
    else -> {
        val tr = n.transport.type.ifBlank { "tcp" }
        val tls = when {
            n.tls.realityPublicKey.isNotEmpty() -> "+reality"
            n.tls.enabled -> "+tls"
            else -> ""
        }
        val vision = if (n.flow.isNotEmpty()) "+vision" else ""
        val pq = if (n.tls.keyExchange.contains("mlkem")) "+pq" else ""
        val mux = if (n.multiplex.enabled) "+${n.multiplex.protocol.ifBlank { "mux" }}" else ""
        val frag = if (n.tls.fragment || n.tls.recordFragment) "+frag" else ""
        "$tr$tls$vision$pq$mux$frag"
    }
}

internal fun shortProfileEndpoint(profile: ProfileItem): String = when (profile.kind) {
    ProfileKind.NODE -> profile.node?.let { n ->
        "${n.server}:${n.port} · ${formatNodeTransportSummary(n)}"
    }.orEmpty()
    ProfileKind.POLICY_GROUP -> profile.policyGroup?.let { "${it.strategy} · ${it.memberIds.size} 成员" }.orEmpty()
    ProfileKind.PROXY_CHAIN -> "${profile.proxyChain?.hopIds?.size ?: 0} 跳代理链"
    ProfileKind.CUSTOM_OUTBOUND -> "自定义出站配置"
    ProfileKind.FULL_CUSTOM_KDL -> "完整自定义配置"
}

/**
 * Multi-Column Quick Node Matrix Card (`2-column` Bento node tiles — never full-width horizontal strips):
 * - Displays live group members when running, OR SQLite `workspaceProfiles` in Standby so it is NEVER hollow.
 */
@Composable
internal fun QuickNodesCarouselCard(
    running: Boolean,
    groupTag: String,
    nodes: List<OutboundMemberSnapshot>,
    workspaceProfiles: List<ProfileItem> = emptyList(),
    activeProfileId: String = "",
    isProbing: Boolean,
    onSelectNode: (OutboundMemberSnapshot) -> Unit,
    onSelectWorkspaceProfile: (String) -> Unit = {},
    onQuickPasteImport: (String) -> Unit = {},
    onProbeGroup: () -> Unit,
    onOpenGroups: () -> Unit,
    onOpenConfig: () -> Unit = onOpenGroups,
    maxVisibleNodes: Int = 6,
    nodeColumns: Int = 2,
    showP50Badge: Boolean = true,
    compactHeader: Boolean = !showP50Badge,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val context = LocalContext.current
    val haptic = LocalHapticFeedback.current
    val stats = remember(nodes) { computeGroupLatencyStats(nodes) }

    OpticalCard(cornerRadius = 12.dp, modifier = modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text(
                    text = "快速选点",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    softWrap = false,
                    modifier = Modifier.weight(1f),
                )
                Surface(
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        val clip = context.getSystemService(ClipboardManager::class.java)
                            ?.primaryClip?.getItemAt(0)?.coerceToText(context)?.toString()?.trim().orEmpty()
                        onQuickPasteImport(clip)
                    },
                    modifier = Modifier.minimumInteractiveComponentSize(),
                    shape = RoundedCornerShape(8.dp),
                    color = ext.wellSurface,
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = if (compactHeader) 7.dp else 9.dp, vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        Icon(painterResource(R.drawable.ic_paste), "剪贴板导入", tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(14.dp))
                        if (!compactHeader) {
                            Text("导入", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary, maxLines = 1, softWrap = false)
                        }
                    }
                }
                if (running && groupTag.isNotEmpty()) {
                    Surface(
                        onClick = { if (!isProbing) { haptic.performHapticFeedback(HapticFeedbackType.LongPress); onProbeGroup() } },
                        modifier = Modifier.minimumInteractiveComponentSize(),
                        shape = RoundedCornerShape(8.dp),
                        color = ext.wellSurface,
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = if (compactHeader) 7.dp else 9.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            if (isProbing) {
                                CircularProgressIndicator(Modifier.size(13.dp), strokeWidth = 1.8.dp, color = MaterialTheme.colorScheme.primary)
                            } else {
                                Icon(painterResource(R.drawable.ic_speed), "测速", tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(14.dp))
                            }
                            if (!compactHeader) {
                                Text(if (isProbing) "测速中" else "测速", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold, maxLines = 1, softWrap = false)
                            }
                        }
                    }
                }
                Row(
                    modifier = Modifier
                        .minimumInteractiveComponentSize()
                        .clip(RoundedCornerShape(8.dp))
                        .clickable(onClick = if (running && nodes.isNotEmpty()) onOpenGroups else onOpenConfig)
                        .padding(horizontal = 4.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("全部", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary, maxLines = 1, softWrap = false)
                    Icon(painterResource(R.drawable.ic_chevron_right), null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(15.dp))
                }
            }

            val cols = nodeColumns.coerceIn(1, 3)
            if (running && nodes.isNotEmpty()) {
                LatencySpectrumBar(stats = stats, height = 4.dp)
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    nodes.take(maxVisibleNodes).chunked(cols).forEach { rowItems ->
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            rowItems.forEach { node ->
                                BentoQuickNodeTile(
                                    name = node.name,
                                    badge = groupTag.ifEmpty { "LIVE" },
                                    subtitle = if (node.overridden) "手动锁定" else if (node.selected) "当前活动" else "点击切换",
                                    latencyMs = node.latencyMs,
                                    state = node.state,
                                    active = node.selected,
                                    onClick = {
                                        if (!node.selected) {
                                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                            onSelectNode(node)
                                        }
                                    },
                                    modifier = Modifier.weight(1f),
                                )
                            }
                            repeat(cols - rowItems.size) { Spacer(Modifier.weight(1f)) }
                        }
                    }
                }
            } else if (workspaceProfiles.isNotEmpty()) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    workspaceProfiles.take(maxVisibleNodes).chunked(cols).forEach { rowItems ->
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            rowItems.forEach { p ->
                                val active = p.id == activeProfileId
                                BentoQuickNodeTile(
                                    name = p.remarks.ifBlank { p.id },
                                    badge = shortProtocolBadge(p),
                                    subtitle = shortProfileEndpoint(p),
                                    latencyMs = -1L,
                                    state = "unknown",
                                    active = active,
                                    onClick = {
                                        if (!active) {
                                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                            onSelectWorkspaceProfile(p.id)
                                        }
                                    },
                                    modifier = Modifier.weight(1f),
                                )
                            }
                            repeat(cols - rowItems.size) { Spacer(Modifier.weight(1f)) }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun BentoQuickNodeTile(
    name: String,
    badge: String,
    subtitle: String,
    latencyMs: Long,
    state: String,
    active: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val primary = MaterialTheme.colorScheme.primary
    val interaction = remember { MutableInteractionSource() }
    val reducedMotion = isReducedMotionEnabled()
    val tileBg = animateColorAsState(
        targetValue = if (active) primary.copy(alpha = if (ext.isDark) 0.18f else 0.08f) else ext.wellSurface,
        animationSpec = tween(if (reducedMotion) 0 else 150, easing = NexusStrongEaseOut),
        label = "nodeTileBg",
    ).value
    val borderCol = animateColorAsState(
        targetValue = if (active) primary.copy(alpha = 0.72f) else ext.hairline.copy(alpha = 0f),
        animationSpec = tween(if (reducedMotion) 0 else 150, easing = NexusStrongEaseOut),
        label = "nodeTileBorder",
    ).value
    Surface(
        onClick = onClick,
        interactionSource = interaction,
        shape = RoundedCornerShape(8.dp),
        color = tileBg,
        border = if (active) BorderStroke(1.2.dp, borderCol) else null,
        modifier = modifier.heightIn(min = 58.dp).tactilePress(interaction, pressedScale = 0.97f),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(7.dp)
                        .background(if (active) ext.success else ext.muted.copy(alpha = 0.55f), CircleShape),
                )
                Text(
                    text = name,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = if (active) FontWeight.Bold else FontWeight.SemiBold,
                    color = if (active) primary else MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                if (latencyMs >= 0L || state == "timeout") {
                    LatencyReadoutText(latencyMs = latencyMs, state = state)
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text(
                    text = badge,
                    style = NexusNumericStyles.monoBadge,
                    fontWeight = FontWeight.Bold,
                    color = if (active) primary else ext.muted,
                    maxLines = 1,
                )
                Text(
                    text = subtitle,
                    style = NexusNumericStyles.monoBadge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
            }
        }
    }
}
