package org.nexus.android.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
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
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.nexus.android.R
import org.nexus.android.bridge.workspace.AndroidHostConfig
import org.nexus.android.bridge.workspace.AndroidHostSection
import org.nexus.android.bridge.workspace.AndroidPerAppMode
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

data class ConnectivityTargetRtt(
    val cfMs: Long = -1L,
    val googleMs: Long = -1L,
    val githubMs: Long = -1L,
    val youtubeMs: Long = -1L,
)

/**
 * Inbound Combination & Connectivity 2x2 Matrix Card (`12dp` single-level Card Console container):
 * - 3-Column independent `Mixed / HTTP / SOCKS5` quick toggle tiles (arbitrary combinations!)
 * - Session/MTU summary + 2x2 Connectivity Probe Matrix (CF / Google / GitHub / YouTube)
 */
@Composable
internal fun TrafficSplitCard(
    running: Boolean,
    downloadBytes: Long,
    uploadBytes: Long,
    excludedCount: Int,
    perAppMode: AndroidPerAppMode = AndroidPerAppMode.EXCLUDE,
    localListen: String = "127.0.0.1:10808",
    tunMtu: Int = 1400,
    connectivityRtt: ConnectivityTargetRtt = ConnectivityTargetRtt(),
    isProbing: Boolean,
    diagnostic: String,
    memoryText: String = "",
    activeSessions: Long = 0L,
    onProbeGroup: () -> Unit,
    onClearCache: () -> Unit,
    onOpenSplitTunnel: () -> Unit,
    onOpenConfig: () -> Unit = {},
    onOpenDiagnostics: (() -> Unit)? = null,
    onOpenConnections: (() -> Unit)? = null,
    hostSection: AndroidHostSection = AndroidHostSection(localListen = localListen, tunMtu = tunMtu),
    onUpdateHostSection: ((AndroidHostSection) -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val haptic = LocalHapticFeedback.current
    val reducedMotion = isReducedMotionEnabled()
    val totalTraffic = formatTrafficBytes((downloadBytes + uploadBytes).coerceAtLeast(0L))
    val perAppSummary = when (perAppMode) {
        AndroidPerAppMode.OFF -> "全局"
        AndroidPerAppMode.EXCLUDE -> if (excludedCount > 0) "绕过${excludedCount}项" else "未排除"
        AndroidPerAppMode.INCLUDE -> "仅代理${excludedCount}项"
    }
    val mixedPort = AndroidHostConfig.parseHostPort(hostSection.localListen)?.second ?: 10808
    val httpPort = AndroidHostConfig.parseHostPort(hostSection.httpListen)?.second ?: 10809
    val socksPort = AndroidHostConfig.parseHostPort(hostSection.socksListen)?.second ?: 10806

    OpticalCard(cornerRadius = 12.dp, modifier = modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "入站组合与连通矩阵",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                Row(
                    modifier = Modifier
                        .minimumInteractiveComponentSize()
                        .clip(RoundedCornerShape(8.dp))
                        .clickable(onClick = onOpenDiagnostics ?: onOpenConfig)
                        .padding(horizontal = 4.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(if (onOpenDiagnostics != null) "诊断" else "端口", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary)
                    Icon(painterResource(R.drawable.ic_chevron_right), null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(15.dp))
                }
            }

            // 3-Column Arbitrary-Combination Local Inbound Toggles (Mixed / HTTP / SOCKS5)
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AndroidInboundProtoTile(
                    title = "Mixed",
                    port = mixedPort,
                    active = hostSection.enableLocalProxy,
                    live = running,
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        if (onUpdateHostSection != null) {
                            onUpdateHostSection(hostSection.copy(enableLocalProxy = !hostSection.enableLocalProxy))
                        } else {
                            onOpenConfig()
                        }
                    },
                    modifier = Modifier.weight(1f),
                )
                AndroidInboundProtoTile(
                    title = "HTTP",
                    port = httpPort,
                    active = hostSection.enableHttp,
                    live = running,
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        if (onUpdateHostSection != null) {
                            onUpdateHostSection(hostSection.copy(enableHttp = !hostSection.enableHttp))
                        } else {
                            onOpenConfig()
                        }
                    },
                    modifier = Modifier.weight(1f),
                )
                AndroidInboundProtoTile(
                    title = "SOCKS",
                    port = socksPort,
                    active = hostSection.enableSocks,
                    live = running,
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        if (onUpdateHostSection != null) {
                            onUpdateHostSection(hostSection.copy(enableSocks = !hostSection.enableSocks))
                        } else {
                            onOpenConfig()
                        }
                    },
                    modifier = Modifier.weight(1f),
                )
            }

            // 2-Column Interface/LAN & Session Footprint Bento Wells
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                InboundBentoWell(
                    label = "网卡与监听范围",
                    value = (if (hostSection.allowLan) "LAN 0.0.0.0" else "本机回环") + " · MTU $tunMtu",
                    mono = false,
                    onClick = onOpenConfig,
                    modifier = Modifier.weight(1f),
                )
                InboundBentoWell(
                    label = "并发与内存",
                    value = "${activeSessions}流 · " + memoryText.ifEmpty { perAppSummary },
                    mono = false,
                    onClick = { onOpenConnections?.invoke() ?: onOpenSplitTunnel() },
                    modifier = Modifier.weight(1f),
                )
            }

            // 2x2 Connectivity Probe Matrix (CF / Google / GitHub / YouTube)
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    ProbeMatrixCell("Cloudflare", "1.1.1.1", if (running) connectivityRtt.cfMs else -1L, onProbeGroup, Modifier.weight(1f))
                    ProbeMatrixCell("Google", "gstatic", if (running) connectivityRtt.googleMs else -1L, onProbeGroup, Modifier.weight(1f))
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    ProbeMatrixCell("GitHub", "github", if (running) connectivityRtt.githubMs else -1L, onProbeGroup, Modifier.weight(1f))
                    ProbeMatrixCell("YouTube", "ytimg", if (running) connectivityRtt.youtubeMs else -1L, onProbeGroup, Modifier.weight(1f))
                }
            }

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                QuickActionWellButton(
                    label = if (isProbing) "测速中…" else "连通测速",
                    enabled = running && !isProbing,
                    onClick = { haptic.performHapticFeedback(HapticFeedbackType.LongPress); onProbeGroup() },
                    modifier = Modifier.weight(1f),
                )
                QuickActionWellButton(
                    label = if (running) "释放缓存" else "累计 $totalTraffic",
                    enabled = running,
                    onClick = { haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove); onClearCache() },
                    modifier = Modifier.weight(1f),
                )
            }

            AnimatedVisibility(
                visible = diagnostic.isNotEmpty(),
                enter = expandVertically(tween(if (reducedMotion) 0 else 160, easing = NexusStrongEaseOut)) + fadeIn(tween(if (reducedMotion) 0 else 160)),
                exit = shrinkVertically(tween(if (reducedMotion) 0 else 120, easing = FastOutSlowInEasing)) + fadeOut(tween(if (reducedMotion) 0 else 120)),
            ) {
                Surface(shape = RoundedCornerShape(8.dp), color = ext.wellSurface, modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = diagnostic,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                    )
                }
            }
        }
    }
}

@Composable
internal fun AndroidInboundProtoTile(
    title: String,
    port: Int,
    active: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    live: Boolean = true,
) {
    val ext = NexusTheme.colors
    val primary = MaterialTheme.colorScheme.primary
    val interaction = remember { MutableInteractionSource() }
    val reducedMotion = isReducedMotionEnabled()
    val bg = animateColorAsState(
        targetValue = when {
            !active -> ext.wellSurface
            live -> ext.successContainer
            else -> primary.copy(alpha = if (ext.isDark) 0.18f else 0.09f)
        },
        animationSpec = tween(if (reducedMotion) 0 else 145, easing = NexusStrongEaseOut),
        label = "protoBg",
    ).value
    val borderCol = animateColorAsState(
        targetValue = when {
            !active -> ext.hairline
            live -> ext.success.copy(alpha = 0.65f)
            else -> primary.copy(alpha = 0.72f)
        },
        animationSpec = tween(if (reducedMotion) 0 else 145, easing = NexusStrongEaseOut),
        label = "protoBorder",
    ).value
    val dotCol = animateColorAsState(
        targetValue = when {
            !active -> ext.muted
            live -> ext.success
            else -> primary
        },
        animationSpec = tween(if (reducedMotion) 0 else 145, easing = NexusStrongEaseOut),
        label = "protoDot",
    ).value

    Surface(
        onClick = onClick,
        interactionSource = interaction,
        shape = RoundedCornerShape(8.dp),
        color = bg,
        border = BorderStroke(1.dp, borderCol),
        modifier = modifier.heightIn(min = 52.dp).tactilePress(interaction, pressedScale = 0.96f),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 7.dp),
            verticalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                Box(modifier = Modifier.size(7.dp).background(dotCol, CircleShape))
                Text(
                    text = title,
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = if (!active) MaterialTheme.colorScheme.onSurface else if (live) ext.success else primary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Text(
                text = when {
                    !active -> "已关闭"
                    live -> ":$port"
                    else -> ":$port · 待命"
                },
                style = NexusNumericStyles.monoBadge,
                fontWeight = FontWeight.Bold,
                color = if (!active) ext.muted else if (live) ext.success else primary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun InboundBentoWell(
    label: String,
    value: String,
    mono: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val interaction = remember { MutableInteractionSource() }
    Surface(
        onClick = onClick,
        interactionSource = interaction,
        shape = RoundedCornerShape(8.dp),
        color = ext.wellSurface,
        modifier = modifier.heightIn(min = 54.dp).tactilePress(interaction, pressedScale = 0.98f),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 7.dp),
            verticalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Icon(painterResource(R.drawable.ic_chevron_right), null, tint = ext.muted, modifier = Modifier.size(13.dp))
            }
            Text(
                text = value,
                style = if (mono) NexusNumericStyles.monoBadge else MaterialTheme.typography.bodySmall,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun ProbeMatrixCell(
    name: String,
    hint: String,
    ms: Long,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val interaction = remember { MutableInteractionSource() }
    val rttColor = when {
        ms <= 0L -> ext.muted
        ms < 90L -> ext.success
        ms < 220L -> MaterialTheme.colorScheme.primary
        else -> ext.warning
    }
    Surface(
        onClick = onClick,
        interactionSource = interaction,
        shape = RoundedCornerShape(8.dp),
        color = ext.wellSurface,
        modifier = modifier.heightIn(min = 50.dp).tactilePress(interaction, pressedScale = 0.98f),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 7.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
                Text(name, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onSurface, maxLines = 1)
                Text(hint, style = NexusNumericStyles.monoBadge, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Text(
                text = if (ms > 0L) "${ms}ms" else "--",
                style = NexusNumericStyles.monoBadge,
                fontWeight = FontWeight.Bold,
                color = rttColor,
                maxLines = 1,
                softWrap = false,
            )
        }
    }
}

@Composable
private fun QuickActionWellButton(
    label: String,
    enabled: Boolean,
    onClick: () -> Unit,
    modifier: Modifier,
) {
    val ext = NexusTheme.colors
    val interaction = remember { MutableInteractionSource() }
    Surface(
        onClick = onClick,
        enabled = enabled,
        interactionSource = interaction,
        shape = RoundedCornerShape(8.dp),
        color = ext.wellSurface,
        modifier = modifier.minimumInteractiveComponentSize().heightIn(min = 44.dp).tactilePress(interaction, pressedScale = 0.97f),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 9.dp),
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = if (enabled) MaterialTheme.colorScheme.primary else ext.muted,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}
