package org.nexus.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import org.nexus.android.R
import org.nexus.android.bridge.workspace.AndroidPerAppMode
import org.nexus.android.bridge.workspace.AndroidRunMode
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

/**
 * Signature Move #1 — Live Route Transit Strip (`入口 → 路由 → 出口 → 实时`):
 * - Single flat matte `OpticalCard(16.dp)` with zero nested bordered cards
 * - Compact phones (`<600dp`) or `fontScale >= 1.5f` render a `2×2` grid (`minHeight 54.dp` per hop)
 * - 674dp Foldable & `>=840dp` Tablet render a full-width 4-hop horizontal pipeline with static
 *   directional chevrons tinted Signal Emerald when live (0ms, zero infinite animations)
 */
@Composable
internal fun RouteTransitStrip(
    running: Boolean,
    runMode: AndroidRunMode,
    perAppMode: AndroidPerAppMode,
    excludedCount: Int,
    bypassLan: Boolean,
    outboundMode: String,
    routingProfileName: String,
    fakeIpEnabled: Boolean,
    activeProfileName: String,
    activeExit: ActiveExitSummary,
    downloadRateBps: Long,
    uploadRateBps: Long,
    activeSessions: Long,
    windowSizeClass: NexusWindowSizeClass,
    onOpenSplitTunnel: () -> Unit,
    onOpenRouting: () -> Unit,
    onOpenGroups: () -> Unit,
    onOpenConnections: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val haptic = LocalHapticFeedback.current
    val fontScale = LocalDensity.current.fontScale
    val useGrid = windowSizeClass == NexusWindowSizeClass.COMPACT || fontScale >= 1.5f

    val ingressTitle = if (runMode == AndroidRunMode.VPN) "VPN · TUN" else "本地代理"
    val ingressSub = when {
        perAppMode == AndroidPerAppMode.INCLUDE -> "仅代理 $excludedCount 应用"
        perAppMode == AndroidPerAppMode.EXCLUDE && excludedCount > 0 -> "绕过 $excludedCount 应用"
        bypassLan -> "绕过局域网"
        else -> "全局接管"
    }

    val routeTitle = when (outboundMode) {
        "global" -> "全局模式"
        "direct" -> "直连模式"
        else -> "规则模式"
    }
    val routeSub = when {
        outboundMode != "rule" && fakeIpEnabled -> "FakeIP"
        fakeIpEnabled -> "FakeIP · ${routingProfileName.ifEmpty { "默认" }}"
        else -> routingProfileName.ifEmpty { "标准解析" }
    }

    val isDirectMode = running && outboundMode == "direct"
    val exitTitle = when {
        isDirectMode -> "直连出站"
        running && activeExit.memberName.isNotEmpty() -> activeExit.memberName
        activeProfileName.isNotEmpty() -> activeProfileName
        else -> "未选择"
    }
    val isTimeout = isLatencyTimeout(activeExit.latencyMs, activeExit.state)
    val (exitSub, exitSubColor) = when {
        !running -> "待连接" to MaterialTheme.colorScheme.onSurfaceVariant
        isDirectMode -> "绕过代理" to ext.success
        isTimeout -> "超时" to ext.danger
        activeExit.latencyMs > 0L -> {
            val fg = when {
                activeExit.latencyMs < 80L -> ext.success
                activeExit.latencyMs < 180L -> ext.warning
                activeExit.latencyMs < 350L -> ext.slow
                else -> ext.danger
            }
            "${activeExit.latencyMs} ms" to fg
        }
        else -> "未测速" to MaterialTheme.colorScheme.onSurfaceVariant
    }

    val rateTitle = if (running) "↓ ${formatTrafficRate(downloadRateBps)}" else "待连接"
    val rateSub = when {
        !running -> "$activeSessions 连接"
        useGrid -> "↑ ${formatTrafficRate(uploadRateBps)} · $activeSessions 连接"
        else -> "↑${formatTrafficRate(uploadRateBps)} · ${activeSessions}连接"
    }

    val connectorTint = if (running) ext.success else ext.hairlineStrong

    OpticalCard(
        modifier = modifier.fillMaxWidth(),
        cornerRadius = 16.dp,
        borderColor = if (running) ext.success.copy(alpha = 0.28f) else ext.hairline,
    ) {
        if (useGrid) {
            Column(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    TransitHopCell(
                        stepTag = "1 入口",
                        headline = ingressTitle,
                        subline = ingressSub,
                        headlineColor = MaterialTheme.colorScheme.onSurface,
                        sublineColor = MaterialTheme.colorScheme.onSurfaceVariant,
                        onClick = { haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove); onOpenSplitTunnel() },
                        modifier = Modifier.weight(1f).fillMaxHeight(),
                    )
                    Box(Modifier.width(1.dp).fillMaxHeight().background(ext.hairline))
                    TransitHopCell(
                        stepTag = "2 路由",
                        headline = routeTitle,
                        subline = routeSub,
                        headlineColor = MaterialTheme.colorScheme.primary,
                        sublineColor = MaterialTheme.colorScheme.onSurfaceVariant,
                        onClick = { haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove); onOpenRouting() },
                        modifier = Modifier.weight(1f).fillMaxHeight(),
                    )
                }
                HorizontalDivider(color = ext.hairline)
                Row(
                    modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    TransitHopCell(
                        stepTag = "3 出口",
                        headline = exitTitle,
                        subline = exitSub,
                        headlineColor = MaterialTheme.colorScheme.onSurface,
                        sublineColor = exitSubColor,
                        leadingDotColor = if (running) ext.success else ext.muted,
                        monoSubline = running && !isDirectMode && activeExit.latencyMs > 0L,
                        onClick = { haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove); onOpenGroups() },
                        modifier = Modifier.weight(1f).fillMaxHeight(),
                    )
                    Box(Modifier.width(1.dp).fillMaxHeight().background(ext.hairline))
                    TransitHopCell(
                        stepTag = "4 实时",
                        headline = rateTitle,
                        subline = rateSub,
                        headlineColor = if (running) ext.telemetryDownload else MaterialTheme.colorScheme.onSurfaceVariant,
                        sublineColor = MaterialTheme.colorScheme.onSurfaceVariant,
                        monoHeadline = running,
                        monoSubline = true,
                        onClick = { haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove); onOpenConnections() },
                        modifier = Modifier.weight(1f).fillMaxHeight(),
                    )
                }
            }
        } else {
            Row(
                modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                TransitHopCell(
                    stepTag = "入口",
                    headline = ingressTitle,
                    subline = ingressSub,
                    headlineColor = MaterialTheme.colorScheme.onSurface,
                    sublineColor = MaterialTheme.colorScheme.onSurfaceVariant,
                    horizontalPadding = 10.dp,
                    onClick = { haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove); onOpenSplitTunnel() },
                    modifier = Modifier.weight(0.90f).fillMaxHeight(),
                )
                TransitArrowConnector(tint = connectorTint)
                TransitHopCell(
                    stepTag = "路由",
                    headline = routeTitle,
                    subline = routeSub,
                    headlineColor = MaterialTheme.colorScheme.primary,
                    sublineColor = MaterialTheme.colorScheme.onSurfaceVariant,
                    horizontalPadding = 10.dp,
                    onClick = { haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove); onOpenRouting() },
                    modifier = Modifier.weight(0.95f).fillMaxHeight(),
                )
                TransitArrowConnector(tint = connectorTint)
                TransitHopCell(
                    stepTag = "出口",
                    headline = exitTitle,
                    subline = exitSub,
                    headlineColor = MaterialTheme.colorScheme.onSurface,
                    sublineColor = exitSubColor,
                    leadingDotColor = if (running) ext.success else ext.muted,
                    monoSubline = running && !isDirectMode && activeExit.latencyMs > 0L,
                    horizontalPadding = 10.dp,
                    onClick = { haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove); onOpenGroups() },
                    modifier = Modifier.weight(1.05f).fillMaxHeight(),
                )
                TransitArrowConnector(tint = connectorTint)
                TransitHopCell(
                    stepTag = "实时",
                    headline = rateTitle,
                    subline = rateSub,
                    headlineColor = if (running) ext.telemetryDownload else MaterialTheme.colorScheme.onSurfaceVariant,
                    sublineColor = MaterialTheme.colorScheme.onSurfaceVariant,
                    monoHeadline = running,
                    monoSubline = true,
                    horizontalPadding = 10.dp,
                    onClick = { haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove); onOpenConnections() },
                    modifier = Modifier.weight(1.30f).fillMaxHeight(),
                )
            }
        }
    }
}

@Composable
private fun TransitArrowConnector(tint: Color) {
    Box(
        modifier = Modifier.padding(horizontal = 2.dp),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            painter = painterResource(R.drawable.ic_chevron_right),
            contentDescription = null,
            tint = tint,
            modifier = Modifier.size(14.dp),
        )
    }
}

@Composable
private fun TransitHopCell(
    stepTag: String,
    headline: String,
    subline: String,
    headlineColor: Color,
    sublineColor: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    leadingDotColor: Color? = null,
    monoHeadline: Boolean = false,
    monoSubline: Boolean = false,
    horizontalPadding: Dp = 12.dp,
) {
    Column(
        modifier = modifier
            .heightIn(min = 56.dp)
            .clickable(onClick = onClick)
            .padding(horizontal = horizontalPadding, vertical = 9.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(
            text = stepTag,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(5.dp),
        ) {
            if (leadingDotColor != null) {
                Box(
                    modifier = Modifier
                        .size(7.dp)
                        .background(leadingDotColor, CircleShape),
                )
            }
            Text(
                text = headline,
                style = if (monoHeadline) NexusNumericStyles.rateReadout else MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                color = headlineColor,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Text(
            text = subline,
            style = if (monoSubline) NexusNumericStyles.monoBadge else MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Medium,
            color = sublineColor,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}
