package org.nexus.android.ui

import androidx.annotation.DrawableRes
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.FloatingActionButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationDrawerItem
import androidx.compose.material3.NavigationDrawerItemDefaults
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.PermanentDrawerSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.TopAppBarScrollBehavior
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.nexus.android.R
import org.nexus.android.bridge.workspace.AndroidPerAppMode
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

internal enum class NexusTab(val label: String, @param:DrawableRes val iconRes: Int) {
    OVERVIEW("概览", R.drawable.ic_nav_overview),
    GROUPS("策略组", R.drawable.ic_nav_groups),
    CONNECTIONS("连接", R.drawable.ic_nav_connections),
    CONFIG("档案", R.drawable.ic_nav_config),
    LOGS("日志", R.drawable.ic_nav_logs),
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun NexusTopAppBar(
    showSplitTunnel: Boolean,
    perAppMode: AndroidPerAppMode = AndroidPerAppMode.EXCLUDE,
    currentTab: NexusTab,
    windowSizeClass: NexusWindowSizeClass,
    heroState: HeroConnectionState,
    activeProfileName: String,
    dashEditing: Boolean,
    scrollBehavior: TopAppBarScrollBehavior,
    onOpenConfig: () -> Unit,
    onToggleDashEditing: () -> Unit,
    onCloseSplitTunnel: () -> Unit,
) {
    val ext = NexusTheme.colors
    val haptic = LocalHapticFeedback.current
    TopAppBar(
        scrollBehavior = scrollBehavior,
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = MaterialTheme.colorScheme.surface.copy(alpha = 0.92f),
            scrolledContainerColor = MaterialTheme.colorScheme.surfaceContainer,
        ),
        navigationIcon = {
            if (showSplitTunnel) {
                IconButton(onClick = onCloseSplitTunnel) {
                    Icon(
                        painter = painterResource(R.drawable.ic_back),
                        contentDescription = "返回",
                    )
                }
            }
        },
        title = {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (!showSplitTunnel && windowSizeClass != NexusWindowSizeClass.EXPANDED) {
                    NexusPrismMark(modifier = Modifier.size(24.dp))
                }
                Text(
                    text = when {
                        showSplitTunnel -> when (perAppMode) {
                            AndroidPerAppMode.INCLUDE -> "分应用代理"
                            AndroidPerAppMode.EXCLUDE -> "分应用绕过"
                            AndroidPerAppMode.OFF -> "分应用控制"
                        }
                        windowSizeClass == NexusWindowSizeClass.EXPANDED -> currentTab.label
                        else -> "Nexus"
                    },
                    fontWeight = FontWeight.ExtraBold,
                )
                if (!showSplitTunnel && currentTab == NexusTab.OVERVIEW && activeProfileName.isNotEmpty()) {
                    Surface(
                        onClick = onOpenConfig,
                        modifier = Modifier.minimumInteractiveComponentSize(),
                        shape = RoundedCornerShape(999.dp),
                        color = ext.wellSurface,
                        border = BorderStroke(1.dp, ext.hairlineStrong),
                    ) {
                        Text(
                            text = activeProfileName,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
                        )
                    }
                }
            }
        },
        actions = {
            if (!showSplitTunnel) {
                Row(
                    modifier = Modifier.padding(end = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    if (currentTab == NexusTab.OVERVIEW) {
                        val editInteraction = remember { MutableInteractionSource() }
                        Surface(
                            onClick = {
                                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                onToggleDashEditing()
                            },
                            interactionSource = editInteraction,
                            modifier = Modifier
                                .minimumInteractiveComponentSize()
                                .liquidPress(editInteraction, pressedScale = 0.94f),
                            shape = RoundedCornerShape(999.dp),
                            color = if (dashEditing) MaterialTheme.colorScheme.primaryContainer else ext.wellSurface,
                            border = BorderStroke(
                                1.dp,
                                if (dashEditing) MaterialTheme.colorScheme.primary.copy(alpha = 0.55f) else ext.hairlineStrong,
                            ),
                        ) {
                            Text(
                                text = if (dashEditing) "完成" else "自定义",
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                color = if (dashEditing) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                            )
                        }
                    } else {
                        val (pillBg, pillFg, pillLabel) = when (heroState) {
                            HeroConnectionState.CONNECTED -> Triple(ext.successContainer, ext.success, "已连接")
                            HeroConnectionState.STARTING -> Triple(ext.warningContainer, ext.warning, "连接中")
                            HeroConnectionState.DEGRADED -> Triple(ext.warningContainer, ext.warning, "波动")
                            HeroConnectionState.ERROR -> Triple(ext.dangerContainer, ext.danger, "异常")
                            HeroConnectionState.STANDBY -> Triple(ext.mutedContainer, ext.muted, "未连接")
                        }
                        StatusPill(
                            text = pillLabel,
                            containerColor = pillBg,
                            contentColor = pillFg,
                        )
                    }
                }
            }
        },
    )
}

@Composable
internal fun CompactBottomChrome(
    tabs: List<NexusTab>,
    selectedTab: Int,
    onSelectTab: (Int) -> Unit,
) {
    val ext = NexusTheme.colors
    val haptic = LocalHapticFeedback.current
    val scrimBase = MaterialTheme.colorScheme.background
    Column(modifier = Modifier.fillMaxWidth()) {
        HorizontalDivider(
            modifier = Modifier.background(scrimBase),
            color = ext.hairline,
        )
        NavigationBar(
            containerColor = MaterialTheme.colorScheme.surfaceContainer,
        ) {
            tabs.forEachIndexed { idx, tab ->
                NavigationBarItem(
                    selected = selectedTab == idx,
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onSelectTab(idx)
                    },
                    icon = {
                        Icon(
                            painter = painterResource(tab.iconRes),
                            contentDescription = tab.label,
                            modifier = Modifier.size(22.dp),
                        )
                    },
                    label = { Text(tab.label, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                )
            }
        }
    }
}

@Composable
internal fun MediumNavigationRail(
    tabs: List<NexusTab>,
    selectedTab: Int,
    showSplitTunnel: Boolean,
    running: Boolean,
    heroState: HeroConnectionState = if (running) HeroConnectionState.CONNECTED else HeroConnectionState.STANDBY,
    showQuickPower: Boolean = showSplitTunnel || selectedTab != NexusTab.OVERVIEW.ordinal,
    onSelectTab: (Int) -> Unit,
    onStartStop: () -> Unit,
) {
    val ext = NexusTheme.colors
    val haptic = LocalHapticFeedback.current
    val isStarting = heroState == HeroConnectionState.STARTING
    val isLive = heroState == HeroConnectionState.CONNECTED || heroState == HeroConnectionState.DEGRADED
    val (fabContainer, fabContent) = when (heroState) {
        HeroConnectionState.CONNECTED -> ext.successContainer to ext.success
        HeroConnectionState.STARTING, HeroConnectionState.DEGRADED -> ext.warningContainer to ext.warning
        HeroConnectionState.ERROR -> ext.dangerContainer to ext.danger
        HeroConnectionState.STANDBY -> MaterialTheme.colorScheme.primaryContainer to MaterialTheme.colorScheme.onPrimaryContainer
    }

    NavigationRail(
        containerColor = MaterialTheme.colorScheme.surfaceContainer,
        header = if (showQuickPower) {
            {
                FloatingActionButton(
                    onClick = {
                        if (!isStarting) {
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                            onStartStop()
                        }
                    },
                    shape = RoundedCornerShape(16.dp),
                    containerColor = fabContainer,
                    contentColor = fabContent,
                    elevation = FloatingActionButtonDefaults.loweredElevation(defaultElevation = 0.dp),
                    modifier = Modifier.padding(top = 8.dp, bottom = 12.dp),
                ) {
                    if (isStarting) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            strokeWidth = 2.2.dp,
                            color = fabContent,
                        )
                    } else {
                        Icon(
                            painter = painterResource(
                                when {
                                    heroState == HeroConnectionState.ERROR -> R.drawable.ic_refresh
                                    isLive -> R.drawable.ic_stop
                                    else -> R.drawable.ic_play
                                },
                            ),
                            contentDescription = if (isLive) "断开" else "连接",
                            modifier = Modifier.size(20.dp),
                        )
                    }
                }
            }
        } else null,
    ) {
        tabs.forEachIndexed { idx, tab ->
            NavigationRailItem(
                selected = !showSplitTunnel && selectedTab == idx,
                onClick = {
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    onSelectTab(idx)
                },
                icon = {
                    Icon(
                        painter = painterResource(tab.iconRes),
                        contentDescription = tab.label,
                        modifier = Modifier.size(22.dp),
                    )
                },
                label = { Text(tab.label) },
            )
        }
    }
}

@Composable
internal fun ExpandedDrawerContent(
    tabs: List<NexusTab>,
    selectedTab: Int,
    showSplitTunnel: Boolean,
    heroState: HeroConnectionState,
    downloadRateBps: Long,
    uploadRateBps: Long,
    onSelectTab: (Int) -> Unit,
    onStartStop: () -> Unit,
) {
    val ext = NexusTheme.colors
    val running = heroState == HeroConnectionState.CONNECTED || heroState == HeroConnectionState.DEGRADED
    PermanentDrawerSheet(
        modifier = Modifier.width(236.dp),
        drawerContainerColor = MaterialTheme.colorScheme.surfaceContainer,
    ) {
        Column(
            modifier = Modifier.fillMaxHeight().padding(vertical = 12.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(9.dp),
            ) {
                NexusPrismMark(modifier = Modifier.size(24.dp))
                Text(
                    text = "Nexus",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.ExtraBold,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }
            tabs.forEachIndexed { idx, tab ->
                NavigationDrawerItem(
                    label = { Text(tab.label, fontWeight = FontWeight.SemiBold) },
                    selected = !showSplitTunnel && selectedTab == idx,
                    onClick = { onSelectTab(idx) },
                    icon = {
                        Icon(
                            painter = painterResource(tab.iconRes),
                            contentDescription = null,
                            modifier = Modifier.size(20.dp),
                        )
                    },
                    modifier = Modifier.padding(NavigationDrawerItemDefaults.ItemPadding),
                )
            }
            Spacer(Modifier.weight(1f))
            HorizontalDivider(
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
                color = ext.hairline,
            )
            Surface(
                onClick = onStartStop,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 4.dp),
                shape = RoundedCornerShape(12.dp),
                color = ext.wellSurface,
                border = BorderStroke(1.dp, if (running) ext.success.copy(alpha = 0.45f) else ext.hairline),
            ) {
                Column(
                    modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Box(
                            modifier = Modifier
                                .size(8.dp)
                                .background(if (running) ext.success else ext.muted, CircleShape),
                        )
                        Text(
                            text = if (running) "已连接 · 点击断开" else "未连接 · 点击连接",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(
                            text = "↓ ${formatTrafficRate(downloadRateBps)}",
                            style = NexusNumericStyles.monoBadge,
                            color = ext.telemetryDownload,
                            maxLines = 1,
                            softWrap = false,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f),
                        )
                        Text(
                            text = "↑ ${formatTrafficRate(uploadRateBps)}",
                            style = NexusNumericStyles.monoBadge,
                            color = ext.telemetryUpload,
                            maxLines = 1,
                            softWrap = false,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f),
                        )
                    }
                }
            }
        }
    }
}

@Composable
internal fun NexusPrismMark(modifier: Modifier = Modifier) {
    val isDark = NexusTheme.colors.isDark
    Box(
        modifier = modifier.drawWithCache {
            val (w, h) = size.width to size.height
            val apex = Offset(w * 0.50f, h * 0.06f)
            val left = Offset(w * 0.09f, h * 0.78f)
            val right = Offset(w * 0.91f, h * 0.78f)
            val center = Offset(w * 0.50f, h * 0.59f)
            val leftFacet = Path().apply { moveTo(apex.x, apex.y); lineTo(left.x, left.y); lineTo(center.x, center.y); close() }
            val rightFacet = Path().apply { moveTo(apex.x, apex.y); lineTo(center.x, center.y); lineTo(right.x, right.y); close() }
            val baseFacet = Path().apply { moveTo(left.x, left.y); lineTo(center.x, center.y); lineTo(right.x, right.y); lineTo(w * 0.50f, h * 0.96f); close() }
            val ridges = Path().apply { moveTo(apex.x, apex.y); lineTo(center.x, center.y); moveTo(left.x, left.y); lineTo(center.x, center.y); lineTo(right.x, right.y) }
            val glowCenter = Offset(w * 0.50f, h * 0.56f)
            val glowBrush = Brush.radialGradient(
                0.0f to Color(0xFF38BDF8).copy(alpha = if (isDark) 0.42f else 0.24f),
                0.65f to Color(0xFF6366F1).copy(alpha = if (isDark) 0.14f else 0.08f),
                1.0f to Color.Transparent,
                center = glowCenter,
                radius = w * 0.62f,
            )
            val leftBrush = Brush.linearGradient(listOf(Color(0xFF67E8F9), Color(0xFF38BDF8), Color(0xFF3B82F6)), start = apex, end = left)
            val rightBrush = Brush.linearGradient(listOf(Color(0xFF60A5FA), Color(0xFF818CF8), Color(0xFF8B5CF6)), start = apex, end = right)
            val baseBrush = Brush.linearGradient(listOf(Color(0xFF2563EB), Color(0xFF4F46E5)), start = left, end = right)
            val ridgeStroke = Stroke(width = 0.9.dp.toPx(), cap = StrokeCap.Round, join = StrokeJoin.Round)
            val ridgeColor = Color.White.copy(alpha = if (isDark) 0.72f else 0.85f)
            onDrawBehind {
                drawCircle(brush = glowBrush, radius = w * 0.62f, center = glowCenter)
                drawPath(leftFacet, brush = leftBrush)
                drawPath(rightFacet, brush = rightBrush)
                drawPath(baseFacet, brush = baseBrush)
                drawPath(ridges, color = ridgeColor, style = ridgeStroke)
            }
        },
    )
}
