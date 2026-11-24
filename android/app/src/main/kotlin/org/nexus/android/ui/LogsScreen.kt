package org.nexus.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import org.nexus.android.R
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

private val LOG_LEVELS = listOf("trace", "error", "warn", "info", "debug")
private val LOG_TIMESTAMP_REGEX = Regex("^(\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,3})?)\\s+(.*)$")
private val LOG_LEVEL_TAG_REGEX = Regex("^\\[(error|warn|warning|info|debug|trace)]\\s*(.*)$", RegexOption.IGNORE_CASE)

@Composable
fun LogsScreen(
    logs: List<UiLogLine>,
    logSearch: String,
    onLogSearchChange: (String) -> Unit,
    logLevel: String,
    onLogLevelChange: (String) -> Unit,
    onRefreshLogs: () -> Unit,
    onShareLogs: (String) -> Unit,
    contentPadding: PaddingValues,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    var pauseAutoScroll by rememberSaveable { mutableStateOf(false) }
    var levelMenuExpanded by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()

    val visibleLogs = remember(logs, logSearch, logLevel) {
        val q = logSearch.trim().lowercase()
        val lvlFilter = if (logLevel == "trace") "" else "[$logLevel]"
        logs.filter { entry ->
            val lower = entry.text.lowercase()
            val levelMatches = lvlFilter.isEmpty() ||
                lower.contains(lvlFilter) ||
                (logLevel == "warn" && lower.contains("[warning]"))
            levelMatches && (q.isEmpty() || lower.contains(q))
        }
    }

    LaunchedEffect(visibleLogs.size, pauseAutoScroll) {
        if (!pauseAutoScroll && visibleLogs.isNotEmpty()) {
            listState.animateScrollToItem(visibleLogs.lastIndex)
        }
    }

    val layoutDirection = LocalLayoutDirection.current
    val startPad = contentPadding.calculateStartPadding(layoutDirection) + 16.dp
    val endPad = contentPadding.calculateEndPadding(layoutDirection) + 16.dp
    val topPad = contentPadding.calculateTopPadding()
    val bottomPad = contentPadding.calculateBottomPadding()

    Column(
        modifier = modifier
            .fillMaxSize()
            .consumeWindowInsets(contentPadding)
            .imePadding()
            .padding(start = startPad, end = endPad, top = topPad),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedTextField(
                value = logSearch,
                onValueChange = onLogSearchChange,
                modifier = Modifier.weight(1f),
                singleLine = true,
                shape = RoundedCornerShape(999.dp),
                placeholder = { Text("搜索日志...") },
                leadingIcon = {
                    Icon(
                        painter = painterResource(R.drawable.ic_search),
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                },
                trailingIcon = {
                    if (logSearch.isNotEmpty()) {
                        IconButton(onClick = { onLogSearchChange("") }) {
                            Icon(
                                painter = painterResource(R.drawable.ic_close),
                                contentDescription = "清除",
                                modifier = Modifier.size(18.dp),
                            )
                        }
                    }
                },
            )
            FilledTonalIconButton(
                onClick = { pauseAutoScroll = !pauseAutoScroll },
                colors = if (pauseAutoScroll) {
                    IconButtonDefaults.filledTonalIconButtonColors(
                        containerColor = ext.warningContainer,
                        contentColor = ext.warning,
                    )
                } else {
                    IconButtonDefaults.filledTonalIconButtonColors()
                },
            ) {
                Icon(
                    painter = painterResource(if (pauseAutoScroll) R.drawable.ic_play else R.drawable.ic_pause),
                    contentDescription = if (pauseAutoScroll) "恢复自动跟随" else "暂停自动跟随",
                    modifier = Modifier.size(18.dp),
                )
            }
            FilledTonalIconButton(onClick = onRefreshLogs) {
                Icon(
                    painter = painterResource(R.drawable.ic_refresh),
                    contentDescription = "刷新",
                    modifier = Modifier.size(20.dp),
                )
            }
            FilledTonalIconButton(
                enabled = visibleLogs.isNotEmpty(),
                onClick = { onShareLogs(visibleLogs.joinToString("\n") { it.text }) },
            ) {
                Icon(
                    painter = painterResource(R.drawable.ic_share),
                    contentDescription = "导出",
                    modifier = Modifier.size(20.dp),
                )
            }
        }

        if (visibleLogs.isEmpty()) {
            EmptyStateCard(
                title = "暂无日志",
                subtitle = if (logLevel == "trace") "连接后将在此显示实时运行日志。" else "当前级别筛选下暂无日志。",
                iconRes = R.drawable.ic_nav_logs,
                actionLabel = if (logLevel == "trace") "刷新" else "显示全部级别",
                onAction = { if (logLevel == "trace") onRefreshLogs() else onLogLevelChange("trace") },
            )
        } else {
            Surface(
                modifier = Modifier.weight(1f).fillMaxWidth(),
                shape = RoundedCornerShape(topStart = 20.dp, topEnd = 20.dp),
                color = ext.wellSurface,
                border = BorderStroke(1.dp, ext.hairline),
            ) {
                Column(modifier = Modifier.fillMaxSize()) {
                    // Terminal stream header bar with count, compact level dropdown pill & auto-scroll toggle
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(MaterialTheme.colorScheme.surfaceContainerHigh.copy(alpha = 0.45f))
                            .padding(horizontal = 12.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(7.dp),
                    ) {
                        Text(
                            text = "实时日志流",
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            softWrap = false,
                        )
                        StatusPill(
                            text = "${visibleLogs.size} 条",
                            containerColor = ext.insetSurface,
                            contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                            mono = true,
                        )
                        Spacer(Modifier.weight(1f))
                        LogLevelDropdownPill(
                            selectedLevel = logLevel,
                            expanded = levelMenuExpanded,
                            onExpandedChange = { levelMenuExpanded = it },
                            onSelectLevel = { lvl ->
                                levelMenuExpanded = false
                                onLogLevelChange(lvl)
                            },
                        )
                        Surface(
                            onClick = { pauseAutoScroll = !pauseAutoScroll },
                            shape = RoundedCornerShape(999.dp),
                            color = if (pauseAutoScroll) ext.warningContainer else ext.successContainer,
                            border = BorderStroke(
                                1.dp,
                                (if (pauseAutoScroll) ext.warning else ext.success).copy(alpha = 0.42f),
                            ),
                        ) {
                            Row(
                                modifier = Modifier.padding(horizontal = 9.dp, vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(5.dp),
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(6.dp)
                                        .background(
                                            color = if (pauseAutoScroll) ext.warning else ext.success,
                                            shape = CircleShape,
                                        ),
                                )
                                Text(
                                    text = if (pauseAutoScroll) "已暂停" else "跟随",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = if (pauseAutoScroll) ext.warning else ext.success,
                                    maxLines = 1,
                                    softWrap = false,
                                )
                            }
                        }
                    }
                    HorizontalDivider(color = ext.hairline)

                    LazyColumn(
                        state = listState,
                        modifier = Modifier.weight(1f).fillMaxWidth(),
                        contentPadding = PaddingValues(
                            start = 10.dp,
                            end = 10.dp,
                            top = 8.dp,
                            bottom = bottomPad + 12.dp,
                        ),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        items(
                            items = visibleLogs,
                            key = { it.seq },
                            contentType = { "log_line" },
                        ) { entry ->
                            LogLineRow(line = entry.text)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun LogLevelDropdownPill(
    selectedLevel: String,
    expanded: Boolean,
    onExpandedChange: (Boolean) -> Unit,
    onSelectLevel: (String) -> Unit,
) {
    val ext = NexusTheme.colors
    val (pillBg, pillFg, pillText) = when (selectedLevel) {
        "error" -> Triple(ext.dangerContainer, ext.danger, "ERR ▾")
        "warn" -> Triple(ext.warningContainer, ext.warning, "WRN ▾")
        "info" -> Triple(ext.telemetryDownloadContainer, ext.telemetryDownload, "INF ▾")
        "debug" -> Triple(ext.insetSurface, MaterialTheme.colorScheme.onSurfaceVariant, "DBG ▾")
        else -> Triple(ext.insetSurface, MaterialTheme.colorScheme.onSurface, "级别: 全部 ▾")
    }

    Box {
        Surface(
            onClick = { onExpandedChange(!expanded) },
            shape = RoundedCornerShape(999.dp),
            color = pillBg,
            border = BorderStroke(
                width = 1.dp,
                color = if (selectedLevel == "trace") ext.hairline else pillFg.copy(alpha = 0.45f),
            ),
        ) {
            Text(
                text = pillText,
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.SemiBold,
                color = pillFg,
                maxLines = 1,
                softWrap = false,
                modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
            )
        }
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { onExpandedChange(false) },
            shape = RoundedCornerShape(14.dp),
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
        ) {
            LOG_LEVELS.forEach { lvl ->
                val isSelected = selectedLevel == lvl
                val dotColor = when (lvl) {
                    "error" -> ext.danger
                    "warn" -> ext.warning
                    "info" -> ext.telemetryDownload
                    "debug" -> ext.muted
                    else -> MaterialTheme.colorScheme.primary
                }
                val itemLabel = if (lvl == "trace") "全部级别" else lvl.uppercase()
                DropdownMenuItem(
                    text = {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Box(Modifier.size(7.dp).background(dotColor, CircleShape))
                            Text(
                                text = itemLabel,
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium,
                                color = if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                            )
                        }
                    },
                    trailingIcon = if (isSelected) {
                        {
                            Icon(
                                painter = painterResource(R.drawable.ic_check),
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(16.dp),
                            )
                        }
                    } else null,
                    onClick = { onSelectLevel(lvl) },
                )
            }
        }
    }
}

private data class ParsedLogEntry(
    val level: String,
    val timestamp: String,
    val message: String,
)

private fun parseLogEntry(raw: String): ParsedLogEntry {
    var rest = raw.trim()
    var timestamp = ""
    LOG_TIMESTAMP_REGEX.matchEntire(rest)?.let { m ->
        timestamp = m.groupValues[1]
        rest = m.groupValues[2].trimStart()
    }
    var level = "LOG"
    LOG_LEVEL_TAG_REGEX.matchEntire(rest)?.let { m ->
        level = when (m.groupValues[1].lowercase()) {
            "error" -> "ERR"
            "warn", "warning" -> "WRN"
            "info" -> "INF"
            "debug", "trace" -> "DBG"
            else -> "LOG"
        }
        rest = m.groupValues[2]
    }
    if (timestamp.isEmpty()) {
        LOG_TIMESTAMP_REGEX.matchEntire(rest)?.let { m ->
            timestamp = m.groupValues[1]
            rest = m.groupValues[2].trimStart()
        }
    }
    return ParsedLogEntry(level = level, timestamp = timestamp, message = rest.ifEmpty { raw })
}

@Composable
private fun LogLineRow(line: String) {
    val ext = NexusTheme.colors
    val parsed = remember(line) { parseLogEntry(line) }
    val (badgeBg, badgeFg, rowTint) = when (parsed.level) {
        "ERR" -> Triple(ext.dangerContainer, ext.danger, ext.dangerContainer.copy(alpha = 0.28f))
        "WRN" -> Triple(ext.warningContainer, ext.warning, ext.warningContainer.copy(alpha = 0.16f))
        "INF" -> Triple(ext.telemetryDownloadContainer, ext.telemetryDownload, Color.Transparent)
        "DBG" -> Triple(ext.mutedContainer, ext.muted, Color.Transparent)
        else -> Triple(ext.mutedContainer, ext.muted, Color.Transparent)
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(rowTint, RoundedCornerShape(8.dp))
            .padding(horizontal = 6.dp, vertical = 5.dp),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Surface(
            modifier = Modifier.width(40.dp),
            shape = RoundedCornerShape(6.dp),
            color = badgeBg,
            border = BorderStroke(1.dp, badgeFg.copy(alpha = 0.30f)),
        ) {
            Text(
                text = parsed.level,
                style = NexusNumericStyles.monoBadge,
                color = badgeFg,
                textAlign = TextAlign.Center,
                maxLines = 1,
                softWrap = false,
                modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
            )
        }
        if (parsed.timestamp.isNotEmpty()) {
            Text(
                text = parsed.timestamp,
                style = NexusNumericStyles.monoBadge,
                color = ext.muted,
                maxLines = 1,
                softWrap = false,
                modifier = Modifier.padding(top = 2.dp),
            )
        }
        Text(
            text = parsed.message,
            style = NexusNumericStyles.codeBlock,
            color = if (parsed.level == "ERR") ext.danger else MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f),
        )
    }
}
