package org.nexus.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.nexus.android.R
import org.nexus.android.ui.theme.NexusTheme

@OptIn(ExperimentalLayoutApi::class)
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
    running: Boolean = false,
    sseStreaming: Boolean = false,
    coreLogLevel: String = "info",
    onSetCoreLogLevel: (suspend (String) -> Boolean)? = null,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val scope = rememberCoroutineScope()
    var pauseAutoScroll by rememberSaveable { mutableStateOf(false) }
    var selectedDomain by rememberSaveable { mutableStateOf("all") }
    var levelMenuExpanded by remember { mutableStateOf(false) }
    var coreLevelMenuExpanded by remember { mutableStateOf(false) }
    var activeCoreLevel by rememberSaveable(coreLogLevel) { mutableStateOf(coreLogLevel) }
    var coreLevelNote by remember { mutableStateOf("") }
    val listState = rememberLazyListState()

    val visibleLogs = remember(logs, logSearch, logLevel, selectedDomain) {
        val q = logSearch.trim().lowercase()
        val lvlFilter = if (logLevel == "trace") "" else "[$logLevel]"
        logs.filter { entry ->
            val lower = entry.text.lowercase()
            val levelMatches = lvlFilter.isEmpty() ||
                lower.contains(lvlFilter) ||
                (logLevel == "warn" && lower.contains("[warning]"))
            val domainMatches = selectedDomain == "all" || parseLogDomain(entry.text) == selectedDomain
            levelMatches && domainMatches && (q.isEmpty() || lower.contains(q))
        }
    }

    LaunchedEffect(visibleLogs.size, pauseAutoScroll) {
        if (!pauseAutoScroll && visibleLogs.isNotEmpty()) {
            listState.scrollToItem(visibleLogs.lastIndex)
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

        LogDomainFilterRow(
            selectedDomain = selectedDomain,
            onSelectDomain = { selectedDomain = it },
        )

        if (coreLevelNote.isNotEmpty()) {
            Surface(
                shape = RoundedCornerShape(10.dp),
                color = ext.wellSurface,
                border = BorderStroke(1.dp, ext.hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text = coreLevelNote,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                )
            }
        }

        if (visibleLogs.isEmpty()) {
            val hasFilter = logLevel != "trace" || selectedDomain != "all" || logSearch.isNotEmpty()
            EmptyStateCard(
                title = "暂无日志",
                subtitle = if (!hasFilter) "连接后将在此显示实时运行日志。" else "当前筛选条件下暂无日志。",
                iconRes = R.drawable.ic_nav_logs,
                actionLabel = if (!hasFilter) "刷新" else "重置筛选",
                onAction = {
                    if (!hasFilter) onRefreshLogs()
                    else {
                        onLogLevelChange("trace")
                        selectedDomain = "all"
                        onLogSearchChange("")
                    }
                },
            )
        } else {
            Surface(
                modifier = Modifier.weight(1f).fillMaxWidth(),
                shape = RoundedCornerShape(topStart = 16.dp, topEnd = 16.dp),
                color = ext.wellSurface,
                border = BorderStroke(1.dp, ext.hairline),
            ) {
                Column(modifier = Modifier.fillMaxSize()) {
                    FlowRow(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(MaterialTheme.colorScheme.surfaceContainerHigh.copy(alpha = 0.45f))
                            .padding(horizontal = 12.dp, vertical = 6.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                        itemVerticalAlignment = Alignment.CenterVertically,
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                        ) {
                            Text(
                                text = if (sseStreaming) "实时日志流" else "运行日志",
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onSurface,
                                maxLines = 1,
                                softWrap = false,
                            )
                            StatusPill(
                                text = "${visibleLogs.size}",
                                containerColor = ext.insetSurface,
                                contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                                mono = true,
                            )
                        }
                        if (running && onSetCoreLogLevel != null) {
                            CoreLogLevelDropdownPill(
                                currentLevel = activeCoreLevel,
                                expanded = coreLevelMenuExpanded,
                                onExpandedChange = { coreLevelMenuExpanded = it },
                                onSelectLevel = { lvl ->
                                    coreLevelMenuExpanded = false
                                    scope.launch {
                                        val ok = onSetCoreLogLevel(lvl)
                                        if (ok) {
                                            activeCoreLevel = lvl
                                            coreLevelNote = "已动态切换内核日志级别为 ${lvl.uppercase()}"
                                        } else {
                                            coreLevelNote = "内核日志级别切换失败"
                                        }
                                    }
                                },
                            )
                        }
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
                            modifier = Modifier.minimumInteractiveComponentSize(),
                            shape = RoundedCornerShape(999.dp),
                            color = if (pauseAutoScroll) ext.warningContainer else ext.successContainer,
                            border = BorderStroke(
                                1.dp,
                                (if (pauseAutoScroll) ext.warning else ext.success).copy(alpha = 0.42f),
                            ),
                        ) {
                            Row(
                                modifier = Modifier.padding(horizontal = 9.dp, vertical = 5.dp),
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
                                    text = if (pauseAutoScroll) "暂停" else "跟随",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = if (pauseAutoScroll) ext.warning else ext.success,
                                    maxLines = 1,
                                    softWrap = false,
                                )
                            }
                        }
                        if (pauseAutoScroll && visibleLogs.isNotEmpty()) {
                            Surface(
                                onClick = {
                                    pauseAutoScroll = false
                                    scope.launch { listState.scrollToItem(visibleLogs.lastIndex) }
                                },
                                modifier = Modifier.minimumInteractiveComponentSize(),
                                shape = RoundedCornerShape(999.dp),
                                color = MaterialTheme.colorScheme.primaryContainer,
                                border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.45f)),
                            ) {
                                Text(
                                    text = "跳至最新",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                                    maxLines = 1,
                                    softWrap = false,
                                    modifier = Modifier.padding(horizontal = 9.dp, vertical = 5.dp),
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
