package org.nexus.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.grid.rememberLazyGridState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
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
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.nexus.android.R
import org.nexus.android.bridge.ipc.OutboundGroupSnapshot
import org.nexus.android.bridge.ipc.OutboundMemberSnapshot
import org.nexus.android.bridge.ipc.OutboundProbeResult
import org.nexus.android.ui.theme.NexusTheme

@Composable
fun GroupsScreen(
    onFetchGroups: suspend () -> List<OutboundGroupSnapshot>,
    onSelectMember: suspend (group: String, member: String) -> Boolean,
    onResetAuto: suspend (group: String) -> Boolean,
    onProbeGroup: suspend (group: String) -> Boolean,
    onProbeOutbound: (suspend (outboundTag: String) -> OutboundProbeResult)? = null,
    windowSizeClass: NexusWindowSizeClass,
    contentPadding: PaddingValues,
    running: Boolean = true,
    onOpenOverview: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val haptic = LocalHapticFeedback.current
    val layoutDirection = LocalLayoutDirection.current
    // Hoisted scroll states above conditional branches to preserve position across empty/filter toggles.
    val railListState = rememberLazyListState()
    val memberGridState = rememberLazyGridState()

    var groups by remember { mutableStateOf<List<OutboundGroupSnapshot>>(emptyList()) }
    var selectedTag by rememberSaveable { mutableStateOf("") }
    var searchQuery by rememberSaveable { mutableStateOf("") }
    var sortMode by rememberSaveable { mutableStateOf(GROUPS_SORT_DEFAULT) }
    var hideTimeout by rememberSaveable { mutableStateOf(false) }
    var isProbing by remember { mutableStateOf(false) }
    var probingMembers by remember { mutableStateOf<Set<String>>(emptySet()) }
    var feedback by remember { mutableStateOf("") }

    suspend fun reload() {
        val loaded = onFetchGroups()
        groups = loaded
        if (selectedTag.isEmpty() || loaded.none { it.tag == selectedTag }) {
            selectedTag = loaded.firstOrNull()?.tag.orEmpty()
        }
    }

    LaunchedEffect(Unit) { reload() }

    val activeGroup = groups.firstOrNull { it.tag == selectedTag }
    val filteredMembers = remember(activeGroup, searchQuery, sortMode, hideTimeout) {
        val raw = activeGroup?.members.orEmpty()
        val q = searchQuery.trim().lowercase()
        val filtered = raw.filter { m ->
            val isTimeout = m.state.equals("timeout", ignoreCase = true) ||
                m.state.equals("unreachable", ignoreCase = true) ||
                m.latencyMs == 0L
            (!hideTimeout || !isTimeout) && (q.isEmpty() || m.name.lowercase().contains(q))
        }
        when (sortMode) {
            GROUPS_SORT_LATENCY -> filtered.sortedWith(
                compareBy<OutboundMemberSnapshot> {
                    if (it.latencyMs > 0L) it.latencyMs else Long.MAX_VALUE
                }.thenBy { it.name.lowercase() },
            )
            else -> filtered
        }
    }

    val isExpanded = windowSizeClass == NexusWindowSizeClass.EXPANDED
    val startPad = contentPadding.calculateStartPadding(layoutDirection) + 16.dp
    val endPad = contentPadding.calculateEndPadding(layoutDirection) + 16.dp
    val topPad = contentPadding.calculateTopPadding()
    val bottomPad = contentPadding.calculateBottomPadding()

    if (groups.isEmpty()) {
        val openOverview = if (!running) onOpenOverview else null
        Box(
            modifier = modifier
                .fillMaxSize()
                .consumeWindowInsets(contentPadding)
                .padding(top = topPad, bottom = bottomPad, start = startPad, end = endPad),
        ) {
            EmptyStateCard(
                title = if (openOverview != null) "尚未连接" else "暂无策略组",
                subtitle = if (openOverview != null) {
                    "开启代理连接后，即可在此搜索、测速并切换节点。"
                } else {
                    "连接后可在此搜索、测速并切换节点。"
                },
                iconRes = R.drawable.ic_nav_groups,
                actionLabel = if (openOverview != null) "前往连接" else "刷新",
                onAction = {
                    if (openOverview != null) openOverview() else scope.launch { reload() }
                },
            )
        }
        return
    }

    Box(
        modifier = modifier
            .fillMaxSize()
            .consumeWindowInsets(contentPadding)
            .imePadding(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxSize()
                .padding(start = startPad, end = endPad),
            horizontalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            if (isExpanded) {
                LazyColumn(
                    state = railListState,
                    modifier = Modifier.width(248.dp).fillMaxHeight(),
                    contentPadding = PaddingValues(top = topPad, bottom = bottomPad),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    item(key = "rail_header", contentType = "header") {
                        Text(
                            text = "策略组 (${groups.size})",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 4.dp, vertical = 4.dp),
                        )
                    }
                    items(items = groups, key = { it.tag }, contentType = { "group_rail_item" }) { group ->
                        GroupRailCard(
                            group = group,
                            selected = group.tag == selectedTag,
                            onClick = {
                                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                selectedTag = group.tag
                            },
                        )
                    }
                }
            }

            Column(
                modifier = Modifier.weight(1f).fillMaxHeight().padding(top = topPad),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                if (!isExpanded) {
                    GroupChipRow(
                        groups = groups,
                        selectedTag = selectedTag,
                        onSelectTag = { selectedTag = it },
                    )
                }

                if (activeGroup != null) {
                    GroupSummaryStrip(
                        group = activeGroup,
                        isProbing = isProbing,
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    OutlinedTextField(
                        value = searchQuery,
                        onValueChange = { searchQuery = it },
                        placeholder = {
                            Text(
                                text = "搜索节点...",
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        },
                        shape = RoundedCornerShape(999.dp),
                        leadingIcon = {
                            Icon(
                                painter = painterResource(R.drawable.ic_search),
                                contentDescription = null,
                                modifier = Modifier.size(18.dp),
                            )
                        },
                        trailingIcon = {
                            if (searchQuery.isNotEmpty()) {
                                IconButton(onClick = { searchQuery = "" }) {
                                    Icon(
                                        painter = painterResource(R.drawable.ic_close),
                                        contentDescription = "清除",
                                        modifier = Modifier.size(18.dp),
                                    )
                                }
                            }
                        },
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                    )
                    FilledTonalIconButton(onClick = { scope.launch { reload() } }) {
                        Icon(
                            painter = painterResource(R.drawable.ic_refresh),
                            contentDescription = "刷新",
                            modifier = Modifier.size(20.dp),
                        )
                    }
                }

                GroupFilterToolbar(
                    sortMode = sortMode,
                    hideTimeout = hideTimeout,
                    showResetAuto = activeGroup?.manualOverride == true,
                    onSortChange = { sortMode = it },
                    onToggleHideTimeout = { hideTimeout = !hideTimeout },
                    onResetAuto = {
                        val tag = activeGroup?.tag ?: return@GroupFilterToolbar
                        scope.launch {
                            val ok = onResetAuto(tag)
                            feedback = if (ok) "已恢复自动选优" else "恢复失败"
                            reload()
                        }
                    },
                )

                if (feedback.isNotEmpty()) {
                    val ext = NexusTheme.colors
                    Surface(
                        shape = RoundedCornerShape(10.dp),
                        color = ext.wellSurface,
                        border = BorderStroke(1.dp, ext.hairline),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(
                            text = feedback,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 7.dp),
                        )
                    }
                }

                if (filteredMembers.isEmpty()) {
                    EmptyStateCard(
                        title = "未匹配到节点",
                        subtitle = if (searchQuery.isNotEmpty() || hideTimeout) {
                            "尝试清空搜索词或关闭「隐藏超时」过滤。"
                        } else {
                            "当前策略组 ${activeGroup?.tag.orEmpty()} 尚无出站节点。"
                        },
                        iconRes = R.drawable.ic_nav_groups,
                        actionLabel = if (searchQuery.isNotEmpty() || hideTimeout) "重置过滤" else null,
                        onAction = if (searchQuery.isNotEmpty() || hideTimeout) {
                            {
                                searchQuery = ""
                                hideTimeout = false
                            }
                        } else null,
                    )
                } else {
                    val gridCells = when (windowSizeClass) {
                        NexusWindowSizeClass.COMPACT -> GridCells.Fixed(1)
                        NexusWindowSizeClass.MEDIUM -> GridCells.Fixed(2)
                        NexusWindowSizeClass.EXPANDED -> GridCells.Adaptive(minSize = 240.dp)
                    }
                    LazyVerticalGrid(
                        state = memberGridState,
                        columns = gridCells,
                        modifier = Modifier.weight(1f).fillMaxWidth(),
                        contentPadding = PaddingValues(bottom = bottomPad + 86.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        items(
                            items = filteredMembers,
                            key = { "${activeGroup?.tag.orEmpty()}:${it.name}" },
                            contentType = { "member_card" },
                        ) { member ->
                            val probingThis = member.name in probingMembers
                            GroupMemberCard(
                                member = member,
                                isProbing = probingThis,
                                onSelect = {
                                    val g = activeGroup?.tag ?: return@GroupMemberCard
                                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    scope.launch {
                                        val ok = onSelectMember(g, member.name)
                                        feedback = if (ok) "已切换至 ${member.name}" else "切换失败"
                                        reload()
                                    }
                                },
                                onProbe = if (onProbeOutbound != null) {
                                    {
                                        if (member.name !in probingMembers) {
                                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                            scope.launch {
                                                probingMembers = probingMembers + member.name
                                                try {
                                                    val res = onProbeOutbound(member.name)
                                                    if (res.ok) {
                                                        groups = groups.map { grp ->
                                                            grp.copy(
                                                                members = grp.members.map { m ->
                                                                    if (m.name == member.name) {
                                                                        m.copy(
                                                                            state = res.state,
                                                                            latencyMs = if (res.state.equals("timeout", true) || res.state.equals("unreachable", true)) 0L else res.latencyMs,
                                                                        )
                                                                    } else m
                                                                },
                                                            )
                                                        }
                                                        feedback = if (res.latencyMs > 0L) {
                                                            "${member.name}: ${res.latencyMs} ms (${res.state})"
                                                        } else {
                                                            "${member.name}: ${res.state}"
                                                        }
                                                    } else {
                                                        feedback = "${member.name} 测速失败: ${res.errorMessage}"
                                                    }
                                                } finally {
                                                    probingMembers = probingMembers - member.name
                                                }
                                            }
                                        }
                                    }
                                } else null,
                            )
                        }
                    }
                }
            }
        }

        if (activeGroup != null) {
            GroupProbeFab(
                isProbing = isProbing,
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .padding(end = endPad, bottom = bottomPad + 14.dp),
                onClick = {
                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                    scope.launch {
                        isProbing = true
                        val ok = onProbeGroup(activeGroup.tag)
                        feedback = if (ok) "正在探测 ${activeGroup.tag} 节点延迟…" else "测速触发失败"
                        if (ok) {
                            delay(650L)
                            reload()
                            feedback = "${activeGroup.tag} 测速已更新"
                        }
                        isProbing = false
                    }
                },
            )
        }
    }
}
