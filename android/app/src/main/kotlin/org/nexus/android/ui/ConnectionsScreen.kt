package org.nexus.android.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandHorizontally
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkHorizontally
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
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
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.nexus.android.R
import org.nexus.android.bridge.ipc.ActiveConnectionSnapshot
import org.nexus.android.bridge.workspace.AndroidPerAppMode
import org.nexus.android.ui.theme.NexusTheme

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConnectionsScreen(
    running: Boolean,
    powerSave: Boolean = false,
    excludedPackages: Set<String>,
    perAppMode: AndroidPerAppMode = AndroidPerAppMode.EXCLUDE,
    onFetchConnections: suspend () -> List<ActiveConnectionSnapshot>,
    wsActive: Boolean = false,
    wsConnections: List<ActiveConnectionSnapshot>? = null,
    connectionsStream: (() -> Flow<List<ActiveConnectionSnapshot>>)? = null,
    onInspectConnection: suspend (Long) -> ActiveConnectionSnapshot?,
    onResolveOwnerPackage: suspend (ActiveConnectionSnapshot) -> String?,
    onCloseConnection: suspend (Long) -> Boolean,
    onCloseAllConnections: suspend () -> Boolean,
    onCreateRuleFromConnection: suspend (targetHost: String, action: String, outbound: String) -> String,
    onBypassPackage: (packageName: String) -> Unit,
    windowSizeClass: NexusWindowSizeClass,
    contentPadding: PaddingValues,
    initialSelectedConnection: ActiveConnectionSnapshot? = null,
    downloadRateBps: Long = -1L,
    uploadRateBps: Long = -1L,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val lifecycleOwner = LocalLifecycleOwner.current
    val haptic = LocalHapticFeedback.current
    val layoutDirection = LocalLayoutDirection.current
    val ext = NexusTheme.colors
    val primary = MaterialTheme.colorScheme.primary
    val twoPane = windowSizeClass == NexusWindowSizeClass.EXPANDED

    // Hoisted scroll state above conditional branches.
    val listState = rememberLazyListState()
    val latestFetch by rememberUpdatedState(onFetchConnections)
    val latestStream by rememberUpdatedState(connectionsStream)
    val latestInspect by rememberUpdatedState(onInspectConnection)
    val latestResolveOwner by rememberUpdatedState(onResolveOwnerPackage)

    var connections by remember { mutableStateOf<List<ActiveConnectionSnapshot>>(emptyList()) }
    var selectedId by rememberSaveable { mutableLongStateOf(initialSelectedConnection?.id ?: -1L) }
    var inspectedDetail by remember(initialSelectedConnection) { mutableStateOf(initialSelectedConnection) }
    var resolvedOwner by remember { mutableStateOf<String?>(null) }
    var actionFeedback by remember { mutableStateOf("") }
    var query by rememberSaveable { mutableStateOf("") }
    var isPaused by rememberSaveable { mutableStateOf(false) }

    // Consume multiplexed WebSocket snapshots directly when active (respecting Pause toggle)
    LaunchedEffect(wsConnections, isPaused) {
        if (wsConnections != null && !isPaused) {
            connections = wsConnections
        }
    }

    // Lifecycle-scoped SSE / polling fallback when multiplexed WebSocket is not active
    val wsFeeding = wsActive || wsConnections != null
    LaunchedEffect(running, powerSave, isPaused, wsFeeding, lifecycleOwner) {
        lifecycleOwner.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            if (wsConnections == null) connections = latestFetch()
            if (!running || isPaused || wsFeeding) return@repeatOnLifecycle
            val sseFactory = latestStream
            if (!powerSave && sseFactory != null) {
                sseFactory().collect { snapshot ->
                    if (!isPaused) connections = snapshot
                }
            } else {
                while (isActive) {
                    delay(if (powerSave) 5_000L else 2_000L)
                    if (!isPaused) connections = latestFetch()
                }
            }
        }
    }

    LaunchedEffect(selectedId, connections) {
        if (selectedId <= 0L) {
            inspectedDetail = null
            resolvedOwner = null
            return@LaunchedEffect
        }
        val targetId = selectedId
        val fromList = connections.firstOrNull { it.id == targetId }
        if (inspectedDetail?.id != targetId) {
            resolvedOwner = null
            val fresh = latestInspect(targetId) ?: fromList
            if (selectedId == targetId) {
                inspectedDetail = fresh
                val owner = fresh?.let { latestResolveOwner(it) }
                if (selectedId == targetId) resolvedOwner = owner
            }
        }
    }

    val filtered = remember(connections, query) {
        val q = query.trim().lowercase()
        if (q.isEmpty()) connections
        else connections.filter {
            it.protocol.lowercase().contains(q) ||
                it.path.lowercase().contains(q) ||
                it.outbound.lowercase().contains(q) ||
                it.inbound.lowercase().contains(q) ||
                it.target.lowercase().contains(q) ||
                it.routeRule.lowercase().contains(q) ||
                it.destinationPort.toString().contains(q)
        }
    }

    val totalUpload = remember(filtered) { filtered.sumOf { it.uploadBytes } }
    val totalDownload = remember(filtered) { filtered.sumOf { it.downloadBytes } }
    val tcpCount = remember(filtered) { filtered.count { it.protocol.contains("tcp", ignoreCase = true) } }
    val udpCount = filtered.size - tcpCount
    val proxyPercent = remember(filtered) {
        if (filtered.isEmpty()) 0
        else {
            val proxied = filtered.count { !it.outbound.equals("direct", ignoreCase = true) }
            ((proxied * 100L) / filtered.size).toInt()
        }
    }
    val activeDetail = inspectedDetail ?: filtered.firstOrNull { it.id == selectedId }

    val dismissDetail: () -> Unit = {
        selectedId = -1L
        inspectedDetail = null
        resolvedOwner = null
        actionFeedback = ""
    }

    val closeSingle: (Long) -> Unit = { id ->
        scope.launch {
            if (onCloseConnection(id)) {
                if (selectedId == id) dismissDetail()
                connections = latestFetch()
            }
        }
    }

    val createRule: (String, String, String) -> Unit = { host, action, outbound ->
        scope.launch {
            actionFeedback = onCreateRuleFromConnection(host, action, outbound)
        }
    }

    val bypassApp: (String) -> Unit = { pkg ->
        val action = computePerAppConnectionAction(perAppMode, pkg, excludedPackages)
        if (action.enabled) {
            onBypassPackage(pkg)
            actionFeedback = action.feedbackText
        }
    }

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
                value = query,
                onValueChange = { query = it },
                placeholder = { Text("搜索连接...", maxLines = 1, overflow = TextOverflow.Ellipsis) },
                shape = RoundedCornerShape(999.dp),
                leadingIcon = { Icon(painterResource(R.drawable.ic_search), null, Modifier.size(18.dp)) },
                trailingIcon = {
                    if (query.isNotEmpty()) {
                        IconButton(onClick = { query = "" }) {
                            Icon(painterResource(R.drawable.ic_close), "清除", Modifier.size(18.dp))
                        }
                    }
                },
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
            FilledTonalIconButton(
                onClick = {
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    isPaused = !isPaused
                },
                colors = if (isPaused) {
                    IconButtonDefaults.filledTonalIconButtonColors(
                        containerColor = ext.warningContainer,
                        contentColor = ext.warning,
                    )
                } else {
                    IconButtonDefaults.filledTonalIconButtonColors()
                },
            ) {
                Icon(
                    painter = painterResource(if (isPaused) R.drawable.ic_play else R.drawable.ic_pause),
                    contentDescription = if (isPaused) "恢复实时刷新" else "暂停实时刷新",
                    modifier = Modifier.size(18.dp),
                )
            }
            FilledTonalIconButton(onClick = { scope.launch { connections = latestFetch() } }) {
                Icon(painterResource(R.drawable.ic_refresh), "刷新", Modifier.size(20.dp))
            }
            if (windowSizeClass != NexusWindowSizeClass.COMPACT) {
                Surface(
                    onClick = {
                        if (connections.isNotEmpty()) {
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                            scope.launch {
                                if (onCloseAllConnections()) {
                                    dismissDetail()
                                    connections = latestFetch()
                                }
                            }
                        }
                    },
                    enabled = connections.isNotEmpty(),
                    modifier = Modifier.heightIn(min = 44.dp),
                    shape = RoundedCornerShape(999.dp),
                    color = if (connections.isNotEmpty()) ext.dangerContainer else ext.wellSurface,
                    border = BorderStroke(1.dp, if (connections.isNotEmpty()) ext.danger.copy(alpha = 0.40f) else ext.hairline),
                ) {
                    Box(
                        modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            text = "全部断开",
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.SemiBold,
                            color = if (connections.isNotEmpty()) ext.danger else ext.muted,
                        )
                    }
                }
            }
        }

        ConnectionsKpiStrip(
            activeCount = filtered.size,
            tcpCount = tcpCount,
            udpCount = udpCount,
            downloadRateBps = downloadRateBps,
            uploadRateBps = uploadRateBps,
            totalDownload = totalDownload,
            totalUpload = totalUpload,
            proxyPercent = proxyPercent,
            compact = windowSizeClass == NexusWindowSizeClass.COMPACT,
        )

        if (windowSizeClass == NexusWindowSizeClass.COMPACT || isPaused) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (isPaused) {
                    StatusPill(text = "实时刷新已暂停", containerColor = ext.warningContainer, contentColor = ext.warning)
                }
                Box(modifier = Modifier.weight(1f))
                if (windowSizeClass == NexusWindowSizeClass.COMPACT) {
                    OutlinedButton(
                        enabled = connections.isNotEmpty(),
                        shape = RoundedCornerShape(999.dp),
                        onClick = {
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                            scope.launch {
                                if (onCloseAllConnections()) {
                                    dismissDetail()
                                    connections = latestFetch()
                                }
                            }
                        },
                    ) {
                        Text("全部断开")
                    }
                }
            }
        }

        // Zero-BoxWithConstraints master / on-demand list-detail workspace
        Row(modifier = Modifier.weight(1f).fillMaxWidth()) {
            if (filtered.isEmpty()) {
                Column(modifier = Modifier.weight(1f).fillMaxHeight()) {
                    EmptyStateCard(
                        title = "暂无活跃连接",
                        subtitle = if (query.isNotEmpty()) "未匹配到 \"$query\"" else "产生流量后将在此实时显示连接与路由。",
                        iconRes = R.drawable.ic_nav_connections,
                        actionLabel = if (query.isNotEmpty()) "清除搜索" else "刷新",
                        onAction = { if (query.isNotEmpty()) query = "" else scope.launch { connections = latestFetch() } },
                    )
                }
            } else {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.weight(1f).fillMaxHeight(),
                    contentPadding = PaddingValues(bottom = bottomPad + 12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    items(
                        items = filtered,
                        key = { it.id },
                        contentType = { "connection" },
                    ) { conn ->
                        ConnectionItemCard(
                            conn = conn,
                            selected = selectedId == conn.id,
                            onInspect = {
                                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                if (twoPane && selectedId == conn.id) {
                                    dismissDetail()
                                    return@ConnectionItemCard
                                }
                                val targetId = conn.id
                                actionFeedback = ""
                                resolvedOwner = null
                                selectedId = targetId
                                inspectedDetail = conn
                                scope.launch {
                                    val detail = latestInspect(targetId) ?: conn
                                    if (selectedId == targetId) {
                                        inspectedDetail = detail
                                        val owner = latestResolveOwner(detail)
                                        if (selectedId == targetId) resolvedOwner = owner
                                    }
                                }
                            },
                            onClose = { closeSingle(conn.id) },
                        )
                    }
                }
            }

            AnimatedVisibility(
                visible = twoPane && activeDetail != null,
                enter = expandHorizontally(expandFrom = Alignment.End) + fadeIn(),
                exit = shrinkHorizontally(shrinkTowards = Alignment.End) + fadeOut(),
            ) {
                activeDetail?.let { detail ->
                    Column(
                        modifier = Modifier
                            .width(404.dp)
                            .fillMaxHeight()
                            .padding(start = 14.dp, bottom = bottomPad + 8.dp),
                    ) {
                        OpticalCard(
                            cornerRadius = 24.dp,
                            borderColor = primary.copy(alpha = 0.55f),
                        ) {
                            ConnectionDetailContent(
                                detail = detail,
                                ownerPackage = resolvedOwner,
                                excludedPackages = excludedPackages,
                                perAppMode = perAppMode,
                                actionFeedback = actionFeedback,
                                showDismissButton = true,
                                onDismiss = dismissDetail,
                                onCloseConnection = closeSingle,
                                onCreateRule = createRule,
                                onBypassOwnerApp = bypassApp,
                            )
                        }
                    }
                }
            }
        }
    }

    if (!twoPane && activeDetail != null) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ModalBottomSheet(
            onDismissRequest = dismissDetail,
            sheetState = sheetState,
            shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp),
            containerColor = MaterialTheme.colorScheme.surfaceContainer,
        ) {
            ConnectionDetailContent(
                detail = activeDetail,
                ownerPackage = resolvedOwner,
                excludedPackages = excludedPackages,
                perAppMode = perAppMode,
                actionFeedback = actionFeedback,
                showDismissButton = true,
                onDismiss = dismissDetail,
                onCloseConnection = closeSingle,
                onCreateRule = createRule,
                onBypassOwnerApp = bypassApp,
            )
            Spacer(Modifier.size(16.dp))
        }
    }
}
