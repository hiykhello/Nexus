package org.nexus.android.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.PermanentNavigationDrawer
import androidx.compose.material3.Scaffold
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.launch
import org.nexus.android.apps.InstalledAppEntry
import org.nexus.android.bridge.ipc.ActiveConnectionSnapshot
import org.nexus.android.bridge.ipc.DnsQueryResult
import org.nexus.android.bridge.ipc.FakeIpFlushResult
import org.nexus.android.bridge.ipc.LiveRuleSnapshot
import org.nexus.android.bridge.ipc.LiveStatusSnapshot
import org.nexus.android.bridge.ipc.LogRingEntry
import org.nexus.android.bridge.ipc.MetricsSummary
import org.nexus.android.bridge.ipc.OutboundGroupSnapshot
import org.nexus.android.bridge.ipc.OutboundMemberSnapshot
import org.nexus.android.bridge.ipc.OutboundProbeResult
import org.nexus.android.bridge.ipc.WsEvent
import org.nexus.android.bridge.vpn.VpnTunnelState

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun NexusRootScreen(
    running: Boolean,
    tunnelState: VpnTunnelState = if (running) VpnTunnelState.RUNNING else VpnTunnelState.STOPPED,
    startedAtMs: Long = 0L,
    lastError: String = "",
    powerSave: Boolean,
    localLogs: List<UiLogLine>,
    activeProfileName: String = "默认直连",
    excludedPackages: Set<String>,
    dashVisibility: DashboardCardVisibility = DashboardCardVisibility(),
    onDashVisibilityChange: (DashboardCardVisibility) -> Unit = {},
    workspaceState: WorkspaceUiState = WorkspaceUiState(),
    workspaceActions: WorkspaceUiActions = WorkspaceUiActions(),
    onToggleExcluded: (String, Boolean) -> Unit,
    onBypassFromConnection: ((String) -> Unit)? = null,
    onAddExcludedBatch: ((Set<String>) -> Unit)? = null,
    onStartStop: (Boolean) -> Unit,
    onRestartVpn: () -> Unit = {},
    onSwitchOutboundMode: suspend (mode: String) -> String = { "" },
    onCreateRuleFromConnection: suspend (host: String, action: String, outbound: String) -> String = { _, _, _ -> "" },
    onImportCustomConfig: suspend (String) -> String = { "" },
    onImportShareLink: suspend (String) -> String = { "" },
    onImportSubscription: suspend (String, String) -> String = { _, _ -> "" },
    onRefreshMetrics: suspend () -> MetricsSummary,
    onClearCache: suspend () -> Boolean,
    onClearCacheTarget: (suspend (String) -> Boolean)? = null,
    onFetchGroups: suspend () -> List<OutboundGroupSnapshot>,
    onFetchConnections: suspend () -> List<ActiveConnectionSnapshot>,
    onInspectConnection: suspend (Long) -> ActiveConnectionSnapshot?,
    onResolveOwnerPackage: suspend (ActiveConnectionSnapshot) -> String?,
    onCloseConnection: suspend (Long) -> Boolean,
    onCloseAllConnections: suspend () -> Boolean,
    onSelectMember: suspend (String, String) -> Boolean,
    onResetAuto: suspend (String) -> Boolean,
    onProbeGroup: suspend (String) -> Boolean,
    onProbeOutbound: (suspend (String) -> OutboundProbeResult)? = null,
    onFetchLiveRules: suspend () -> List<LiveRuleSnapshot> = { emptyList() },
    onQueryDns: suspend (String, String, String) -> DnsQueryResult = { _, _, _ -> DnsQueryResult(false, errorMessage = "未连接") },
    onFlushFakeIp: suspend () -> FakeIpFlushResult = { FakeIpFlushResult(false, message = "未连接") },
    onSetCoreLogLevel: (suspend (String) -> Boolean)? = null,
    wsStream: ((channels: List<String>, since: Long, intervalMs: Int) -> Flow<WsEvent>)? = null,
    statusStream: (() -> Flow<LiveStatusSnapshot>)? = null,
    connectionsStream: (() -> Flow<List<ActiveConnectionSnapshot>>)? = null,
    logsStream: ((since: Long, level: String, search: String) -> Flow<LogRingEntry>)? = null,
    onFetchLogs: suspend (String, String) -> List<UiLogLine>,
    onShareLogs: (String) -> Unit,
    previewMetrics: MetricsSummary? = null,
    previewApps: List<InstalledAppEntry>? = null,
    previewDownloadSamples: List<Long>? = null,
    previewUploadSamples: List<Long>? = null,
    previewActiveExit: ActiveExitSummary? = null,
    previewQuickNodes: List<OutboundMemberSnapshot>? = null,
    previewMemoryText: String? = null,
    previewDashEditing: Boolean = false,
) {
    val scope = rememberCoroutineScope()
    val lifecycleOwner = LocalLifecycleOwner.current
    val haptic = LocalHapticFeedback.current
    val layoutDirection = LocalLayoutDirection.current
    val windowSizeClass = rememberWindowSizeClass()
    val tabs = NexusTab.entries

    var logSearch by rememberSaveable { mutableStateOf("") }
    var logLevel by rememberSaveable { mutableStateOf("trace") }
    var selectedTab by rememberSaveable { mutableIntStateOf(0) }
    var showSplitTunnel by rememberSaveable { mutableStateOf(false) }
    var showDiagnostics by rememberSaveable { mutableStateOf(false) }
    var diagnostic by remember { mutableStateOf("") }
    var dashEditing by rememberSaveable { mutableStateOf(previewDashEditing) }
    var isProbingOverview by remember { mutableStateOf(false) }

    val currentTab = tabs[selectedTab.coerceIn(0, tabs.lastIndex)]
    val outboundMode = workspaceState.outboundMode.ifBlank { "rule" }
    val perAppMode = workspaceState.host.android.perAppMode
    val hasRemoteOutbound = workspaceState.hasAnyRemoteProfile

    val telemetry = rememberNexusTelemetryState(
        running = running,
        powerSave = powerSave,
        startedAtMs = startedAtMs,
        currentTab = currentTab,
        logLevel = logLevel,
        logSearch = logSearch,
        lifecycleOwner = lifecycleOwner,
        onRefreshMetrics = onRefreshMetrics,
        onFetchGroups = onFetchGroups,
        onFetchLogs = onFetchLogs,
        wsStream = wsStream,
        statusStream = statusStream,
        logsStream = logsStream,
        previewMetrics = previewMetrics,
        previewDownloadSamples = previewDownloadSamples,
        previewUploadSamples = previewUploadSamples,
        previewActiveExit = previewActiveExit,
        previewQuickNodes = previewQuickNodes,
        previewMemoryText = previewMemoryText,
    )

    BackHandler(enabled = showSplitTunnel) { showSplitTunnel = false }

    val exitTimedOut = running &&
        telemetry.activeExit.memberName.isNotEmpty() &&
        (telemetry.activeExit.state.equals("timeout", ignoreCase = true) ||
            telemetry.activeExit.state.equals("unreachable", ignoreCase = true) ||
            telemetry.activeExit.latencyMs == 0L)
    val heroState = when {
        tunnelState == VpnTunnelState.STARTING -> HeroConnectionState.STARTING
        tunnelState == VpnTunnelState.ERROR -> HeroConnectionState.ERROR
        running && exitTimedOut -> HeroConnectionState.DEGRADED
        running -> HeroConnectionState.CONNECTED
        else -> HeroConnectionState.STANDBY
    }

    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior()
    // Reset pinned top-bar overlap state cleanly when switching tabs or Split Tunnel overlay.
    LaunchedEffect(selectedTab, showSplitTunnel) {
        scrollBehavior.state.contentOffset = 0f
    }

    val scaffoldContent: @Composable () -> Unit = {
        Scaffold(
            modifier = Modifier.fillMaxSize().nestedScroll(scrollBehavior.nestedScrollConnection),
            containerColor = MaterialTheme.colorScheme.surface,
            topBar = {
                NexusTopAppBar(
                    showSplitTunnel = showSplitTunnel,
                    perAppMode = perAppMode,
                    currentTab = currentTab,
                    windowSizeClass = windowSizeClass,
                    heroState = heroState,
                    activeProfileName = activeProfileName,
                    dashEditing = dashEditing,
                    scrollBehavior = scrollBehavior,
                    onOpenConfig = { selectedTab = NexusTab.CONFIG.ordinal },
                    onToggleDashEditing = { dashEditing = !dashEditing },
                    onCloseSplitTunnel = { showSplitTunnel = false },
                )
            },
            bottomBar = {
                if (windowSizeClass == NexusWindowSizeClass.COMPACT && !showSplitTunnel) {
                    CompactBottomChrome(
                        tabs = tabs,
                        selectedTab = selectedTab,
                        onSelectTab = { selectedTab = it },
                    )
                }
            },
        ) { innerPadding ->
            val screenPadding = PaddingValues(
                start = innerPadding.calculateStartPadding(layoutDirection) + 16.dp,
                end = innerPadding.calculateEndPadding(layoutDirection) + 16.dp,
                top = innerPadding.calculateTopPadding() + 8.dp,
                bottom = innerPadding.calculateBottomPadding() + 16.dp,
            )

            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
                Box(modifier = Modifier.widthIn(max = 1120.dp).fillMaxSize()) {
                    if (showSplitTunnel) {
                        val h = workspaceState.host
                        SplitTunnelScreen(
                            running = running,
                            excludedPackages = excludedPackages,
                            onToggleExcluded = onToggleExcluded,
                            onRestartVpn = onRestartVpn,
                            windowSizeClass = windowSizeClass,
                            contentPadding = innerPadding,
                            previewApps = previewApps,
                            perAppMode = h.android.perAppMode,
                            onPerAppModeChange = { m -> scope.launch { workspaceActions.onUpdateHost(h.copy(android = h.android.copy(perAppMode = m))) } },
                            excludeSelfFromVpn = h.android.excludeSelfFromVpn,
                            onToggleExcludeSelf = { v -> scope.launch { workspaceActions.onUpdateHost(h.copy(android = h.android.copy(excludeSelfFromVpn = v))) } },
                            allowBypass = h.android.allowBypass,
                            onToggleAllowBypass = { v -> scope.launch { workspaceActions.onUpdateHost(h.copy(android = h.android.copy(allowBypass = v))) } },
                            onAddExcludedBatch = onAddExcludedBatch,
                        )
                    } else {
                        when (currentTab) {
                            NexusTab.OVERVIEW -> {
                                val activeRouting = workspaceState.document.activeRoutingProfile()
                                val dnsCfg = workspaceState.document.dns
                                val dnsLabel = when {
                                    dnsCfg.mode == "raw_kdl" -> "高级 DNS · ${activeRouting.rules.size} 条规则"
                                    dnsCfg.simple.fakeIpEnabled -> "FakeIP · ${activeRouting.rules.size} 条规则"
                                    else -> "标准 DNS · ${activeRouting.rules.size} 条规则"
                                }
                                OverviewScreen(
                                    heroState = heroState,
                                    powerSave = powerSave,
                                    uptimeMs = telemetry.uptimeMs,
                                    activeProfileName = activeProfileName,
                                    outboundMode = outboundMode,
                                    hasRemoteOutbound = hasRemoteOutbound,
                                    activeExit = telemetry.activeExit,
                                    quickNodes = telemetry.quickNodes,
                                    memoryText = telemetry.memoryText,
                                    isProbing = isProbingOverview,
                                    dashEditing = dashEditing,
                                    dashVisibility = dashVisibility,
                                    metrics = telemetry.metrics,
                                    downloadRateBps = telemetry.downloadRateBps,
                                    uploadRateBps = telemetry.uploadRateBps,
                                    peakRateBps = telemetry.peakRateBps,
                                    downloadSamples = telemetry.downloadSamples,
                                    uploadSamples = telemetry.uploadSamples,
                                    excludedCount = excludedPackages.size,
                                    perAppMode = perAppMode,
                                    diagnostic = diagnostic,
                                    errorDetail = lastError,
                                    windowSizeClass = windowSizeClass,
                                    contentPadding = screenPadding,
                                    onStartStop = { onStartStop(running) },
                                    onSwitchOutboundMode = { mode ->
                                        scope.launch { diagnostic = onSwitchOutboundMode(mode) }
                                    },
                                    onDashVisibilityChange = onDashVisibilityChange,
                                    onQuickPasteImport = { raw ->
                                        scope.launch {
                                            diagnostic = importClipboardPayload(
                                                raw = raw,
                                                onImportWorkspaceShare = workspaceActions.onImportShareUri,
                                                onImportWorkspaceBackup = workspaceActions.onImportWorkspaceJson,
                                                onImportCustomConfig = onImportCustomConfig,
                                                onImportSubscription = onImportSubscription,
                                                onImportShareLink = onImportShareLink,
                                            )
                                            selectedTab = NexusTab.CONFIG.ordinal
                                        }
                                    },
                                    onSelectQuickNode = { node ->
                                        val tag = telemetry.activeExit.groupTag.ifEmpty { return@OverviewScreen }
                                        scope.launch {
                                            val ok = onSelectMember(tag, node.name)
                                            diagnostic = if (ok) "已切换至 ${node.name}" else "切换失败"
                                            if (ok) telemetry.applyPrimaryGroups(onFetchGroups(), tag)
                                        }
                                    },
                                    onProbeActiveGroup = {
                                        val tag = telemetry.activeExit.groupTag.ifEmpty { return@OverviewScreen }
                                        scope.launch {
                                            isProbingOverview = true
                                            val ok = onProbeGroup(tag)
                                            if (ok) {
                                                delay(650L)
                                                telemetry.applyPrimaryGroups(onFetchGroups(), tag)
                                                diagnostic = "测速已更新"
                                            } else {
                                                diagnostic = "测速失败"
                                            }
                                            isProbingOverview = false
                                        }
                                    },
                                    onClearCache = { scope.launch { diagnostic = if (onClearCache()) "缓存已清空" else "清空失败" } },
                                    onOpenGroups = { selectedTab = NexusTab.GROUPS.ordinal },
                                    onOpenConnections = { selectedTab = NexusTab.CONNECTIONS.ordinal },
                                    onOpenConfig = { selectedTab = NexusTab.CONFIG.ordinal },
                                    onOpenSplitTunnel = { showSplitTunnel = true },
                                    onOpenDiagnostics = { showDiagnostics = true },
                                    routingProfileName = activeRouting.name,
                                    dnsSummaryText = dnsLabel,
                                )
                            }
                            NexusTab.GROUPS -> GroupsScreen(
                                onFetchGroups = onFetchGroups,
                                onSelectMember = onSelectMember,
                                onResetAuto = onResetAuto,
                                onProbeGroup = onProbeGroup,
                                onProbeOutbound = onProbeOutbound,
                                windowSizeClass = windowSizeClass,
                                contentPadding = innerPadding,
                                running = running,
                                onOpenOverview = { selectedTab = NexusTab.OVERVIEW.ordinal },
                            )
                            NexusTab.CONNECTIONS -> ConnectionsScreen(
                                running = running,
                                powerSave = powerSave,
                                excludedPackages = excludedPackages,
                                perAppMode = perAppMode,
                                onFetchConnections = onFetchConnections,
                                wsActive = telemetry.wsActive && !powerSave,
                                wsConnections = telemetry.wsLiveConnections,
                                connectionsStream = connectionsStream,
                                onInspectConnection = onInspectConnection,
                                onResolveOwnerPackage = onResolveOwnerPackage,
                                onCloseConnection = onCloseConnection,
                                onCloseAllConnections = onCloseAllConnections,
                                onCreateRuleFromConnection = { host, action, outbound ->
                                    onCreateRuleFromConnection(host, action, outbound)
                                },
                                onBypassPackage = { pkg ->
                                    if (onBypassFromConnection != null) onBypassFromConnection(pkg)
                                    else onToggleExcluded(pkg, true)
                                },
                                windowSizeClass = windowSizeClass,
                                contentPadding = innerPadding,
                                downloadRateBps = telemetry.downloadRateBps,
                                uploadRateBps = telemetry.uploadRateBps,
                            )
                            NexusTab.CONFIG -> ConfigScreen(
                                diagnostic = diagnostic,
                                onDiagnosticChange = { diagnostic = it },
                                onImportCustomConfig = onImportCustomConfig,
                                onImportShareLink = onImportShareLink,
                                onImportSubscription = onImportSubscription,
                                windowSizeClass = windowSizeClass,
                                contentPadding = screenPadding,
                                onOpenSplitTunnel = { showSplitTunnel = true },
                                onOpenDiagnostics = { showDiagnostics = true },
                                workspaceState = workspaceState,
                                workspaceActions = workspaceActions,
                            )
                            NexusTab.LOGS -> LogsScreen(
                                logs = if (telemetry.ringLogs.isNotEmpty()) telemetry.ringLogs else localLogs,
                                logSearch = logSearch,
                                onLogSearchChange = { logSearch = it },
                                logLevel = logLevel,
                                onLogLevelChange = { logLevel = it },
                                onRefreshLogs = { scope.launch { telemetry.ringLogs = onFetchLogs(logLevel, logSearch) } },
                                onShareLogs = onShareLogs,
                                contentPadding = innerPadding,
                                running = running,
                                sseStreaming = telemetry.logsSseActive,
                                coreLogLevel = workspaceState.host.common.logLevel,
                                onSetCoreLogLevel = onSetCoreLogLevel,
                            )
                        }
                    }
                }
            }
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        when (windowSizeClass) {
            NexusWindowSizeClass.EXPANDED -> {
                PermanentNavigationDrawer(
                    drawerContent = {
                        ExpandedDrawerContent(
                            tabs = tabs,
                            selectedTab = selectedTab,
                            showSplitTunnel = showSplitTunnel,
                            heroState = heroState,
                            downloadRateBps = telemetry.downloadRateBps,
                            uploadRateBps = telemetry.uploadRateBps,
                            onSelectTab = { idx ->
                                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                showSplitTunnel = false
                                selectedTab = idx
                            },
                            onStartStop = {
                                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                onStartStop(running)
                            },
                        )
                    },
                    content = scaffoldContent,
                )
            }
            NexusWindowSizeClass.MEDIUM -> {
                Row(modifier = Modifier.fillMaxSize()) {
                    MediumNavigationRail(
                        tabs = tabs,
                        selectedTab = selectedTab,
                        showSplitTunnel = showSplitTunnel,
                        running = running,
                        heroState = heroState,
                        showQuickPower = showSplitTunnel || currentTab != NexusTab.OVERVIEW,
                        onSelectTab = { idx ->
                            showSplitTunnel = false
                            selectedTab = idx
                        },
                        onStartStop = { onStartStop(running) },
                    )
                    Box(modifier = Modifier.weight(1f).fillMaxHeight()) {
                        scaffoldContent()
                    }
                }
            }
            NexusWindowSizeClass.COMPACT -> scaffoldContent()
        }

        StatusBarProtection(modifier = Modifier.align(Alignment.TopCenter))
    }

    if (showDiagnostics) {
        DiagnosticsSheet(
            running = running,
            workspaceState = workspaceState,
            workspaceActions = workspaceActions,
            onFetchLiveRules = onFetchLiveRules,
            onQueryDns = onQueryDns,
            onFlushFakeIp = onFlushFakeIp,
            onClearCacheTarget = { target -> onClearCacheTarget?.invoke(target) ?: onClearCache() },
            onFeedback = { diagnostic = it },
            onDismiss = { showDiagnostics = false },
        )
    }
}
