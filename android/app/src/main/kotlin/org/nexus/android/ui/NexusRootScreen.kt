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
import androidx.compose.runtime.mutableLongStateOf
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
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.nexus.android.apps.InstalledAppEntry
import org.nexus.android.bridge.ipc.ActiveConnectionSnapshot
import org.nexus.android.bridge.ipc.MetricsSummary
import org.nexus.android.bridge.ipc.OutboundGroupSnapshot
import org.nexus.android.bridge.ipc.OutboundMemberSnapshot
import org.nexus.android.bridge.model.AndroidKdlOps
import org.nexus.android.bridge.vpn.VpnTunnelState

private const val MAX_SPARKLINE_SAMPLES = 32

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun NexusRootScreen(
    running: Boolean,
    tunnelState: VpnTunnelState = if (running) VpnTunnelState.RUNNING else VpnTunnelState.STOPPED,
    startedAtMs: Long = 0L,
    lastError: String = "",
    powerSave: Boolean,
    localLogs: List<UiLogLine>,
    initialKdl: String,
    profiles: List<UiProfileChip> = emptyList(),
    activeProfileName: String = "默认配置",
    excludedPackages: Set<String>,
    dashVisibility: DashboardCardVisibility = DashboardCardVisibility(),
    onDashVisibilityChange: (DashboardCardVisibility) -> Unit = {},
    onToggleExcluded: (String, Boolean) -> Unit,
    onStartStop: (Boolean) -> Unit,
    onRestartVpn: () -> Unit = {},
    onSwitchOutboundMode: suspend (mode: String, currentKdl: String) -> Pair<String?, String> = { _, _ -> null to "" },
    onCreateRuleFromConnection: suspend (host: String, action: String, outbound: String, currentKdl: String) -> Pair<String?, String> = { _, _, _, _ -> null to "" },
    onSwitchProfile: suspend (String) -> Pair<String?, String> = { null to "" },
    onSaveProfileSnapshot: suspend (String, String) -> String = { _, _ -> "" },
    onValidateKdl: suspend (String) -> Pair<Boolean, String>,
    onSaveAndReload: suspend (String) -> Pair<Boolean, String>,
    onImportShareLink: suspend (String, String) -> Pair<String?, String>,
    onImportSubscription: suspend (String, String) -> Pair<String, String>,
    onRefreshMetrics: suspend () -> MetricsSummary,
    onClearCache: suspend () -> Boolean,
    onFetchGroups: suspend () -> List<OutboundGroupSnapshot>,
    onFetchConnections: suspend () -> List<ActiveConnectionSnapshot>,
    onInspectConnection: suspend (Long) -> ActiveConnectionSnapshot?,
    onResolveOwnerPackage: suspend (ActiveConnectionSnapshot) -> String?,
    onCloseConnection: suspend (Long) -> Boolean,
    onCloseAllConnections: suspend () -> Boolean,
    onSelectMember: suspend (String, String) -> Boolean,
    onResetAuto: suspend (String) -> Boolean,
    onProbeGroup: suspend (String) -> Boolean,
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

    var ringLogs by remember { mutableStateOf<List<UiLogLine>>(emptyList()) }
    var logSearch by rememberSaveable { mutableStateOf("") }
    var logLevel by rememberSaveable { mutableStateOf("trace") }
    var selectedTab by rememberSaveable { mutableIntStateOf(0) }
    var showSplitTunnel by rememberSaveable { mutableStateOf(false) }
    var kdlText by rememberSaveable { mutableStateOf(initialKdl) }
    var diagnostic by remember { mutableStateOf("") }
    var metrics by remember(previewMetrics) { mutableStateOf(previewMetrics ?: MetricsSummary()) }
    var downloadRateBps by remember(previewDownloadSamples) { mutableLongStateOf(previewDownloadSamples?.lastOrNull() ?: 0L) }
    var uploadRateBps by remember(previewUploadSamples) { mutableLongStateOf(previewUploadSamples?.lastOrNull() ?: 0L) }
    var peakRateBps by remember(previewDownloadSamples, previewUploadSamples) {
        mutableLongStateOf(maxOf(previewDownloadSamples?.maxOrNull() ?: 0L, previewUploadSamples?.maxOrNull() ?: 0L))
    }
    var downloadSamples by remember(previewDownloadSamples) { mutableStateOf(previewDownloadSamples ?: List(MAX_SPARKLINE_SAMPLES) { 0L }) }
    var uploadSamples by remember(previewUploadSamples) { mutableStateOf(previewUploadSamples ?: List(MAX_SPARKLINE_SAMPLES) { 0L }) }
    var activeExit by remember(previewActiveExit) { mutableStateOf(previewActiveExit ?: ActiveExitSummary()) }
    var quickNodes by remember(previewQuickNodes) { mutableStateOf(previewQuickNodes ?: emptyList()) }
    var memoryText by remember(previewMemoryText) { mutableStateOf(previewMemoryText ?: sampleRuntimeMemoryText()) }
    var dashEditing by rememberSaveable { mutableStateOf(previewDashEditing) }
    var isProbingOverview by remember { mutableStateOf(false) }
    var uptimeMs by remember(startedAtMs, running) {
        mutableLongStateOf(if (running && startedAtMs > 0L) (System.currentTimeMillis() - startedAtMs).coerceAtLeast(0L) else 0L)
    }

    val currentTab = tabs[selectedTab.coerceIn(0, tabs.lastIndex)]
    val outboundMode = remember(kdlText) { AndroidKdlOps.detectOutboundMode(kdlText) }
    val hasRemoteOutbound = remember(kdlText) { AndroidKdlOps.hasRemoteOutbound(kdlText) }

    suspend fun syncPrimaryGroup(preferredTag: String = "") {
        val loaded = onFetchGroups()
        val primary = loaded.firstOrNull { preferredTag.isNotEmpty() && it.tag == preferredTag } ?: loaded.firstOrNull()
        if (primary != null) {
            val sel = primary.members.firstOrNull { it.selected }
            activeExit = ActiveExitSummary(
                groupTag = primary.tag,
                memberName = sel?.name ?: primary.active,
                latencyMs = sel?.latencyMs ?: -1L,
                state = sel?.state ?: "unknown",
            )
            quickNodes = primary.members.take(6)
        }
    }

    LaunchedEffect(initialKdl) {
        if (kdlText.isEmpty() && initialKdl.isNotEmpty()) {
            kdlText = initialKdl
        }
    }

    BackHandler(enabled = showSplitTunnel) {
        showSplitTunnel = false
    }

    // Lifecycle-aware visible telemetry polling & uptime ticker when running
    LaunchedEffect(running, powerSave, startedAtMs, lifecycleOwner, previewMetrics) {
        if (previewMetrics != null) return@LaunchedEffect
        if (!running) {
            downloadRateBps = 0L
            uploadRateBps = 0L
            peakRateBps = 0L
            uptimeMs = 0L
            downloadSamples = List(MAX_SPARKLINE_SAMPLES) { 0L }
            uploadSamples = List(MAX_SPARKLINE_SAMPLES) { 0L }
            activeExit = ActiveExitSummary()
            quickNodes = emptyList()
            return@LaunchedEffect
        }
        lifecycleOwner.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            var prevMetrics: MetricsSummary? = null
            var prevTimestampMs = 0L
            var groupTick = 0
            while (isActive) {
                val now = System.currentTimeMillis()
                if (startedAtMs > 0L) {
                    uptimeMs = (now - startedAtMs).coerceAtLeast(0L)
                }
                val latest = onRefreshMetrics()
                metrics = latest
                val prior = prevMetrics
                if (prior != null && prevTimestampMs > 0L) {
                    val elapsedMs = (now - prevTimestampMs).coerceAtLeast(250L)
                    val downRate = ((latest.downloadBytes - prior.downloadBytes).coerceAtLeast(0L) * 1000L) / elapsedMs
                    val upRate = ((latest.uploadBytes - prior.uploadBytes).coerceAtLeast(0L) * 1000L) / elapsedMs
                    downloadRateBps = downRate
                    uploadRateBps = upRate
                    if (downRate > peakRateBps) peakRateBps = downRate
                    if (upRate > peakRateBps) peakRateBps = upRate
                    downloadSamples = downloadSamples.drop(1) + downRate
                    uploadSamples = uploadSamples.drop(1) + upRate
                }
                prevMetrics = latest
                prevTimestampMs = now

                if (groupTick % 5 == 0) {
                    syncPrimaryGroup(activeExit.groupTag)
                    memoryText = sampleRuntimeMemoryText()
                }
                groupTick++
                delay(if (powerSave) 4_000L else 1_000L)
            }
        }
    }

    LaunchedEffect(running, currentTab, previewMetrics) {
        if (!running || previewMetrics != null) return@LaunchedEffect
        if (currentTab == NexusTab.LOGS) {
            ringLogs = onFetchLogs(logLevel, logSearch)
        }
    }

    val exitTimedOut = running &&
        activeExit.memberName.isNotEmpty() &&
        (activeExit.state.equals("timeout", ignoreCase = true) ||
            activeExit.state.equals("unreachable", ignoreCase = true) ||
            activeExit.latencyMs == 0L)
    val heroState = when {
        tunnelState == VpnTunnelState.STARTING -> HeroConnectionState.STARTING
        tunnelState == VpnTunnelState.ERROR -> HeroConnectionState.ERROR
        running && exitTimedOut -> HeroConnectionState.DEGRADED
        running -> HeroConnectionState.CONNECTED
        else -> HeroConnectionState.STANDBY
    }

    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior()

    val scaffoldContent: @Composable () -> Unit = {
        Scaffold(
            modifier = Modifier.fillMaxSize().nestedScroll(scrollBehavior.nestedScrollConnection),
            containerColor = MaterialTheme.colorScheme.surface,
            topBar = {
                NexusTopAppBar(
                    showSplitTunnel = showSplitTunnel,
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

            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.TopCenter,
            ) {
                Box(modifier = Modifier.widthIn(max = 1120.dp).fillMaxSize()) {
                    if (showSplitTunnel) {
                        SplitTunnelScreen(
                            running = running,
                            excludedPackages = excludedPackages,
                            onToggleExcluded = onToggleExcluded,
                            onRestartVpn = onRestartVpn,
                            windowSizeClass = windowSizeClass,
                            contentPadding = innerPadding,
                            previewApps = previewApps,
                        )
                    } else {
                        when (currentTab) {
                            NexusTab.OVERVIEW -> OverviewScreen(
                                heroState = heroState,
                                powerSave = powerSave,
                                uptimeMs = uptimeMs,
                                activeProfileName = activeProfileName,
                                outboundMode = outboundMode,
                                hasRemoteOutbound = hasRemoteOutbound,
                                activeExit = activeExit,
                                quickNodes = quickNodes,
                                memoryText = memoryText,
                                isProbing = isProbingOverview,
                                dashEditing = dashEditing,
                                dashVisibility = dashVisibility,
                                metrics = metrics,
                                downloadRateBps = downloadRateBps,
                                uploadRateBps = uploadRateBps,
                                peakRateBps = peakRateBps,
                                downloadSamples = downloadSamples,
                                uploadSamples = uploadSamples,
                                excludedCount = excludedPackages.size,
                                diagnostic = diagnostic,
                                errorDetail = lastError,
                                windowSizeClass = windowSizeClass,
                                contentPadding = screenPadding,
                                onStartStop = { onStartStop(running) },
                                onSwitchOutboundMode = { mode ->
                                    scope.launch {
                                        val (updated, note) = onSwitchOutboundMode(mode, kdlText)
                                        if (updated != null) kdlText = updated
                                        diagnostic = note
                                    }
                                },
                                onDashVisibilityChange = onDashVisibilityChange,
                                onQuickPasteImport = { raw ->
                                    scope.launch {
                                        val (updated, note) = importClipboardPayload(raw, kdlText, onImportSubscription, onImportShareLink)
                                        if (updated != null) {
                                            val looksLikeKdl = raw.contains("schema-version") ||
                                                (raw.contains("routing {") && raw.contains("outbound "))
                                            if (looksLikeKdl) {
                                                val (saved, saveMsg) = onSaveAndReload(updated)
                                                if (saved) kdlText = updated
                                                diagnostic = saveMsg
                                            } else {
                                                kdlText = updated
                                                diagnostic = note
                                            }
                                        } else {
                                            diagnostic = note
                                        }
                                        selectedTab = NexusTab.CONFIG.ordinal
                                    }
                                },
                                onSelectQuickNode = { node ->
                                    val tag = activeExit.groupTag.ifEmpty { return@OverviewScreen }
                                    scope.launch {
                                        val ok = onSelectMember(tag, node.name)
                                        diagnostic = if (ok) "已切换至 ${node.name}" else "切换失败"
                                        if (ok) syncPrimaryGroup(tag)
                                    }
                                },
                                onProbeActiveGroup = {
                                    val tag = activeExit.groupTag.ifEmpty { return@OverviewScreen }
                                    scope.launch {
                                        isProbingOverview = true
                                        val ok = onProbeGroup(tag)
                                        if (ok) {
                                            delay(650L)
                                            syncPrimaryGroup(tag)
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
                            )
                            NexusTab.GROUPS -> GroupsScreen(
                                onFetchGroups = onFetchGroups,
                                onSelectMember = onSelectMember,
                                onResetAuto = onResetAuto,
                                onProbeGroup = onProbeGroup,
                                windowSizeClass = windowSizeClass,
                                contentPadding = innerPadding,
                            )
                            NexusTab.CONNECTIONS -> ConnectionsScreen(
                                running = running,
                                powerSave = powerSave,
                                excludedPackages = excludedPackages,
                                onFetchConnections = onFetchConnections,
                                onInspectConnection = onInspectConnection,
                                onResolveOwnerPackage = onResolveOwnerPackage,
                                onCloseConnection = onCloseConnection,
                                onCloseAllConnections = onCloseAllConnections,
                                onCreateRuleFromConnection = { host, action, outbound ->
                                    val (updated, note) = onCreateRuleFromConnection(host, action, outbound, kdlText)
                                    if (updated != null) {
                                        kdlText = updated
                                    }
                                    note
                                },
                                onBypassPackage = { pkg -> onToggleExcluded(pkg, true) },
                                windowSizeClass = windowSizeClass,
                                contentPadding = innerPadding,
                                downloadRateBps = downloadRateBps,
                                uploadRateBps = uploadRateBps,
                            )
                            NexusTab.CONFIG -> ConfigScreen(
                                kdlText = kdlText,
                                hasRemoteOutbound = hasRemoteOutbound,
                                profiles = profiles,
                                onApplyConfig = { next ->
                                    val res = onSaveAndReload(next)
                                    if (res.first) kdlText = next
                                    res
                                },
                                diagnostic = diagnostic,
                                onDiagnosticChange = { diagnostic = it },
                                onImportShareLink = { raw, cur ->
                                    val res = onImportShareLink(raw, cur)
                                    if (res.first != null) kdlText = res.first!!
                                    res
                                },
                                onImportSubscription = { name, url ->
                                    val res = onImportSubscription(name, url)
                                    if (res.first.isNotEmpty()) kdlText = res.first
                                    res
                                },
                                onSwitchProfile = { id ->
                                    val res = onSwitchProfile(id)
                                    val loaded = res.first
                                    if (loaded != null) kdlText = loaded
                                    res
                                },
                                onSaveProfileSnapshot = onSaveProfileSnapshot,
                                onValidateKdl = onValidateKdl,
                                windowSizeClass = windowSizeClass,
                                contentPadding = screenPadding,
                                excludedCount = excludedPackages.size,
                                onOpenSplitTunnel = { showSplitTunnel = true },
                            )
                            NexusTab.LOGS -> LogsScreen(
                                logs = if (ringLogs.isNotEmpty()) ringLogs else localLogs,
                                logSearch = logSearch,
                                onLogSearchChange = { logSearch = it },
                                logLevel = logLevel,
                                onLogLevelChange = { logLevel = it },
                                onRefreshLogs = { scope.launch { ringLogs = onFetchLogs(logLevel, logSearch) } },
                                onShareLogs = onShareLogs,
                                contentPadding = innerPadding,
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
                            downloadRateBps = downloadRateBps,
                            uploadRateBps = uploadRateBps,
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
                // Sibling Row keeps MediumNavigationRail outside Scaffold so NexusTopAppBar never overlaps its FAB.
                Row(modifier = Modifier.fillMaxSize()) {
                    MediumNavigationRail(
                        tabs = tabs,
                        selectedTab = selectedTab,
                        showSplitTunnel = showSplitTunnel,
                        running = running,
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
}
