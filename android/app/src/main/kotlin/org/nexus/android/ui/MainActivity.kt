package org.nexus.android.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.nexus.android.bridge.core.CoreProcessSupervisor
import org.nexus.android.bridge.ipc.CachedTokenReader
import org.nexus.android.bridge.ipc.NexusControlClient
import org.nexus.android.bridge.ipc.NexusSseClient
import org.nexus.android.bridge.ipc.NexusWsClient
import org.nexus.android.bridge.ipc.OutboundJsonParser
import org.nexus.android.bridge.model.RuntimeSocketPaths
import org.nexus.android.bridge.owner.ConnectionOwnerResolver
import org.nexus.android.bridge.vpn.NexusVpnService
import org.nexus.android.bridge.vpn.VpnTunnelState
import org.nexus.android.bridge.workspace.AndroidHostConfig
import org.nexus.android.bridge.workspace.AndroidRunMode
import org.nexus.android.bridge.workspace.NexusClientDatabase
import org.nexus.android.ui.theme.NexusTheme
import java.util.concurrent.atomic.AtomicBoolean

class MainActivity : ComponentActivity() {
    private lateinit var socketPaths: RuntimeSocketPaths
    private lateinit var db: NexusClientDatabase
    private lateinit var supervisor: CoreProcessSupervisor
    private lateinit var controlClient: NexusControlClient
    private lateinit var sseClient: NexusSseClient
    private lateinit var wsClient: NexusWsClient
    private val tunnelCoordinator = MainTunnelCoordinator()
    private lateinit var workspaceCoordinator: WorkspaceCoordinator
    private lateinit var syncCoordinator: WorkspaceSyncCoordinator
    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val trimInFlight = AtomicBoolean(false)
    private val dashSaveMutex = Mutex()
    @Volatile private var pendingDashVisibility: DashboardCardVisibility? = null
    @Volatile private var controlHttpBaseUrl: String = "http://127.0.0.1:9090"
    private var ownerResolver: ConnectionOwnerResolver? = null
    private var askedNotificationPermission = false
    private var pendingStartConfigPath: String? = null
    private var pendingFakeIpv6Pool: String = ""

    private val vpnPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) startVpnService()
        }

    private val notificationPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { _ ->
            launchVpnConsentOrStart()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        window.isNavigationBarContrastEnforced = false
        super.onCreate(savedInstanceState)

        socketPaths = RuntimeSocketPaths(noBackupFilesDir)
        db = NexusClientDatabase.open(this)
        supervisor = CoreProcessSupervisor(this)
        val tokenReader = CachedTokenReader(socketPaths.controlTokenFile)
        controlClient = NexusControlClient(
            unixSocketPath = socketPaths.controlSocket.absolutePath,
            httpBaseUrlProvider = { controlHttpBaseUrl },
            bearerTokenProvider = { tokenReader.read() },
        )
        sseClient = controlClient.createSseClient()
        wsClient = controlClient.createWsClient()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ownerResolver = ConnectionOwnerResolver(applicationContext).apply { start() }
        }
        workspaceCoordinator = WorkspaceCoordinator(filesDir, socketPaths, db, supervisor, controlClient)
        syncCoordinator = WorkspaceSyncCoordinator(workspaceCoordinator, socketPaths, supervisor, controlClient)

        setContent {
            val scope = rememberCoroutineScope()
            var dashVisibility by remember { mutableStateOf(DashboardCardVisibility()) }
            var workspaceState by remember { mutableStateOf(WorkspaceUiState()) }
            var composeLaunchError by remember { mutableStateOf("") }

            fun applyWorkspace(
                next: WorkspaceUiState,
                syncConflict: SyncConflictUi? = workspaceState.syncConflict,
            ) {
                controlHttpBaseUrl = NexusControlClient.httpUrlFromListen(next.host.common.controlHttpListen)
                workspaceState = next.copy(
                    isRefreshingSub = workspaceState.isRefreshingSub,
                    isSyncing = workspaceState.isSyncing,
                    syncConflict = syncConflict,
                    isProbingUdp = workspaceState.isProbingUdp,
                    udpProbeResult = workspaceState.udpProbeResult,
                )
            }

            LaunchedEffect(Unit) {
                dashVisibility = withContext(Dispatchers.IO) { DashboardLayoutPrefs.load(db) }
                val initial = workspaceCoordinator.loadInitialState()
                applyWorkspace(initial)
                if (!socketPaths.composedConfigFile.isFile && initial.activeProfileId.isNotEmpty()) {
                    workspaceCoordinator.composeForLaunch(initial.activeProfileId)
                }
            }

            NexusTheme(dynamicColor = workspaceState.host.android.dynamicColor) {
                val running by NexusVpnService.runningState.collectAsStateWithLifecycle()
                val tunnelState by NexusVpnService.tunnelState.collectAsStateWithLifecycle()
                val startedAtMs by NexusVpnService.startedAtMs.collectAsStateWithLifecycle()
                val lastError by NexusVpnService.lastError.collectAsStateWithLifecycle()
                val powerSave by NexusVpnService.powerSaveMode.collectAsStateWithLifecycle()
                val rawLocalLogs by NexusVpnService.recentLogs.collectAsStateWithLifecycle()
                val localLogs = remember(rawLocalLogs) { rawLocalLogs.map { UiLogLine(seq = -it.seq, text = it.text) } }
                val effectiveTunnelState = if (!running && composeLaunchError.isNotEmpty()) VpnTunnelState.ERROR else tunnelState
                val effectiveError = lastError.ifBlank { composeLaunchError }
                val perAppPackages = remember(workspaceState.host.android.perAppPackages) {
                    workspaceState.host.android.perAppPackages.toSet()
                }

                fun launchRestartAsync() {
                    scope.launch {
                        composeLaunchError = ""
                        val state = workspaceCoordinator.loadInitialState()
                        applyWorkspace(state)
                        val composed = workspaceCoordinator.composeForLaunch(state.activeProfileId)
                        if (!composed.ok || !socketPaths.composedConfigFile.isFile) {
                            composeLaunchError = composed.errors.firstOrNull() ?: "配置生成失败，已取消重启"
                            return@launch
                        }
                        pendingStartConfigPath = socketPaths.composedConfigFile.absolutePath
                        pendingFakeIpv6Pool = if (AndroidHostConfig.needsFakeIpv6Route(state.document, state.host.android)) {
                            state.document.dns.simple.fakeIpV6Pool
                        } else ""
                        restartVpnService(state.host.android.runMode)
                    }
                }

                val workspaceActions = remember(running) {
                    WorkspaceUiActions(
                        onSelectProfile = { id ->
                            composeLaunchError = ""
                            workspaceCoordinator.selectProfile(id, running) { launchRestartAsync() }.let { (n, m) -> applyWorkspace(n); m }
                        },
                        onAddProfile = { item -> workspaceCoordinator.addProfile(item, running).let { (n, m) -> applyWorkspace(n); m } },
                        onDeleteProfile = { id -> workspaceCoordinator.deleteProfile(id, running).let { (n, m) -> applyWorkspace(n); m } },
                        onAddSubscription = { name, url ->
                            workspaceState = workspaceState.copy(isRefreshingSub = true)
                            try { workspaceCoordinator.addAndRefreshSubscription(name, url, running).let { (n, m) -> applyWorkspace(n); m } }
                            finally { workspaceState = workspaceState.copy(isRefreshingSub = false) }
                        },
                        onRefreshSubscription = { subId ->
                            workspaceState = workspaceState.copy(isRefreshingSub = true)
                            try { workspaceCoordinator.refreshSubscription(subId, running).let { (n, m) -> applyWorkspace(n); m } }
                            finally { workspaceState = workspaceState.copy(isRefreshingSub = false) }
                        },
                        onUpdateSubscriptionChain = { subId, prevId, nextId ->
                            workspaceCoordinator.updateSubscriptionChain(subId, prevId, nextId, running).let { (n, m) -> applyWorkspace(n); m }
                        },
                        onSelectRoutingProfile = { routingId -> workspaceCoordinator.selectRoutingProfile(routingId, running).let { (n, m) -> applyWorkspace(n); m } },
                        onAddRoutingRule = { rule -> workspaceCoordinator.addRoutingRule(rule, running).let { (n, m) -> applyWorkspace(n); m } },
                        onToggleRoutingRule = { ruleId, en -> workspaceCoordinator.toggleRoutingRule(ruleId, en, running).let { (n, m) -> applyWorkspace(n); m } },
                        onDeleteRoutingRule = { ruleId -> workspaceCoordinator.deleteRoutingRule(ruleId, running).let { (n, m) -> applyWorkspace(n); m } },
                        onUpdateRoutingFlags = { autoIf, findProc ->
                            workspaceCoordinator.updateRoutingProfileFlags(autoIf, findProc, running).let { (n, m) -> applyWorkspace(n); m }
                        },
                        onUpdateDns = { dns -> workspaceCoordinator.updateDns(dns, running).let { (n, m) -> applyWorkspace(n); m } },
                        onUpdateHost = { host -> workspaceCoordinator.updateHost(host).let { (n, m) -> applyWorkspace(n); m } },
                        onUpdateSyncSettings = { u, user, pw, pass, dev ->
                            workspaceCoordinator.mutateHost { cur ->
                                cur.copy(android = cur.android.copy(webdavUrl = u, webdavUsername = user, webdavPassword = pw, syncPassphrase = pass, syncDeviceLabel = dev))
                            }.let { (n, m) -> applyWorkspace(n); m }
                        },
                        onExportWorkspaceJson = { workspaceCoordinator.exportPortableWorkspaceJson() },
                        onImportWorkspaceJson = { raw -> workspaceCoordinator.importPortableWorkspaceJson(raw, running).let { (n, m) -> applyWorkspace(n); m } },
                        onExportShareUri = { id -> syncCoordinator.exportShareUri(id) },
                        onImportShareUri = { uri -> syncCoordinator.importShareUri(uri, running).let { (n, m) -> applyWorkspace(n); m } },
                        onPushWebDav = { force ->
                            workspaceState = workspaceState.copy(isSyncing = true)
                            try { syncCoordinator.pushWebDav(force).let { (n, c, m) -> applyWorkspace(n, syncConflict = c); m } }
                            finally { workspaceState = workspaceState.copy(isSyncing = false) }
                        },
                        onPullWebDav = { force ->
                            workspaceState = workspaceState.copy(isSyncing = true)
                            try { syncCoordinator.pullWebDav(force, running).let { (n, c, m) -> applyWorkspace(n, syncConflict = c); m } }
                            finally { workspaceState = workspaceState.copy(isSyncing = false) }
                        },
                        onDismissSyncConflict = { workspaceState = workspaceState.copy(syncConflict = null) },
                        onRunUdpProbe = { kind ->
                            workspaceState = workspaceState.copy(isProbingUdp = true)
                            try { syncCoordinator.runUdpProbe(kind, running).let { (r, m) -> workspaceState = workspaceState.copy(udpProbeResult = r); m } }
                            finally { workspaceState = workspaceState.copy(isProbingUdp = false) }
                        },
                    )
                }

                NexusRootScreen(
                    running = running,
                    tunnelState = effectiveTunnelState,
                    startedAtMs = startedAtMs,
                    lastError = effectiveError,
                    powerSave = powerSave,
                    localLogs = localLogs,
                    activeProfileName = workspaceState.activeProfileTitle,
                    excludedPackages = perAppPackages,
                    dashVisibility = dashVisibility,
                    onDashVisibilityChange = { next ->
                        dashVisibility = next
                        pendingDashVisibility = next
                        ioScope.launch { dashSaveMutex.withLock { pendingDashVisibility?.let { DashboardLayoutPrefs.save(db, it) } } }
                    },
                    workspaceState = workspaceState,
                    workspaceActions = workspaceActions,
                    onShareLogs = { text ->
                        val shareIntent = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(Intent.EXTRA_SUBJECT, "Nexus 运行日志")
                            putExtra(Intent.EXTRA_TEXT, text)
                        }
                        startActivity(Intent.createChooser(shareIntent, "导出日志"))
                    },
                    onToggleExcluded = { pkg, checked ->
                        scope.launch {
                            applyWorkspace(workspaceCoordinator.mutateHost { cur ->
                                val updated = if (checked) (cur.android.perAppPackages + pkg).distinct()
                                else cur.android.perAppPackages.filterNot { it == pkg }
                                cur.copy(android = cur.android.copy(perAppPackages = updated))
                            }.first)
                        }
                    },
                    onBypassFromConnection = { pkg ->
                        scope.launch {
                            applyWorkspace(workspaceCoordinator.mutateHost { cur ->
                                MainTunnelCoordinator.applyBypassFromConnection(cur, pkg)
                            }.first)
                        }
                    },
                    onAddExcludedBatch = { pkgs ->
                        scope.launch {
                            applyWorkspace(workspaceCoordinator.mutateHost { cur ->
                                cur.copy(android = cur.android.copy(perAppPackages = (cur.android.perAppPackages + pkgs).distinct()))
                            }.first)
                        }
                    },
                    onStartStop = { isRunning ->
                        if (isRunning) {
                            composeLaunchError = ""
                            stopVpnService()
                        } else {
                            scope.launch {
                                composeLaunchError = ""
                                withContext(Dispatchers.IO) { workspaceCoordinator.telemetryStore.clearUnexpectedCrash() }
                                val latest = workspaceCoordinator.loadInitialState()
                                applyWorkspace(latest)
                                val composed = workspaceCoordinator.composeForLaunch(latest.activeProfileId)
                                if (!composed.ok || !socketPaths.composedConfigFile.isFile) {
                                    composeLaunchError = composed.errors.firstOrNull() ?: "配置生成失败，已阻止启动"
                                    return@launch
                                }
                                pendingStartConfigPath = socketPaths.composedConfigFile.absolutePath
                                pendingFakeIpv6Pool = if (AndroidHostConfig.needsFakeIpv6Route(latest.document, latest.host.android)) {
                                    latest.document.dns.simple.fakeIpV6Pool
                                } else ""
                                applyWorkspace(workspaceCoordinator.loadInitialState())
                                requestAndStartTunnel(latest.host.android.runMode)
                            }
                        }
                    },
                    onRestartVpn = { launchRestartAsync() },
                    onSwitchOutboundMode = { mode ->
                        val (next, msg) = workspaceCoordinator.switchOutboundMode(mode, running)
                        applyWorkspace(next)
                        msg
                    },
                    onCreateRuleFromConnection = { host, action, outbound ->
                        val rule = WorkspaceCoordinator.buildRuleFromConnection(host, action, outbound)
                        val (next, msg) = workspaceCoordinator.addRoutingRule(rule, running)
                        applyWorkspace(next)
                        msg
                    },
                    onImportCustomConfig = { raw ->
                        val (next, msg) = workspaceCoordinator.importCustomConfig(raw, running)
                        applyWorkspace(next)
                        msg
                    },
                    onImportShareLink = { uri ->
                        val (next, msg) = workspaceCoordinator.importShareUri(uri, running)
                        applyWorkspace(next)
                        msg
                    },
                    onImportSubscription = { name, url ->
                        val (next, msg) = workspaceCoordinator.addAndRefreshSubscription(name, url, running)
                        applyWorkspace(next)
                        msg
                    },
                    onRefreshMetrics = { controlClient.fetchMetrics() },
                    onClearCache = { controlClient.clearCache("all").ok },
                    onClearCacheTarget = { target -> controlClient.clearCache(target).ok },
                    onFetchGroups = {
                        val reply = controlClient.fetchOutboundsJson()
                        if (reply.ok) OutboundJsonParser.parse(reply.body) else emptyList()
                    },
                    onFetchConnections = {
                        val reply = controlClient.fetchConnectionsJson()
                        if (reply.ok) OutboundJsonParser.parseConnections(reply.body) else emptyList()
                    },
                    onInspectConnection = { id ->
                        val reply = controlClient.fetchConnectionDetailJson(id)
                        if (reply.ok) OutboundJsonParser.parseConnectionDetail(reply.body) else null
                    },
                    onResolveOwnerPackage = { conn -> tunnelCoordinator.resolveOwnerPackage(ownerResolver, conn) },
                    onCloseConnection = { id -> controlClient.closeConnection(id).ok },
                    onCloseAllConnections = { controlClient.closeAllConnections().ok },
                    onSelectMember = { g, m -> controlClient.selectOutbound(g, m).ok },
                    onResetAuto = { g -> controlClient.resetGroupAuto(g).ok },
                    onProbeGroup = { g -> controlClient.probeGroup(g).ok },
                    onProbeOutbound = { tag -> controlClient.probeOutbound(tag) },
                    onFetchLiveRules = { controlClient.fetchRules() },
                    onQueryDns = { name, type, server -> controlClient.queryDns(name, type, server) },
                    onFlushFakeIp = { controlClient.flushFakeIp() },
                    onSetCoreLogLevel = { level -> controlClient.setLogLevel(level).ok },
                    wsStream = { channels, since, intervalMs -> wsClient.stream(channels = channels, since = since, intervalMs = intervalMs) },
                    statusStream = { sseClient.streamStatus(1_000) },
                    connectionsStream = { sseClient.streamConnections(1_500) },
                    logsStream = { since, level, search -> sseClient.streamLogs(since = since, level = level, search = search) },
                    onFetchLogs = { level, search ->
                        val reply = controlClient.fetchLogsJson(level = level, search = search, limit = 128)
                        if (reply.ok) {
                            OutboundJsonParser.parseLogs(reply.body).entries.map { e ->
                                UiLogLine(seq = e.seq, text = "[${e.level}] ${e.domain}: ${e.message}")
                            }
                        } else emptyList()
                    },
                )
            }
        }
    }

    private fun requestAndStartTunnel(runMode: AndroidRunMode) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !askedNotificationPermission) {
            val granted = ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                askedNotificationPermission = true
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                return
            }
        }
        if (runMode == AndroidRunMode.PROXY_ONLY) startVpnService() else launchVpnConsentOrStart()
    }

    private fun launchVpnConsentOrStart() {
        val prep = VpnService.prepare(this)
        if (prep != null) vpnPermissionLauncher.launch(prep) else startVpnService()
    }

    private fun startVpnService() = dispatchVpnAction(NexusVpnService.ACTION_START)

    private fun stopVpnService() {
        startService(Intent(this, NexusVpnService::class.java).setAction(NexusVpnService.ACTION_STOP))
    }

    private fun restartVpnService(runMode: AndroidRunMode) {
        if (runMode == AndroidRunMode.VPN) {
            VpnService.prepare(this)?.let { vpnPermissionLauncher.launch(it); return }
        }
        dispatchVpnAction(NexusVpnService.ACTION_RESTART)
    }

    private fun dispatchVpnAction(action: String) {
        val targetPath = pendingStartConfigPath ?: socketPaths.composedConfigFile.absolutePath
        startForegroundService(
            Intent(this, NexusVpnService::class.java)
                .setAction(action)
                .putExtra(NexusVpnService.EXTRA_CONFIG_PATH, targetPath)
                .putExtra(NexusVpnService.EXTRA_FAKE_IPV6_POOL, pendingFakeIpv6Pool),
        )
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (::db.isInitialized && trimInFlight.compareAndSet(false, true)) {
            ioScope.launch { try { runCatching { db.shrinkMemory() } } finally { trimInFlight.set(false) } }
        }
    }

    override fun onDestroy() {
        ioScope.cancel()
        ownerResolver?.close(); ownerResolver = null
        super.onDestroy()
    }
}
