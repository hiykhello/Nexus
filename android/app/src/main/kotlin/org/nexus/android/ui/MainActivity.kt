package org.nexus.android.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.InetAddresses
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.system.OsConstants
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
import org.nexus.android.bridge.ipc.ActiveConnectionSnapshot
import org.nexus.android.bridge.ipc.NexusControlClient
import org.nexus.android.bridge.ipc.OutboundJsonParser
import org.nexus.android.bridge.model.RuntimeSocketPaths
import org.nexus.android.bridge.owner.ConnectionOwnerResolver
import org.nexus.android.bridge.vpn.NexusVpnService
import org.nexus.android.bridge.vpn.VpnTunnelState
import org.nexus.android.bridge.workspace.AndroidHostConfig
import org.nexus.android.bridge.workspace.AndroidRunMode
import org.nexus.android.bridge.workspace.NexusClientDatabase
import org.nexus.android.bridge.workspace.ProfileItem
import org.nexus.android.bridge.workspace.ProfileKind
import org.nexus.android.ui.theme.NexusTheme
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

class MainActivity : ComponentActivity() {
    private lateinit var configFile: File
    private lateinit var socketPaths: RuntimeSocketPaths
    private lateinit var db: NexusClientDatabase
    private lateinit var supervisor: CoreProcessSupervisor
    private lateinit var controlClient: NexusControlClient
    private lateinit var workspaceCoordinator: WorkspaceCoordinator
    private lateinit var syncCoordinator: WorkspaceSyncCoordinator
    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val trimInFlight = AtomicBoolean(false)
    private val dashSaveMutex = Mutex()
    @Volatile private var pendingDashVisibility: DashboardCardVisibility? = null
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

        configFile = File(filesDir, "config.kdl")
        socketPaths = RuntimeSocketPaths(noBackupFilesDir)
        db = NexusClientDatabase.open(this)
        supervisor = CoreProcessSupervisor(this)
        controlClient = NexusControlClient(
            unixSocketPath = socketPaths.controlSocket.absolutePath,
            httpBaseUrl = "http://127.0.0.1:9090",
            bearerTokenProvider = { socketPaths.controlTokenFile.takeIf { it.isFile }?.readText()?.trim() },
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ownerResolver = ConnectionOwnerResolver(applicationContext).apply { start() }
        }
        workspaceCoordinator = WorkspaceCoordinator(filesDir, socketPaths, db, supervisor, controlClient)
        syncCoordinator = WorkspaceSyncCoordinator(workspaceCoordinator, socketPaths, supervisor, controlClient)

        setContent {
            NexusTheme {
                val scope = rememberCoroutineScope()
                var dashVisibility by remember { mutableStateOf(DashboardCardVisibility()) }
                var loadedKdl by remember { mutableStateOf("") }
                var workspaceState by remember { mutableStateOf(WorkspaceUiState()) }
                var composeLaunchError by remember { mutableStateOf("") }

                LaunchedEffect(configFile) {
                    val (kdl, dash) = withContext(Dispatchers.IO) {
                        if (!configFile.exists()) writeConfigAtomically(defaultAndroidKdl(socketPaths))
                        configFile.readText() to DashboardLayoutPrefs.load(db)
                    }
                    loadedKdl = kdl
                    dashVisibility = dash
                    workspaceState = workspaceCoordinator.loadInitialState()
                }

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
                val profileChips = remember(workspaceState.document.profiles, workspaceState.activeProfileId) {
                    workspaceState.document.profiles.map { p ->
                        UiProfileChip(id = p.id, name = p.remarks.ifBlank { p.id }, active = p.id == workspaceState.activeProfileId)
                    }
                }

                fun applyWorkspace(
                    next: WorkspaceUiState,
                    syncConflict: SyncConflictUi? = workspaceState.syncConflict,
                ) {
                    workspaceState = next.copy(
                        isRefreshingSub = workspaceState.isRefreshingSub,
                        isSyncing = workspaceState.isSyncing,
                        syncConflict = syncConflict,
                        isProbingUdp = workspaceState.isProbingUdp,
                        udpProbeResult = workspaceState.udpProbeResult,
                    )
                }

                fun launchRestartAsync() {
                    scope.launch {
                        composeLaunchError = ""
                        val state = workspaceCoordinator.loadInitialState()
                        applyWorkspace(state)
                        if (state.document.profiles.isNotEmpty()) {
                            val composed = workspaceCoordinator.composeForLaunch(state.activeProfileId)
                            if (!composed.ok || !socketPaths.composedConfigFile.isFile) {
                                composeLaunchError = composed.errors.firstOrNull() ?: "工作区编译失败，已取消重启"
                                return@launch
                            }
                            pendingStartConfigPath = socketPaths.composedConfigFile.absolutePath
                        } else {
                            pendingStartConfigPath = configFile.absolutePath
                        }
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
                    initialKdl = loadedKdl,
                    profiles = profileChips,
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
                                if (latest.document.profiles.isNotEmpty()) {
                                    val composed = workspaceCoordinator.composeForLaunch(latest.activeProfileId)
                                    if (!composed.ok || !socketPaths.composedConfigFile.isFile) {
                                        composeLaunchError = composed.errors.firstOrNull() ?: "工作区编译失败，已阻止启动"
                                        return@launch
                                    }
                                    pendingStartConfigPath = socketPaths.composedConfigFile.absolutePath
                                } else {
                                    pendingStartConfigPath = configFile.absolutePath
                                }
                                pendingFakeIpv6Pool = if (AndroidHostConfig.needsFakeIpv6Route(latest.document, latest.host.android)) {
                                    latest.document.dns.simple.fakeIpV6Pool
                                } else ""
                                applyWorkspace(workspaceCoordinator.loadInitialState())
                                requestAndStartTunnel(latest.host.android.runMode)
                            }
                        }
                    },
                    onRestartVpn = { launchRestartAsync() },
                    onSwitchOutboundMode = { mode, _ ->
                        val (next, msg) = workspaceCoordinator.switchOutboundMode(mode, running)
                        applyWorkspace(next)
                        null to msg
                    },
                    onCreateRuleFromConnection = { host, action, outbound, _ ->
                        val rule = WorkspaceCoordinator.buildRuleFromConnection(host, action, outbound)
                        val (next, msg) = workspaceCoordinator.addRoutingRule(rule, running)
                        applyWorkspace(next)
                        null to msg
                    },
                    onSwitchProfile = { profileId ->
                        val (next, msg) = workspaceCoordinator.selectProfile(profileId, running) { launchRestartAsync() }
                        applyWorkspace(next)
                        null to msg
                    },
                    onSaveProfileSnapshot = { name, kdl ->
                        val item = ProfileItem(id = "", remarks = name, kind = ProfileKind.FULL_CUSTOM_KDL, fullCustomKdl = kdl)
                        workspaceCoordinator.addProfile(item, running).let { (next, msg) -> applyWorkspace(next); msg }
                    },
                    onValidateKdl = { text -> validateDraft(text) },
                    onSaveAndReload = { text -> saveAndReload(text) },
                    onImportShareLink = { uri, _ ->
                        val (next, msg) = workspaceCoordinator.importShareUri(uri, running)
                        applyWorkspace(next)
                        null to msg
                    },
                    onImportSubscription = { name, url ->
                        val (next, msg) = workspaceCoordinator.addAndRefreshSubscription(name, url, running)
                        applyWorkspace(next)
                        "" to msg
                    },
                    onRefreshMetrics = { controlClient.fetchMetrics() },
                    onClearCache = { controlClient.clearCache().ok },
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
                    onResolveOwnerPackage = { conn -> resolveOwnerPackage(conn) },
                    onCloseConnection = { id -> controlClient.closeConnection(id).ok },
                    onCloseAllConnections = { controlClient.closeAllConnections().ok },
                    onSelectMember = { g, m -> controlClient.selectOutbound(g, m).ok },
                    onResetAuto = { g -> controlClient.resetGroupAuto(g).ok },
                    onProbeGroup = { g -> controlClient.probeGroup(g).ok },
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

    private suspend fun validateDraft(text: String): Pair<Boolean, String> = withContext(Dispatchers.IO) {
        val draft = File.createTempFile("draft-", ".kdl", cacheDir)
        try {
            draft.writeText(text, Charsets.UTF_8)
            val res = supervisor.validateConfig(draft)
            res.ok to res.output
        } finally {
            runCatching { draft.delete() }
        }
    }

    private fun writeConfigAtomically(text: String) {
        val parent = configFile.parentFile ?: filesDir
        parent.mkdirs()
        val tmp = File.createTempFile(".config-", ".kdl.tmp", parent)
        try {
            tmp.writeText(text, Charsets.UTF_8)
            if (!tmp.renameTo(configFile)) throw java.io.IOException("Atomic rename failed")
        } catch (t: Throwable) {
            runCatching { tmp.delete() }
            throw t
        }
    }

    private suspend fun saveAndReload(text: String): Pair<Boolean, String> {
        val (ok, msg) = validateDraft(text)
        if (!ok) return false to "拒绝保存无效配置: $msg"
        val writeErr = withContext(Dispatchers.IO) { runCatching { writeConfigAtomically(text) }.exceptionOrNull() }
        if (writeErr != null) return false to "保存配置失败: ${writeErr.message}"
        val reload = controlClient.reload()
        return true to if (reload.ok) "已校验保存并热重载" else "已保存配置"
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
        if (runMode == AndroidRunMode.PROXY_ONLY) {
            startVpnService()
        } else {
            launchVpnConsentOrStart()
        }
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
        val targetPath = pendingStartConfigPath ?: socketPaths.composedConfigFile.takeIf { it.isFile }?.absolutePath ?: configFile.absolutePath
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

    private suspend fun resolveOwnerPackage(conn: ActiveConnectionSnapshot): String? = withContext(Dispatchers.IO) {
        val resolver = ownerResolver ?: return@withContext null
        val src = AndroidHostConfig.parseHostPort(conn.source) ?: return@withContext null
        val dst = AndroidHostConfig.parseHostPort(conn.target) ?: return@withContext null
        if (!InetAddresses.isNumericAddress(src.first) || !InetAddresses.isNumericAddress(dst.first)) return@withContext null
        val proto = if (conn.protocol.contains("udp", ignoreCase = true)) OsConstants.IPPROTO_UDP else OsConstants.IPPROTO_TCP
        val info = runCatching {
            resolver.resolve(proto, InetAddresses.parseNumericAddress(src.first), src.second, InetAddresses.parseNumericAddress(dst.first), dst.second)
        }.getOrNull() ?: return@withContext null
        if (info.packageNames.isNotEmpty()) "${info.packageNames.joinToString(", ")} (UID ${info.uid})" else "UID ${info.uid}"
    }

    companion object {
        private fun escapeKdlString(raw: String): String = buildString(raw.length) {
            for (ch in raw) when (ch) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                else -> if (ch.code >= 0x20 && ch.code != 0x7F && ch != '\u0085' && ch != '\u2028' && ch != '\u2029') append(ch)
            }
        }

        private fun androidControlDirective(paths: RuntimeSocketPaths): String {
            val ctrlSock = escapeKdlString(paths.controlSocket.absolutePath)
            val tokenFile = escapeKdlString(paths.controlTokenFile.absolutePath)
            return """control socket="$ctrlSock" http-listen="127.0.0.1:9090" bearer-token-file="$tokenFile" metrics=#true"""
        }

        private fun defaultAndroidKdl(paths: RuntimeSocketPaths): String = """
            schema-version 1
            role "client"
            workers 2
            ${androidControlDirective(paths)}
            inbound "local" type="socks5" {
                listen host="127.0.0.1" port=10808
                authentication "none"
            }
            outbound "direct" type="direct"
            routing { default-outbound "direct"; }
        """.trimIndent() + "\n"
    }
}
