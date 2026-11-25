package org.nexus.android.ui

import android.Manifest
import android.content.Context
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.nexus.android.bridge.core.CoreProcessSupervisor
import org.nexus.android.bridge.ipc.ActiveConnectionSnapshot
import org.nexus.android.bridge.ipc.NexusControlClient
import org.nexus.android.bridge.ipc.OutboundJsonParser
import org.nexus.android.bridge.model.AndroidKdlBuilder
import org.nexus.android.bridge.model.RuntimeSocketPaths
import org.nexus.android.bridge.owner.ConnectionOwnerResolver
import org.nexus.android.bridge.profile.ProfileRepository
import org.nexus.android.bridge.vpn.NexusVpnService
import org.nexus.android.bridge.vpn.VpnTunnelState
import org.nexus.android.bridge.workspace.AndroidHostConfig
import org.nexus.android.bridge.workspace.AndroidRunMode
import org.nexus.android.ui.theme.NexusTheme
import java.io.File

class MainActivity : ComponentActivity() {
    private lateinit var configFile: File
    private lateinit var socketPaths: RuntimeSocketPaths
    private lateinit var profiles: ProfileRepository
    private lateinit var supervisor: CoreProcessSupervisor
    private lateinit var controlClient: NexusControlClient
    private lateinit var workspaceCoordinator: WorkspaceCoordinator
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
        profiles = ProfileRepository(filesDir)
        supervisor = CoreProcessSupervisor(this)
        controlClient = NexusControlClient(
            unixSocketPath = socketPaths.controlSocket.absolutePath,
            httpBaseUrl = "http://127.0.0.1:9090",
            bearerTokenProvider = { socketPaths.controlTokenFile.takeIf { it.isFile }?.readText()?.trim() },
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ownerResolver = ConnectionOwnerResolver(applicationContext).apply { start() }
        }
        val prefs = getSharedPreferences("nexus_prefs", Context.MODE_PRIVATE)
        workspaceCoordinator = WorkspaceCoordinator(filesDir, socketPaths, prefs, supervisor, controlClient)

        setContent {
            NexusTheme {
                val scope = rememberCoroutineScope()
                var dashVisibility by remember { mutableStateOf(DashboardLayoutPrefs.load(prefs)) }
                var loadedKdl by remember { mutableStateOf("") }
                var workspaceState by remember { mutableStateOf(WorkspaceUiState()) }
                var composeLaunchError by remember { mutableStateOf("") }

                LaunchedEffect(configFile) {
                    loadedKdl = withContext(Dispatchers.IO) {
                        if (!configFile.exists()) writeConfigAtomically(defaultAndroidKdl(socketPaths))
                        configFile.readText()
                    }
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

                fun launchRestartAsync() {
                    scope.launch {
                        composeLaunchError = ""
                        val state = workspaceCoordinator.loadInitialState()
                        workspaceState = state
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
                            val (next, msg) = workspaceCoordinator.selectProfile(id, running) { launchRestartAsync() }
                            workspaceState = next
                            msg
                        },
                        onAddProfile = { item ->
                            val (next, msg) = workspaceCoordinator.addProfile(item, running)
                            workspaceState = next
                            msg
                        },
                        onDeleteProfile = { id ->
                            val (next, msg) = workspaceCoordinator.deleteProfile(id, running)
                            workspaceState = next
                            msg
                        },
                        onAddSubscription = { name, url ->
                            workspaceState = workspaceState.copy(isRefreshingSub = true)
                            val (next, msg) = workspaceCoordinator.addAndRefreshSubscription(name, url, running)
                            workspaceState = next.copy(isRefreshingSub = false)
                            msg
                        },
                        onRefreshSubscription = { subId ->
                            workspaceState = workspaceState.copy(isRefreshingSub = true)
                            val (next, msg) = workspaceCoordinator.refreshSubscription(subId, running)
                            workspaceState = next.copy(isRefreshingSub = false)
                            msg
                        },
                        onUpdateSubscriptionChain = { subId, prevId, nextId ->
                            val (next, msg) = workspaceCoordinator.updateSubscriptionChain(subId, prevId, nextId, running)
                            workspaceState = next
                            msg
                        },
                        onSelectRoutingProfile = { routingId ->
                            val (next, msg) = workspaceCoordinator.selectRoutingProfile(routingId, running)
                            workspaceState = next
                            msg
                        },
                        onAddRoutingRule = { rule ->
                            val (next, msg) = workspaceCoordinator.addRoutingRule(rule, running)
                            workspaceState = next
                            msg
                        },
                        onUpdateDns = { dns ->
                            val (next, msg) = workspaceCoordinator.updateDns(dns, running)
                            workspaceState = next
                            msg
                        },
                        onUpdateHost = { host ->
                            val (next, msg) = workspaceCoordinator.updateHost(host)
                            workspaceState = next
                            msg
                        },
                        onExportWorkspaceJson = { workspaceCoordinator.exportPortableWorkspaceJson() },
                        onImportWorkspaceJson = { raw ->
                            val (next, msg) = workspaceCoordinator.importPortableWorkspaceJson(raw, running)
                            workspaceState = next
                            msg
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
                        DashboardLayoutPrefs.save(prefs, next)
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
                            workspaceState = workspaceCoordinator.mutateHost { cur ->
                                val updated = if (checked) (cur.android.perAppPackages + pkg).distinct()
                                else cur.android.perAppPackages.filterNot { it == pkg }
                                cur.copy(android = cur.android.copy(perAppPackages = updated))
                            }.first
                        }
                    },
                    onAddExcludedBatch = { pkgs ->
                        scope.launch {
                            workspaceState = workspaceCoordinator.mutateHost { cur ->
                                val updated = (cur.android.perAppPackages + pkgs).distinct()
                                cur.copy(android = cur.android.copy(perAppPackages = updated))
                            }.first
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
                                workspaceState = latest
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
                                workspaceState = workspaceCoordinator.loadInitialState()
                                requestAndStartTunnel(latest.host.android.runMode)
                            }
                        }
                    },
                    onRestartVpn = { launchRestartAsync() },
                    onSwitchOutboundMode = { mode, _ ->
                        val (next, msg) = workspaceCoordinator.switchOutboundMode(mode, running)
                        workspaceState = next
                        null to msg
                    },
                    onCreateRuleFromConnection = { host, action, outbound, _ ->
                        val rule = WorkspaceCoordinator.buildRuleFromConnection(host, action, outbound)
                        val (next, msg) = workspaceCoordinator.addRoutingRule(rule, running)
                        workspaceState = next
                        null to msg
                    },
                    onSwitchProfile = { profileId ->
                        val (next, msg) = workspaceCoordinator.selectProfile(profileId, running) { launchRestartAsync() }
                        workspaceState = next
                        null to msg
                    },
                    onSaveProfileSnapshot = { name, kdl ->
                        withContext(Dispatchers.IO) { profiles.saveProfile(name, kdl).name.let { "已保存档案 $it" } }
                    },
                    onValidateKdl = { text -> validateDraft(text) },
                    onSaveAndReload = { text -> saveAndReload(text) },
                    onImportShareLink = { uri, _ ->
                        val (next, msg) = workspaceCoordinator.importShareUri(uri, running)
                        workspaceState = next
                        null to msg
                    },
                    onImportSubscription = { name, url ->
                        val (next, msg) = workspaceCoordinator.addAndRefreshSubscription(name, url, running)
                        workspaceState = next
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

    private fun startVpnService() {
        val targetPath = pendingStartConfigPath ?: socketPaths.composedConfigFile.takeIf { it.isFile }?.absolutePath
            ?: configFile.absolutePath
        val intent = Intent(this, NexusVpnService::class.java)
            .setAction(NexusVpnService.ACTION_START)
            .putExtra(NexusVpnService.EXTRA_CONFIG_PATH, targetPath)
            .putExtra(NexusVpnService.EXTRA_FAKE_IPV6_POOL, pendingFakeIpv6Pool)
        startForegroundService(intent)
    }

    private fun stopVpnService() {
        startService(Intent(this, NexusVpnService::class.java).setAction(NexusVpnService.ACTION_STOP))
    }

    private fun restartVpnService(runMode: AndroidRunMode) {
        if (runMode == AndroidRunMode.VPN) {
            val prep = VpnService.prepare(this)
            if (prep != null) {
                vpnPermissionLauncher.launch(prep)
                return
            }
        }
        val targetPath = pendingStartConfigPath ?: socketPaths.composedConfigFile.takeIf { it.isFile }?.absolutePath
            ?: configFile.absolutePath
        val intent = Intent(this, NexusVpnService::class.java)
            .setAction(NexusVpnService.ACTION_RESTART)
            .putExtra(NexusVpnService.EXTRA_CONFIG_PATH, targetPath)
            .putExtra(NexusVpnService.EXTRA_FAKE_IPV6_POOL, pendingFakeIpv6Pool)
        startForegroundService(intent)
    }

    override fun onDestroy() {
        ownerResolver?.close()
        ownerResolver = null
        super.onDestroy()
    }

    private suspend fun resolveOwnerPackage(conn: ActiveConnectionSnapshot): String? = withContext(Dispatchers.IO) {
        val resolver = ownerResolver ?: return@withContext null
        val src = splitHostPort(conn.source) ?: return@withContext null
        val dst = splitHostPort(conn.target) ?: return@withContext null
        if (!InetAddresses.isNumericAddress(src.first) || !InetAddresses.isNumericAddress(dst.first)) return@withContext null
        val proto = if (conn.protocol.contains("udp", ignoreCase = true)) OsConstants.IPPROTO_UDP else OsConstants.IPPROTO_TCP
        val info = runCatching {
            resolver.resolve(proto, InetAddresses.parseNumericAddress(src.first), src.second, InetAddresses.parseNumericAddress(dst.first), dst.second)
        }.getOrNull() ?: return@withContext null
        if (info.packageNames.isNotEmpty()) "${info.packageNames.joinToString(", ")} (UID ${info.uid})" else "UID ${info.uid}"
    }

    private fun splitHostPort(endpoint: String): Pair<String, Int>? {
        val trimmed = endpoint.trim()
        if (trimmed.isEmpty()) return null
        val (host, portStr) = if (trimmed.startsWith("[")) {
            val end = trimmed.indexOf(']')
            if (end <= 1 || end + 2 > trimmed.length || trimmed[end + 1] != ':') return null
            trimmed.substring(1, end) to trimmed.substring(end + 2)
        } else {
            val colon = trimmed.lastIndexOf(':')
            if (colon <= 0) return null
            trimmed.substring(0, colon) to trimmed.substring(colon + 1)
        }
        val port = portStr.toIntOrNull() ?: return null
        return if (port in 1..65535) host to port else null
    }

    companion object {
        private fun androidControlDirective(paths: RuntimeSocketPaths): String {
            val ctrlSock = AndroidKdlBuilder.escapeKdlString(paths.controlSocket.absolutePath)
            val tokenFile = AndroidKdlBuilder.escapeKdlString(paths.controlTokenFile.absolutePath)
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
