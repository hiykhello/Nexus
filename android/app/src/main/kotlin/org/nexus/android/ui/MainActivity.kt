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
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.nexus.android.bridge.core.CoreProcessSupervisor
import org.nexus.android.bridge.ipc.ActiveConnectionSnapshot
import org.nexus.android.bridge.ipc.NexusControlClient
import org.nexus.android.bridge.ipc.OutboundJsonParser
import org.nexus.android.bridge.model.AndroidKdlBuilder
import org.nexus.android.bridge.model.AndroidKdlOps
import org.nexus.android.bridge.model.RuntimeSocketPaths
import org.nexus.android.bridge.model.ShareLinkParser
import org.nexus.android.bridge.owner.ConnectionOwnerResolver
import org.nexus.android.bridge.profile.ProfileRepository
import org.nexus.android.bridge.vpn.NexusVpnService
import org.nexus.android.ui.theme.NexusTheme
import java.io.File

class MainActivity : ComponentActivity() {
    private lateinit var configFile: File
    private lateinit var socketPaths: RuntimeSocketPaths
    private lateinit var profiles: ProfileRepository
    private lateinit var supervisor: CoreProcessSupervisor
    private lateinit var controlClient: NexusControlClient
    private var ownerResolver: ConnectionOwnerResolver? = null
    private var askedNotificationPermission = false

    private val vpnPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) startVpnService()
        }

    private val notificationPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { _ ->
            // Proceed to start VPN even if notifications were denied; foreground service still runs.
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
            bearerTokenProvider = {
                socketPaths.controlTokenFile.takeIf { it.isFile }?.readText()?.trim()
            },
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ownerResolver = ConnectionOwnerResolver(applicationContext).apply { start() }
        }
        val prefs = getSharedPreferences("nexus_prefs", Context.MODE_PRIVATE)

        setContent {
            NexusTheme {
                var excluded by remember {
                    mutableStateOf(prefs.getStringSet("excluded_packages", emptySet()).orEmpty().toSet())
                }
                var dashVisibility by remember { mutableStateOf(DashboardLayoutPrefs.load(prefs)) }
                var loadedKdl by remember { mutableStateOf("") }
                var profileChips by remember { mutableStateOf<List<UiProfileChip>>(emptyList()) }
                var activeProfileName by remember { mutableStateOf("默认配置") }

                suspend fun refreshProfilesState() {
                    val (chips, activeName) = loadProfileChips()
                    profileChips = chips
                    activeProfileName = activeName
                }

                LaunchedEffect(configFile) {
                    loadedKdl = withContext(Dispatchers.IO) {
                        if (!configFile.exists()) writeConfigAtomically(defaultAndroidKdl(socketPaths))
                        configFile.readText()
                    }
                    refreshProfilesState()
                }

                val running by NexusVpnService.runningState.collectAsStateWithLifecycle()
                val tunnelState by NexusVpnService.tunnelState.collectAsStateWithLifecycle()
                val startedAtMs by NexusVpnService.startedAtMs.collectAsStateWithLifecycle()
                val lastError by NexusVpnService.lastError.collectAsStateWithLifecycle()
                val powerSave by NexusVpnService.powerSaveMode.collectAsStateWithLifecycle()
                val rawLocalLogs by NexusVpnService.recentLogs.collectAsStateWithLifecycle()
                val localLogs = remember(rawLocalLogs) {
                    rawLocalLogs.map { UiLogLine(seq = -it.seq, text = it.text) }
                }

                NexusRootScreen(
                    running = running,
                    tunnelState = tunnelState,
                    startedAtMs = startedAtMs,
                    lastError = lastError,
                    powerSave = powerSave,
                    localLogs = localLogs,
                    initialKdl = loadedKdl,
                    profiles = profileChips,
                    activeProfileName = activeProfileName,
                    excludedPackages = excluded,
                    dashVisibility = dashVisibility,
                    onDashVisibilityChange = { next ->
                        dashVisibility = next
                        DashboardLayoutPrefs.save(prefs, next)
                    },
                    onShareLogs = { text ->
                        val shareIntent = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(Intent.EXTRA_SUBJECT, "Nexus 运行日志")
                            putExtra(Intent.EXTRA_TEXT, text)
                        }
                        startActivity(Intent.createChooser(shareIntent, "导出日志"))
                    },
                    onToggleExcluded = { pkg, isExcluded ->
                        val next = if (isExcluded) excluded + pkg else excluded - pkg
                        excluded = next
                        prefs.edit().putStringSet("excluded_packages", next).apply()
                    },
                    onStartStop = { isRunning -> if (isRunning) stopVpnService() else requestAndStartVpn() },
                    onRestartVpn = { restartVpnService() },
                    onSwitchOutboundMode = { mode, currentKdl -> switchOutboundMode(mode, currentKdl) },
                    onCreateRuleFromConnection = { host, action, outbound, currentKdl ->
                        createRuleFromConnection(host, action, outbound, currentKdl)
                    },
                    onSwitchProfile = { profileId ->
                        val result = switchProfile(profileId)
                        refreshProfilesState()
                        result
                    },
                    onSaveProfileSnapshot = { name, kdl ->
                        val note = saveProfileSnapshot(name, kdl)
                        refreshProfilesState()
                        note
                    },
                    onValidateKdl = { text -> validateDraft(text) },
                    onSaveAndReload = { text -> saveAndReload(text) },
                    onImportShareLink = { uri, currentKdl -> importShareLink(uri, currentKdl) },
                    onImportSubscription = { name, url ->
                        val result = importSubscription(name, url)
                        refreshProfilesState()
                        result
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
                        } else {
                            emptyList()
                        }
                    },
                )
            }
        }
    }

    private suspend fun loadProfileChips(): Pair<List<UiProfileChip>, String> = withContext(Dispatchers.IO) {
        val list = profiles.listProfiles()
        val activeId = profiles.activeProfileId()
        val chips = list.map { p ->
            UiProfileChip(id = p.id, name = p.name, active = p.id == activeId)
        }
        val activeLabel = list.firstOrNull { it.id == activeId }?.name ?: "默认配置"
        chips to activeLabel
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
            if (!tmp.renameTo(configFile)) {
                throw java.io.IOException("Atomic rename failed for ${configFile.name}")
            }
        } catch (t: Throwable) {
            runCatching { tmp.delete() }
            throw t
        }
    }

    private suspend fun saveAndReload(text: String): Pair<Boolean, String> {
        val (ok, msg) = validateDraft(text)
        if (!ok) return false to "拒绝保存无效配置: $msg"
        val writeErr = withContext(Dispatchers.IO) {
            runCatching { writeConfigAtomically(text) }.exceptionOrNull()
        }
        if (writeErr != null) {
            return false to "保存配置失败: ${writeErr.message ?: writeErr.javaClass.simpleName}"
        }
        val reload = controlClient.reload()
        return true to if (reload.ok) "已校验保存并热重载" else "已保存配置"
    }

    private suspend fun switchOutboundMode(mode: String, currentKdl: String): Pair<String?, String> {
        val (applied, nextOrErr) = AndroidKdlOps.applyOutboundMode(currentKdl, mode)
        if (!applied) return null to nextOrErr
        val (saved, msg) = saveAndReload(nextOrErr)
        val label = when (mode) {
            "global" -> "全局代理"
            "direct" -> "直连放行"
            else -> "规则分流"
        }
        return if (saved) nextOrErr to "已切换至$label（$msg）" else null to msg
    }

    private suspend fun createRuleFromConnection(
        targetHost: String,
        action: String,
        outbound: String,
        currentKdl: String,
    ): Pair<String?, String> {
        val resolvedOutbound = if (action == "route" && outbound == "proxy") {
            AndroidKdlOps.extractProxyGroupName(currentKdl)
        } else {
            outbound
        }
        val ruleBlock = AndroidKdlOps.buildQuickRouteRule(targetHost, action, resolvedOutbound)
        val (inserted, nextOrErr) = AndroidKdlOps.insertRouteRule(currentKdl, ruleBlock)
        if (!inserted) return null to "创建规则失败: $nextOrErr"
        val (saved, msg) = saveAndReload(nextOrErr)
        return if (saved) nextOrErr to "已为 $targetHost 创建规则（$msg）" else null to msg
    }

    private suspend fun switchProfile(profileId: String): Pair<String?, String> {
        val rawKdl = withContext(Dispatchers.IO) {
            profiles.listProfiles().firstOrNull { it.id == profileId }?.kdlFile?.takeIf { it.isFile }?.readText()
        } ?: return null to "未找到档案 $profileId"
        val withControl = ensureControlDirective(rawKdl)
        val (saved, msg) = saveAndReload(withControl)
        if (saved) {
            withContext(Dispatchers.IO) { profiles.setActiveProfile(profileId) }
            return withControl to "已切换档案 $profileId（$msg）"
        }
        return null to msg
    }

    private suspend fun saveProfileSnapshot(name: String, kdl: String): String = withContext(Dispatchers.IO) {
        val saved = profiles.saveProfile(name, ensureControlDirective(kdl))
        profiles.setActiveProfile(saved.id)
        "已保存配置档案 ${saved.name}"
    }

    private fun ensureControlDirective(kdl: String): String {
        if (kdl.contains("control ") && kdl.contains("bearer-token-file")) return kdl
        val directive = androidControlDirective(socketPaths)
        return if (kdl.startsWith("schema-version")) {
            val firstNl = kdl.indexOf('\n')
            if (firstNl > 0) {
                kdl.substring(0, firstNl + 1) + directive + "\n" + kdl.substring(firstNl + 1)
            } else {
                "$kdl\n$directive\n"
            }
        } else {
            "$directive\n$kdl"
        }
    }

    private suspend fun importShareLink(uri: String, currentKdl: String): Pair<String?, String> {
        val (candidate, importedTag, hasSecret) = withContext(Dispatchers.IO) {
            val parsed = ShareLinkParser.parse(uri).getOrElse {
                return@withContext Triple(null, "解析失败: ${it.message}", false)
            }
            val secretPath = if (parsed.secret.isNotEmpty()) {
                profiles.writeSecret(parsed.tag, parsed.secret).absolutePath
            } else {
                ""
            }
            val block = ShareLinkParser.renderKdlOutbound(parsed, secretPath)
            Triple(currentKdl.trimEnd() + "\n\n" + block, parsed.tag, secretPath.isNotEmpty())
        }
        if (candidate == null) return null to importedTag
        val (saved, saveMsg) = saveAndReload(candidate)
        if (!saved) return null to saveMsg
        val detail = if (hasSecret) "凭据已保护，$saveMsg" else saveMsg
        return candidate to "已导入节点 $importedTag（$detail）"
    }

    private suspend fun importSubscription(name: String, url: String): Pair<String, String> {
        val imported = withContext(Dispatchers.IO) {
            profiles.importSubscription(
                name = name,
                urlString = url,
                controlDirective = androidControlDirective(socketPaths),
            )
        }
        return imported.fold(
            onSuccess = { p ->
                val text = withContext(Dispatchers.IO) { p.kdlFile.readText() }
                val (saved, saveMsg) = saveAndReload(text)
                if (saved) {
                    withContext(Dispatchers.IO) { profiles.setActiveProfile(p.id) }
                    text to "已拉取并应用订阅 ${p.name}（$saveMsg）"
                } else {
                    "" to "订阅已拉取但校验失败: $saveMsg"
                }
            },
            onFailure = { err -> "" to "订阅导入失败: ${err.message}" },
        )
    }

    private fun requestAndStartVpn() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !askedNotificationPermission) {
            val granted = ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                askedNotificationPermission = true
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                return
            }
        }
        launchVpnConsentOrStart()
    }

    private fun launchVpnConsentOrStart() {
        val prep = VpnService.prepare(this)
        if (prep != null) vpnPermissionLauncher.launch(prep) else startVpnService()
    }

    private fun startVpnService() {
        val prefs = getSharedPreferences("nexus_prefs", Context.MODE_PRIVATE)
        val excluded = ArrayList(prefs.getStringSet("excluded_packages", emptySet()).orEmpty())
        val intent = Intent(this, NexusVpnService::class.java)
            .setAction(NexusVpnService.ACTION_START)
            .putExtra(NexusVpnService.EXTRA_CONFIG_PATH, configFile.absolutePath)
            .putStringArrayListExtra(NexusVpnService.EXTRA_EXCLUDED_PACKAGES, excluded)
        startForegroundService(intent)
    }

    private fun stopVpnService() {
        startService(Intent(this, NexusVpnService::class.java).setAction(NexusVpnService.ACTION_STOP))
    }

    private fun restartVpnService() {
        val prep = VpnService.prepare(this)
        if (prep != null) {
            vpnPermissionLauncher.launch(prep)
            return
        }
        val prefs = getSharedPreferences("nexus_prefs", Context.MODE_PRIVATE)
        val excluded = ArrayList(prefs.getStringSet("excluded_packages", emptySet()).orEmpty())
        val intent = Intent(this, NexusVpnService::class.java)
            .setAction(NexusVpnService.ACTION_RESTART)
            .putExtra(NexusVpnService.EXTRA_CONFIG_PATH, configFile.absolutePath)
            .putStringArrayListExtra(NexusVpnService.EXTRA_EXCLUDED_PACKAGES, excluded)
        startForegroundService(intent)
    }

    override fun onDestroy() {
        ownerResolver?.close()
        ownerResolver = null
        super.onDestroy()
    }

    private suspend fun resolveOwnerPackage(conn: ActiveConnectionSnapshot): String? =
        withContext(Dispatchers.IO) {
            val resolver = ownerResolver ?: return@withContext null
            val src = splitHostPort(conn.source) ?: return@withContext null
            val dst = splitHostPort(conn.target) ?: return@withContext null
            if (!InetAddresses.isNumericAddress(src.first) || !InetAddresses.isNumericAddress(dst.first)) {
                return@withContext null
            }
            val proto = if (conn.protocol.contains("udp", ignoreCase = true)) {
                OsConstants.IPPROTO_UDP
            } else {
                OsConstants.IPPROTO_TCP
            }
            val info = runCatching {
                resolver.resolve(
                    proto,
                    InetAddresses.parseNumericAddress(src.first),
                    src.second,
                    InetAddresses.parseNumericAddress(dst.first),
                    dst.second,
                )
            }.getOrNull() ?: return@withContext null
            if (info.packageNames.isNotEmpty()) {
                "${info.packageNames.joinToString(", ")} (UID ${info.uid})"
            } else {
                "UID ${info.uid}"
            }
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

        private fun defaultAndroidKdl(paths: RuntimeSocketPaths): String {
            val controlLine = androidControlDirective(paths)
            return """
                schema-version 1
                role "client"
                workers 2
                $controlLine
                inbound "local" type="socks5" {
                    listen host="127.0.0.1" port=10808
                    authentication "none"
                }
                outbound "direct" type="direct"
                routing { default-outbound "direct"; }
            """.trimIndent() + "\n"
        }
    }
}
