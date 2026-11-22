package org.nexus.android.ui

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.system.OsConstants
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.nexus.android.bridge.core.CoreProcessSupervisor
import org.nexus.android.bridge.ipc.ActiveConnectionSnapshot
import org.nexus.android.bridge.ipc.MetricsSummary
import org.nexus.android.bridge.ipc.NexusControlClient
import org.nexus.android.bridge.ipc.OutboundGroupSnapshot
import org.nexus.android.bridge.ipc.OutboundJsonParser
import org.nexus.android.bridge.owner.ConnectionOwnerResolver
import org.nexus.android.bridge.profile.ProfileRepository
import org.nexus.android.bridge.share.ShareLinkParser
import org.nexus.android.bridge.vpn.NexusVpnService
import java.io.File
import java.net.InetAddress

class MainActivity : ComponentActivity() {
    private lateinit var configFile: File
    private lateinit var profiles: ProfileRepository
    private lateinit var supervisor: CoreProcessSupervisor
    private lateinit var controlClient: NexusControlClient
    private var ownerResolver: ConnectionOwnerResolver? = null

    private val vpnPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) startVpnService()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)

        configFile = File(filesDir, "config.kdl")
        profiles = ProfileRepository(filesDir)
        if (!configFile.exists()) configFile.writeText(DEFAULT_ANDROID_KDL)

        supervisor = CoreProcessSupervisor(this)
        controlClient = NexusControlClient(
            unixSocketPath = File(noBackupFilesDir, "control.sock").absolutePath,
            httpBaseUrl = "http://127.0.0.1:9090",
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ownerResolver = ConnectionOwnerResolver(applicationContext).apply { start() }
        }
        val prefs = getSharedPreferences("nexus_prefs", Context.MODE_PRIVATE)

        setContent {
            MaterialTheme {
                var excluded by remember {
                    mutableStateOf(prefs.getStringSet("excluded_packages", emptySet()).orEmpty().toSet())
                }
                NexusRootScreen(
                    initialKdl = remember { configFile.readText() },
                    excludedPackages = excluded,
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
                    onStartStop = { running -> if (running) stopVpnService() else requestAndStartVpn() },
                    onValidateKdl = { text -> validateDraft(text) },
                    onSaveAndReload = { text -> saveAndReload(text) },
                    onImportShareLink = { uri, currentKdl -> importShareLink(uri, currentKdl) },
                    onImportSubscription = { name, url -> importSubscription(name, url) },
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
                                "[${e.level}] ${e.domain}: ${e.message}"
                            }
                        } else {
                            emptyList()
                        }
                    },
                )
            }
        }
    }

    private suspend fun validateDraft(text: String): Pair<Boolean, String> {
        val draft = File(cacheDir, ".draft.kdl").apply { writeText(text) }
        val res = supervisor.validateConfig(draft)
        draft.delete()
        return res.ok to res.output
    }

    private suspend fun saveAndReload(text: String): Pair<Boolean, String> {
        val (ok, msg) = validateDraft(text)
        if (!ok) return false to "拒绝保存无效配置: $msg"
        configFile.writeText(text)
        val reload = controlClient.reload()
        return true to if (reload.ok) "已校验保存并热重载" else "已保存配置"
    }

    private fun importShareLink(uri: String, currentKdl: String): Pair<String, String> {
        val parsed = ShareLinkParser.parse(uri).getOrElse { return currentKdl to "解析失败: ${it.message}" }
        val secretFile = profiles.writeSecret(parsed.tag, parsed.secret)
        val block = ShareLinkParser.renderKdlOutbound(parsed, secretFile.absolutePath)
        return (currentKdl.trimEnd() + "\n\n" + block) to "已导入节点 ${parsed.tag}（凭据已写入 0600 私有文件）"
    }

    private suspend fun importSubscription(name: String, url: String): Pair<String, String> =
        withContext(Dispatchers.IO) {
            val result = profiles.importSubscription(name, url)
            result.fold(
                onSuccess = { p -> p.kdlFile.readText() to "已拉取订阅 ${p.name}（请点击校验并保存重载）" },
                onFailure = { err -> "" to "订阅导入失败: ${err.message}" },
            )
        }

    private fun requestAndStartVpn() {
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

    override fun onDestroy() {
        ownerResolver?.close()
        ownerResolver = null
        super.onDestroy()
    }

    private fun resolveOwnerPackage(conn: ActiveConnectionSnapshot): String? {
        val resolver = ownerResolver ?: return null
        val src = splitHostPort(conn.source) ?: return null
        val dst = splitHostPort(conn.target) ?: return null
        val proto = if (conn.protocol.contains("udp", ignoreCase = true)) {
            OsConstants.IPPROTO_UDP
        } else {
            OsConstants.IPPROTO_TCP
        }
        val info = runCatching {
            resolver.resolve(
                proto,
                InetAddress.getByName(src.first),
                src.second,
                InetAddress.getByName(dst.first),
                dst.second,
            )
        }.getOrNull() ?: return null
        return if (info.packageNames.isNotEmpty()) {
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
        private val DEFAULT_ANDROID_KDL = """
            schema-version 1
            role "client"
            workers 2
            inbound "local" type="socks5" {
                listen host="127.0.0.1" port=10808
                authentication "none"
            }
            outbound "direct" type="direct"
            routing { default-outbound "direct"; }
        """.trimIndent() + "\n"
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun NexusRootScreen(
    initialKdl: String,
    excludedPackages: Set<String>,
    onToggleExcluded: (String, Boolean) -> Unit,
    onStartStop: (Boolean) -> Unit,
    onValidateKdl: suspend (String) -> Pair<Boolean, String>,
    onSaveAndReload: suspend (String) -> Pair<Boolean, String>,
    onImportShareLink: (String, String) -> Pair<String, String>,
    onImportSubscription: suspend (String, String) -> Pair<String, String>,
    onRefreshMetrics: suspend () -> MetricsSummary,
    onClearCache: suspend () -> Boolean,
    onFetchGroups: suspend () -> List<OutboundGroupSnapshot>,
    onFetchConnections: suspend () -> List<ActiveConnectionSnapshot>,
    onInspectConnection: suspend (Long) -> ActiveConnectionSnapshot?,
    onResolveOwnerPackage: (ActiveConnectionSnapshot) -> String?,
    onCloseConnection: suspend (Long) -> Boolean,
    onCloseAllConnections: suspend () -> Boolean,
    onSelectMember: suspend (String, String) -> Boolean,
    onResetAuto: suspend (String) -> Boolean,
    onProbeGroup: suspend (String) -> Boolean,
    onFetchLogs: suspend (String, String) -> List<String>,
    onShareLogs: (String) -> Unit,
) {
    val running by NexusVpnService.runningState.collectAsState()
    val powerSave by NexusVpnService.powerSaveMode.collectAsState()
    val localLogs by NexusVpnService.recentLogs.collectAsState()
    var ringLogs by remember { mutableStateOf<List<String>>(emptyList()) }
    var logSearch by remember { mutableStateOf("") }
    var logLevel by remember { mutableStateOf("trace") }
    val scope = rememberCoroutineScope()
    val useRail = LocalConfiguration.current.screenWidthDp >= 600

    var selectedTab by remember { mutableIntStateOf(0) }
    var kdlText by remember { mutableStateOf(initialKdl) }
    var diagnostic by remember { mutableStateOf("") }
    var metrics by remember { mutableStateOf(MetricsSummary()) }
    val tabs = listOf("概览", "策略组", "连接", "分应用", "配置", "日志")

    Scaffold(
        topBar = { TopAppBar(title = { Text("Nexus") }) },
        bottomBar = {
            if (!useRail) {
                NavigationBar {
                    tabs.forEachIndexed { idx, label ->
                        NavigationBarItem(
                            selected = selectedTab == idx,
                            onClick = { selectedTab = idx },
                            icon = { Text(label.take(1)) },
                            label = { Text(label) },
                        )
                    }
                }
            }
        },
    ) { innerPadding ->
        Row(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .consumeWindowInsets(innerPadding)
                .imePadding(),
        ) {
            if (useRail) {
                NavigationRail(modifier = Modifier.fillMaxHeight()) {
                    tabs.forEachIndexed { idx, label ->
                        NavigationRailItem(
                            selected = selectedTab == idx,
                            onClick = { selectedTab = idx },
                            icon = { Text(label.take(1)) },
                            label = { Text(label) },
                        )
                    }
                }
            }
            Column(
                modifier = Modifier.weight(1f).fillMaxHeight().padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                when (selectedTab) {
                    0 -> Card(modifier = Modifier.fillMaxWidth()) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Text(
                                when {
                                    running && powerSave -> "隧道运行中（省电待机）"
                                    running -> "隧道运行中"
                                    else -> "隧道已停止"
                                },
                                style = MaterialTheme.typography.titleMedium,
                            )
                            Text("代次: ${metrics.controlGeneration} · 活跃会话: ${metrics.activeSessions}")
                            Text("上行: ${metrics.uploadBytes / 1024} KiB · 下行: ${metrics.downloadBytes / 1024} KiB")
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(onClick = { onStartStop(running) }) { Text(if (running) "断开" else "连接") }
                                OutlinedButton(onClick = { scope.launch { metrics = onRefreshMetrics() } }) { Text("刷新") }
                                OutlinedButton(onClick = {
                                    scope.launch { diagnostic = if (onClearCache()) "缓存已清空" else "清空失败" }
                                }) { Text("清缓存") }
                            }
                            if (diagnostic.isNotEmpty()) Text(diagnostic)
                        }
                    }
                    1 -> GroupsScreen(onFetchGroups, onSelectMember, onResetAuto, onProbeGroup)
                    2 -> ConnectionsScreen(
                        onFetchConnections = onFetchConnections,
                        onInspectConnection = onInspectConnection,
                        onResolveOwnerPackage = onResolveOwnerPackage,
                        onCloseConnection = onCloseConnection,
                        onCloseAllConnections = onCloseAllConnections,
                    )
                    3 -> SplitTunnelScreen(excludedPackages, onToggleExcluded)
                    4 -> ConfigScreen(
                        kdlText = kdlText,
                        onKdlChange = { kdlText = it },
                        diagnostic = diagnostic,
                        onDiagnosticChange = { diagnostic = it },
                        onImportShareLink = onImportShareLink,
                        onImportSubscription = onImportSubscription,
                        onValidateKdl = onValidateKdl,
                        onSaveAndReload = onSaveAndReload,
                    )
                    else -> Column(modifier = Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        val displayLogs = if (ringLogs.isNotEmpty()) ringLogs else localLogs
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            androidx.compose.material3.OutlinedTextField(
                                value = logSearch,
                                onValueChange = { logSearch = it },
                                modifier = Modifier.weight(1f),
                                singleLine = true,
                                label = { Text("过滤日志") },
                            )
                            OutlinedButton(onClick = {
                                scope.launch { ringLogs = onFetchLogs(logLevel, logSearch) }
                            }) { Text("刷新") }
                            OutlinedButton(
                                enabled = displayLogs.isNotEmpty(),
                                onClick = { onShareLogs(displayLogs.joinToString("\n")) },
                            ) { Text("导出") }
                        }
                        LazyColumn(modifier = Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            items(displayLogs) { line -> Text(line, style = MaterialTheme.typography.bodySmall) }
                        }
                    }
                }
            }
        }
    }
}
