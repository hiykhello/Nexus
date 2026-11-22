package org.nexus.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.nexus.android.apps.InstalledAppsRepository
import org.nexus.android.bridge.model.VpnState
import org.nexus.android.bridge.uds.ControlSocketClient
import org.nexus.android.bridge.vpn.VpnRuntimeStatus
import org.nexus.android.data.ProfileRepository

@Composable
fun DashboardScreen(
    statusFlow: StateFlow<VpnRuntimeStatus>,
    controlClient: ControlSocketClient,
    profileRepository: ProfileRepository,
    appsRepository: InstalledAppsRepository,
    onStartRequested: () -> Unit,
    onStopRequested: () -> Unit,
) {
    val status by statusFlow.collectAsState()
    var activeTab by remember { mutableIntStateOf(0) }

    Scaffold(
        contentWindowInsets = WindowInsets.safeDrawing,
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = activeTab == 0,
                    onClick = { activeTab = 0 },
                    icon = { Text("●") },
                    label = { Text("概览") },
                )
                NavigationBarItem(
                    selected = activeTab == 1,
                    onClick = { activeTab = 1 },
                    icon = { Text("≡") },
                    label = { Text("配置") },
                )
                NavigationBarItem(
                    selected = activeTab == 2,
                    onClick = { activeTab = 2 },
                    icon = { Text("⊞") },
                    label = { Text("分应用") },
                )
            }
        },
    ) { padding ->
        val contentModifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .consumeWindowInsets(padding)

        when (activeTab) {
            0 -> OverviewPane(
                status = status,
                controlClient = controlClient,
                onStartRequested = onStartRequested,
                onStopRequested = onStopRequested,
                modifier = contentModifier,
            )
            1 -> KdlProfilePane(
                profileRepository = profileRepository,
                controlClient = controlClient,
                vpnRunning = status.state == VpnState.RUNNING,
                modifier = contentModifier,
            )
            else -> SplitTunnelingPane(
                appsRepository = appsRepository,
                profileRepository = profileRepository,
                modifier = contentModifier,
            )
        }
    }
}

@Composable
private fun OverviewPane(
    status: VpnRuntimeStatus,
    controlClient: ControlSocketClient,
    onStartRequested: () -> Unit,
    onStopRequested: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val isActive = status.state == VpnState.RUNNING || status.state == VpnState.STARTING

    Column(
        modifier = modifier
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(text = "Nexus Android", style = MaterialTheme.typography.headlineMedium)

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(text = "状态: ${status.state.name}", style = MaterialTheme.typography.titleMedium)
                if (status.interfaceName != null) {
                    Text(text = "物理网口: ${status.interfaceName} (MTU ${status.mtu})")
                    Text(text = "物理 DNS: ${status.dnsServers.ifEmpty { listOf("无") }.joinToString()}")
                    Text(text = "计费网络: ${if (status.metered) "是" else "否"}")
                } else {
                    Text(text = "等待底层物理网络快照...")
                }
                Spacer(modifier = Modifier.height(4.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Button(onClick = onStartRequested, enabled = !isActive) { Text("启动 VPN") }
                    OutlinedButton(onClick = onStopRequested, enabled = isActive) { Text("停止") }
                }
            }
        }

        if (status.privateDnsWarning.isStrictMode) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        text = "检测到系统严格模式 Private DNS",
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                    Text(
                        text = "当前 DoT 主机: ${status.privateDnsHostname}。非 Root 环境下可能绕过 VPN DNS 劫持或导致 FakeIP 失效，建议在系统网络设置中改为“自动”或“关闭”。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                }
            }
        }

        if (!status.lastError.isNullOrBlank()) {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(text = "最近诊断信息", style = MaterialTheme.typography.titleSmall)
                    Text(text = status.lastError.orEmpty(), style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        RuntimeControlCard(
            controlClient = controlClient,
            enabled = status.state == VpnState.RUNNING,
        )

        OfflineRulesetCard(metered = status.metered)
    }
}

@Composable
private fun KdlProfilePane(
    profileRepository: ProfileRepository,
    controlClient: ControlSocketClient,
    vpnRunning: Boolean,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val loaded by produceState<String?>(initialValue = null, profileRepository) {
        value = profileRepository.loadActiveProfile().config.userKdlConfig
    }
    var draft by remember(loaded) { mutableStateOf(loaded.orEmpty()) }
    var feedback by remember { mutableStateOf("") }

    Column(
        modifier = modifier
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(text = "KDL 2.0 配置", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            value = draft,
            onValueChange = { draft = it },
            label = { Text("用户 KDL 配置（后续可直插 sora-editor 高亮）") },
            minLines = 10,
            modifier = Modifier.fillMaxWidth(),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = {
                scope.launch {
                    profileRepository.saveKdl("default", "默认配置", draft)
                    feedback = if (vpnRunning) {
                        val res = withContext(Dispatchers.IO) { controlClient.reload() }
                        res.fold(onSuccess = { "已保存并热重载" }, onFailure = { "已保存，但重载失败: ${it.message}" })
                    } else {
                        "已原子保存配置"
                    }
                }
            }) {
                Text("保存并热重载")
            }
        }
        if (feedback.isNotEmpty()) {
            Text(text = feedback, style = MaterialTheme.typography.bodySmall)
        }
    }
}
