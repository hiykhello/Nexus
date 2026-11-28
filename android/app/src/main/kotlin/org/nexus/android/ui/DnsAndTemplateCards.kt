package org.nexus.android.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.nexus.android.bridge.workspace.DnsConfig
import org.nexus.android.bridge.workspace.FullTemplateConfig
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

private val FULL_DNS_STRATEGIES = listOf(
    "prefer_ipv4" to "优先 IPv4",
    "prefer_ipv6" to "优先 IPv6",
    "ipv4_only" to "仅 IPv4",
    "ipv6_only" to "仅 IPv6",
)

internal fun formatHostsPairs(hosts: Map<String, String>): String =
    hosts.entries.joinToString(", ") { "${it.key}=${it.value}" }

internal fun parseHostsPairs(raw: String): Map<String, String> =
    raw.split(',', '\n')
        .mapNotNull { entry ->
            val trimmed = entry.trim()
            val eq = trimmed.indexOf('=')
            if (eq <= 0 || eq >= trimmed.lastIndex) null
            else trimmed.substring(0, eq).trim() to trimmed.substring(eq + 1).trim()
        }
        .filter { it.first.isNotEmpty() && it.second.isNotEmpty() }
        .toMap()

/**
 * Full Nexus DNS Card (`SimpleDnsConfig` + `FakeIP` pools/global + `hosts` + advanced raw block).
 */
@Composable
internal fun DnsConfigurationCard(
    state: WorkspaceUiState,
    actions: WorkspaceUiActions,
    onFeedback: (String) -> Unit,
) {
    val scope = rememberCoroutineScope()
    val ext = NexusTheme.colors
    val cur = state.document.dns

    var mode by rememberSaveable(cur.mode) { mutableStateOf(cur.mode) }
    var bootstrap by rememberSaveable(cur.simple.bootstrapDns) { mutableStateOf(cur.simple.bootstrapDns) }
    var directDns by rememberSaveable(cur.simple.directDns) { mutableStateOf(cur.simple.directDns.joinToString(", ")) }
    var remoteDns by rememberSaveable(cur.simple.remoteDns) { mutableStateOf(cur.simple.remoteDns.joinToString(", ")) }
    var strategy by rememberSaveable(cur.simple.strategy) { mutableStateOf(cur.simple.strategy) }
    var parallelQuery by rememberSaveable(cur.simple.parallelQuery) { mutableStateOf(cur.simple.parallelQuery) }
    var fakeIp by rememberSaveable(cur.simple.fakeIpEnabled) { mutableStateOf(cur.simple.fakeIpEnabled) }
    var fakeV4 by rememberSaveable(cur.simple.fakeIpV4Pool) { mutableStateOf(cur.simple.fakeIpV4Pool) }
    var fakeV6 by rememberSaveable(cur.simple.fakeIpV6Pool) { mutableStateOf(cur.simple.fakeIpV6Pool) }
    var fakeGlobal by rememberSaveable(cur.simple.fakeIpGlobal) { mutableStateOf(cur.simple.fakeIpGlobal) }
    var blockAaaa by rememberSaveable(cur.simple.blockAaaa) { mutableStateOf(cur.simple.blockAaaa) }
    var blockSvcb by rememberSaveable(cur.simple.blockSvcbHttps) { mutableStateOf(cur.simple.blockSvcbHttps) }
    var useSysHosts by rememberSaveable(cur.simple.useSystemHosts) { mutableStateOf(cur.simple.useSystemHosts) }
    var hostsText by rememberSaveable(cur.simple.hosts) { mutableStateOf(formatHostsPairs(cur.simple.hosts)) }
    var rawKdl by rememberSaveable(cur.rawKdl) { mutableStateOf(cur.rawKdl) }

    OpticalCard(cornerRadius = 12.dp) {
        Column(modifier = Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("DNS 解析与 FakeIP 引擎", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            OpticalSegmentedControl(
                options = listOf("simple" to "结构化 DNS", "raw_kdl" to "高级自定义 DNS"),
                selectedKey = mode,
                onSelect = { mode = it },
                modifier = Modifier.fillMaxWidth(),
            )

            if (mode == "simple") {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(bootstrap, { bootstrap = it }, label = { Text("引导 DNS (Bootstrap)") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.45f))
                    OutlinedTextField(directDns, { directDns = it }, label = { Text("直连 DNS (逗号分隔)") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.55f))
                }
                OutlinedTextField(remoteDns, { remoteDns = it }, label = { Text("远程代理 DNS (DoH / DoT / DoQ)") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.fillMaxWidth())

                Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    FULL_DNS_STRATEGIES.forEach { (k, l) ->
                        EditorChoiceChip(l, strategy == k) { strategy = k }
                    }
                }

                Surface(shape = RoundedCornerShape(8.dp), color = ext.wellSurface, modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        EditorSwitchRow("启用 FakeIP 极速合成映射", fakeIp) { fakeIp = it }
                        if (fakeIp) {
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                OutlinedTextField(fakeV4, { fakeV4 = it }, label = { Text("IPv4 池") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(1f))
                                OutlinedTextField(fakeV6, { fakeV6 = it }, label = { Text("IPv6 池") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(1f))
                            }
                            EditorSwitchRow("全局 FakeIP (含直连规则域名)", fakeGlobal) { fakeGlobal = it }
                        }
                        HorizontalDivider(color = ext.hairline)
                        EditorSwitchRow("并发双上游竞速查询 (parallel_query)", parallelQuery) { parallelQuery = it }
                        HorizontalDivider(color = ext.hairline)
                        EditorSwitchRow("屏蔽 AAAA (IPv6) 查询", blockAaaa) { blockAaaa = it }
                        HorizontalDivider(color = ext.hairline)
                        EditorSwitchRow("屏蔽 HTTPS / SVCB 记录", blockSvcb) { blockSvcb = it }
                        HorizontalDivider(color = ext.hairline)
                        EditorSwitchRow("读取系统 /etc/hosts", useSysHosts) { useSysHosts = it }
                    }
                }

                OutlinedTextField(
                    value = hostsText,
                    onValueChange = { hostsText = it },
                    label = { Text("自定义静态 Hosts (domain=ip, 逗号分隔)") },
                    placeholder = { Text("router.local=192.168.1.1, nas.lan=10.0.0.2") },
                    shape = RoundedCornerShape(8.dp),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            } else {
                OutlinedTextField(
                    value = rawKdl,
                    onValueChange = { rawKdl = it },
                    label = { Text("自定义 DNS 配置块") },
                    textStyle = NexusNumericStyles.codeBlock,
                    shape = RoundedCornerShape(8.dp),
                    minLines = 5,
                    maxLines = 9,
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            Button(
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.fillMaxWidth().heightIn(min = 46.dp),
                onClick = {
                    val next = DnsConfig(
                        mode = mode,
                        simple = cur.simple.copy(
                            bootstrapDns = bootstrap.trim().ifEmpty { "223.5.5.5" },
                            directDns = directDns.split(',').map { it.trim() }.filter { it.isNotEmpty() }.ifEmpty { listOf("local") },
                            remoteDns = remoteDns.split(',').map { it.trim() }.filter { it.isNotEmpty() }.ifEmpty { listOf("https://1.1.1.1/dns-query") },
                            parallelQuery = parallelQuery,
                            fakeIpEnabled = fakeIp,
                            fakeIpV4Pool = fakeV4.trim().ifEmpty { "198.18.0.0/16" },
                            fakeIpV6Pool = fakeV6.trim().ifEmpty { "fc00::/18" },
                            fakeIpGlobal = fakeGlobal,
                            blockAaaa = blockAaaa,
                            blockSvcbHttps = blockSvcb,
                            useSystemHosts = useSysHosts,
                            hosts = parseHostsPairs(hostsText),
                            strategy = strategy,
                        ),
                        rawKdl = rawKdl,
                    )
                    scope.launch { onFeedback(actions.onUpdateDns(next)) }
                },
            ) { Text("保存 DNS 配置", fontWeight = FontWeight.Bold) }
        }
    }
}

/**
 * Global Configuration Template (`全局配置覆盖模板`) Card.
 */
@Composable
internal fun FullTemplateCard(
    state: WorkspaceUiState,
    actions: WorkspaceUiActions,
    onFeedback: (String) -> Unit,
) {
    val scope = rememberCoroutineScope()
    val ext = NexusTheme.colors
    val cur = state.document.fullTemplate

    var enabled by rememberSaveable(cur.enabled) { mutableStateOf(cur.enabled) }
    var appendOnly by rememberSaveable(cur.appendProxiesOnly) { mutableStateOf(cur.appendProxiesOnly) }
    var detour by rememberSaveable(cur.proxyDetour) { mutableStateOf(cur.proxyDetour) }
    var tplText by rememberSaveable(cur.templateKdl) { mutableStateOf(cur.templateKdl) }

    OpticalCard(cornerRadius = 12.dp) {
        Column(modifier = Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("全局配置模板", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Surface(shape = RoundedCornerShape(8.dp), color = ext.wellSurface, modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    EditorSwitchRow("启用全局配置模板覆盖", enabled) { enabled = it }
                    HorizontalDivider(color = ext.hairline)
                    EditorSwitchRow("仅向模板追加工作区节点 (append_proxies_only)", appendOnly) { appendOnly = it }
                }
            }
            if (enabled) {
                OutlinedTextField(detour, { detour = it }, label = { Text("统一前置代理标签 (proxy_detour，可选)") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(tplText, { tplText = it }, label = { Text("全局模板配置文本") }, textStyle = NexusNumericStyles.codeBlock, shape = RoundedCornerShape(8.dp), minLines = 4, maxLines = 8, modifier = Modifier.fillMaxWidth())
            }
            Button(
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.fillMaxWidth().heightIn(min = 46.dp),
                onClick = {
                    val next = FullTemplateConfig(enabled = enabled, templateKdl = tplText, appendProxiesOnly = appendOnly, proxyDetour = detour.trim())
                    scope.launch { onFeedback(actions.onUpdateFullTemplate(next)) }
                },
            ) { Text("保存全局模板", fontWeight = FontWeight.Bold) }
        }
    }
}
