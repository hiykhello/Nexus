package org.nexus.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.nexus.android.bridge.workspace.NodeConfig
import org.nexus.android.bridge.workspace.NodeExtraConfig
import org.nexus.android.bridge.workspace.NodeMultiplexConfig
import org.nexus.android.bridge.workspace.NodeTlsConfig
import org.nexus.android.bridge.workspace.NodeTransportConfig
import org.nexus.android.ui.theme.NexusTheme

internal val ALL_NEXUS_PROTOCOLS = listOf(
    "vless" to "VLESS",
    "trojan" to "Trojan",
    "hysteria2" to "Hysteria2",
    "tuic" to "TUIC",
    "wireguard" to "WireGuard",
    "masque" to "MASQUE",
    "shadowsocks" to "Shadowsocks",
    "anytls" to "AnyTLS",
    "naive" to "Naive",
    "snell" to "Snell",
    "ssh" to "SSH",
    "socks5" to "SOCKS5",
    "http-connect" to "HTTP",
)

private val SS_METHODS = listOf(
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
)

private val UTLS_FINGERPRINTS = listOf("" to "默认", "chrome" to "Chrome", "firefox" to "Firefox", "safari" to "Safari", "ios" to "iOS", "android" to "Android", "randomized" to "随机")
private val PQ_KEMS = listOf("" to "默认曲线", "x25519-mlkem768" to "X25519-MLKEM768 (抗量子)", "x25519" to "X25519", "secp256r1" to "P-256")
private val TRANSPORTS = listOf("" to "TCP", "ws" to "WebSocket", "grpc" to "gRPC", "httpupgrade" to "HTTPUpgrade", "xhttp" to "XHTTP")
private val MUX_PROTOS = listOf("h2mux", "smux-v2", "smux-v1")

/**
 * Complete multi-protocol NodeConfig form covering all 13 Nexus outbound protocols,
 * TLS / REALITY / ECH / Post-Quantum KEM / Fragment, 5 transports, and 3 multiplexers.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun NodeProtocolFields(
    node: NodeConfig,
    onChange: (NodeConfig) -> Unit,
) {
    val ext = NexusTheme.colors
    val proto = if (node.protocol == "http") "http-connect" else node.protocol.lowercase()
    val usesTls = proto !in setOf("wireguard", "shadowsocks", "snell", "ssh")
    val usesTransport = proto in setOf("vless", "trojan", "shadowsocks", "socks5", "http-connect", "anytls")
    val usesMux = proto in setOf("vless", "trojan", "shadowsocks", "anytls", "socks5", "http-connect")

    Text("出站协议 (13 种 Nexus 原生协议)", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurfaceVariant)
    FlowRow(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        ALL_NEXUS_PROTOCOLS.forEach { (key, label) ->
            EditorChoiceChip(label, selected = proto == key) {
                val defaultPort = if (key == "wireguard") 51820 else if (key == "ssh") 22 else if (key == "socks5") 1080 else 443
                onChange(node.copy(protocol = key, port = if (node.port <= 0) defaultPort else node.port))
            }
        }
    }

    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            value = node.server,
            onValueChange = { onChange(node.copy(server = it)) },
            label = { Text("服务器地址") },
            placeholder = { Text("edge.example.com") },
            shape = RoundedCornerShape(8.dp),
            singleLine = true,
            modifier = Modifier.weight(0.68f),
        )
        OutlinedTextField(
            value = if (node.port > 0) "${node.port}" else "",
            onValueChange = { raw -> onChange(node.copy(port = raw.filter(Char::isDigit).toIntOrNull()?.coerceIn(1, 65535) ?: 0)) },
            label = { Text("端口") },
            shape = RoundedCornerShape(8.dp),
            singleLine = true,
            modifier = Modifier.weight(0.32f),
        )
    }

    when (proto) {
        "vless" -> {
            OutlinedTextField(node.password, { onChange(node.copy(password = it)) }, label = { Text("UUID") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.fillMaxWidth())
            Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                EditorChoiceChip("无流控", node.flow.isEmpty()) { onChange(node.copy(flow = "")) }
                EditorChoiceChip("xtls-rprx-vision", node.flow == "xtls-rprx-vision") { onChange(node.copy(flow = "xtls-rprx-vision")) }
                EditorChoiceChip("UDP: xudp", node.packetEncoding.ifBlank { "xudp" } == "xudp") { onChange(node.copy(packetEncoding = "xudp")) }
                EditorChoiceChip("UDP: packetaddr", node.packetEncoding == "packetaddr") { onChange(node.copy(packetEncoding = "packetaddr")) }
            }
        }
        "trojan", "anytls" -> {
            OutlinedTextField(node.password, { onChange(node.copy(password = it)) }, label = { Text("认证密码") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.fillMaxWidth())
        }
        "hysteria2" -> {
            OutlinedTextField(node.password, { onChange(node.copy(password = it)) }, label = { Text("认证密码") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.fillMaxWidth())
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(node.extra.hy2Ports, { onChange(node.copy(extra = node.extra.copy(hy2Ports = it))) }, label = { Text("跳跃端口 (如 20000-40000)") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.6f))
                OutlinedTextField(node.extra.hy2HopIntervalMs.takeIf { it > 0 }?.toString().orEmpty(), { onChange(node.copy(extra = node.extra.copy(hy2HopIntervalMs = it.filter(Char::isDigit).toIntOrNull() ?: 0))) }, label = { Text("跳跃间隔 ms") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.4f))
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(node.extra.hy2UpMbps.takeIf { it > 0 }?.toString().orEmpty(), { onChange(node.copy(extra = node.extra.copy(hy2UpMbps = it.filter(Char::isDigit).toIntOrNull() ?: 0))) }, label = { Text("上行 Mbps") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.35f))
                OutlinedTextField(node.extra.hy2DownMbps.takeIf { it > 0 }?.toString().orEmpty(), { onChange(node.copy(extra = node.extra.copy(hy2DownMbps = it.filter(Char::isDigit).toIntOrNull() ?: 0))) }, label = { Text("下行 Mbps") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.35f))
                OutlinedTextField(node.extra.hy2SalamanderPassword, { onChange(node.copy(extra = node.extra.copy(hy2SalamanderPassword = it))) }, label = { Text("Salamander") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.3f))
            }
        }
        "tuic" -> {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(node.username, { onChange(node.copy(username = it)) }, label = { Text("UUID") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(1f))
                OutlinedTextField(node.password, { onChange(node.copy(password = it)) }, label = { Text("密码") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(1f))
            }
            Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                listOf("bbr", "cubic", "new_reno").forEach { cc ->
                    EditorChoiceChip("拥塞: $cc", node.extra.tuicCongestionControl.ifBlank { "bbr" } == cc) { onChange(node.copy(extra = node.extra.copy(tuicCongestionControl = cc))) }
                }
                EditorChoiceChip("UDP over Stream", node.extra.tuicUdpOverStream) { onChange(node.copy(extra = node.extra.copy(tuicUdpOverStream = !node.extra.tuicUdpOverStream))) }
            }
        }
        "wireguard" -> {
            OutlinedTextField(node.password, { onChange(node.copy(password = it)) }, label = { Text("本机私钥 (Base64)") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(node.extra.wgPeerPublicKey, { onChange(node.copy(extra = node.extra.copy(wgPeerPublicKey = it))) }, label = { Text("对端公钥 (Base64)") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.fillMaxWidth())
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(node.extra.wgLocalAddresses.joinToString(", "), { raw -> onChange(node.copy(extra = node.extra.copy(wgLocalAddresses = raw.split(',').map { it.trim() }.filter { it.isNotEmpty() }))) }, label = { Text("隧道地址 CIDR") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.65f))
                OutlinedTextField((node.extra.wgMtu.takeIf { it > 0 } ?: 1420).toString(), { onChange(node.copy(extra = node.extra.copy(wgMtu = it.filter(Char::isDigit).toIntOrNull() ?: 1420))) }, label = { Text("MTU") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.35f))
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(node.extra.wgPresharedKey, { onChange(node.copy(extra = node.extra.copy(wgPresharedKey = it))) }, label = { Text("预共享密钥 (可选)") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.6f))
                OutlinedTextField(node.extra.wgReserved, { onChange(node.copy(extra = node.extra.copy(wgReserved = it))) }, label = { Text("Reserved (如 1,2,3)") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.4f))
            }
        }
        "masque" -> {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                EditorChoiceChip("CONNECT-UDP", node.extra.masqueMode.ifBlank { "connect-udp" } == "connect-udp") { onChange(node.copy(extra = node.extra.copy(masqueMode = "connect-udp"))) }
                EditorChoiceChip("CONNECT-IP", node.extra.masqueMode == "connect-ip") { onChange(node.copy(extra = node.extra.copy(masqueMode = "connect-ip"))) }
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(node.extra.masquePath, { onChange(node.copy(extra = node.extra.copy(masquePath = it))) }, label = { Text("URI 模板路径") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.55f))
                OutlinedTextField(node.password, { onChange(node.copy(password = it)) }, label = { Text("Bearer / 认证密钥") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.45f))
            }
            if (node.extra.masqueMode == "connect-ip") {
                OutlinedTextField(node.extra.masqueLocalAddresses.joinToString(", "), { raw -> onChange(node.copy(extra = node.extra.copy(masqueLocalAddresses = raw.split(',').map { it.trim() }.filter { it.isNotEmpty() }))) }, label = { Text("CONNECT-IP 本地地址 CIDR") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.fillMaxWidth())
            }
        }
        "shadowsocks" -> {
            Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                SS_METHODS.forEach { m ->
                    EditorChoiceChip(m, node.method.ifBlank { SS_METHODS.first() } == m) { onChange(node.copy(method = m)) }
                }
            }
            OutlinedTextField(node.password, { onChange(node.copy(password = it)) }, label = { Text("密码 / Base64 密钥") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.fillMaxWidth())
        }
        "naive" -> {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                EditorChoiceChip("HTTP/2 (h2)", node.extra.naiveProtocol.ifBlank { "h2" } == "h2") { onChange(node.copy(extra = node.extra.copy(naiveProtocol = "h2"))) }
                EditorChoiceChip("HTTP/3 QUIC (h3)", node.extra.naiveProtocol == "h3") { onChange(node.copy(extra = node.extra.copy(naiveProtocol = "h3"))) }
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(node.username, { onChange(node.copy(username = it)) }, label = { Text("用户名") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(1f))
                OutlinedTextField(node.password, { onChange(node.copy(password = it)) }, label = { Text("密码") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(1f))
            }
        }
        "snell" -> {
            OutlinedTextField(node.password, { onChange(node.copy(password = it)) }, label = { Text("PSK 密钥") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.fillMaxWidth())
            Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                EditorChoiceChip("v5", (node.extra.snellVersion.takeIf { it > 0 } ?: 5) == 5) { onChange(node.copy(extra = node.extra.copy(snellVersion = 5))) }
                EditorChoiceChip("v4", node.extra.snellVersion == 4) { onChange(node.copy(extra = node.extra.copy(snellVersion = 4))) }
                listOf("" to "无混淆", "http" to "OBFS HTTP", "tls" to "OBFS TLS").forEach { (k, l) ->
                    EditorChoiceChip(l, node.extra.snellObfs == k) { onChange(node.copy(extra = node.extra.copy(snellObfs = k))) }
                }
            }
            if (node.extra.snellObfs.isNotEmpty()) {
                OutlinedTextField(node.extra.snellObfsHost, { onChange(node.copy(extra = node.extra.copy(snellObfsHost = it))) }, label = { Text("混淆 Host") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.fillMaxWidth())
            }
        }
        else -> {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(node.username, { onChange(node.copy(username = it)) }, label = { Text("用户名 (可选)") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(1f))
                OutlinedTextField(node.password, { onChange(node.copy(password = it)) }, label = { Text(if (proto == "ssh") "密码 / 私钥" else "密码 (可选)") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(1f))
            }
            if (proto == "ssh") {
                OutlinedTextField(node.extra.sshHostKeySha256.joinToString(", "), { raw -> onChange(node.copy(extra = node.extra.copy(sshHostKeySha256 = raw.split(',').map { it.trim() }.filter { it.isNotEmpty() }))) }, label = { Text("Host Key SHA256 (逗号分隔)") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.fillMaxWidth())
            }
        }
    }

    if (usesTransport) {
        Text("传输层协议 (Transport)", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            TRANSPORTS.forEach { (k, l) ->
                EditorChoiceChip(l, node.transport.type == k) { onChange(node.copy(transport = node.transport.copy(type = k))) }
            }
        }
        if (node.transport.type.isNotEmpty()) {
            val isGrpc = node.transport.type == "grpc"
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = if (isGrpc) node.transport.authority else node.transport.host,
                    onValueChange = { v -> onChange(node.copy(transport = if (isGrpc) node.transport.copy(authority = v) else node.transport.copy(host = v))) },
                    label = { Text(if (isGrpc) "Authority" else "Host") },
                    shape = RoundedCornerShape(8.dp),
                    singleLine = true,
                    modifier = Modifier.weight(0.5f),
                )
                OutlinedTextField(
                    value = if (isGrpc) node.transport.serviceName else node.transport.path,
                    onValueChange = { v -> onChange(node.copy(transport = if (isGrpc) node.transport.copy(serviceName = v) else node.transport.copy(path = v))) },
                    label = { Text(if (isGrpc) "ServiceName" else "Path") },
                    shape = RoundedCornerShape(8.dp),
                    singleLine = true,
                    modifier = Modifier.weight(0.5f),
                )
            }
        }
    }

    if (usesTls) {
        Surface(shape = RoundedCornerShape(8.dp), color = ext.wellSurface, modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                EditorSwitchRow("启用 TLS / REALITY 安全传输", node.tls.enabled) { onChange(node.copy(tls = node.tls.copy(enabled = it))) }
                if (node.tls.enabled) {
                    OutlinedTextField(node.tls.sni, { onChange(node.copy(tls = node.tls.copy(sni = it))) }, label = { Text("SNI 域名") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.fillMaxWidth())
                    Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        UTLS_FINGERPRINTS.forEach { (k, l) -> EditorChoiceChip("uTLS: $l", node.tls.fingerprint == k) { onChange(node.copy(tls = node.tls.copy(fingerprint = k))) } }
                    }
                    Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        PQ_KEMS.forEach { (k, l) -> EditorChoiceChip(l, node.tls.keyExchange == k) { onChange(node.copy(tls = node.tls.copy(keyExchange = k))) } }
                    }
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(node.tls.realityPublicKey, { onChange(node.copy(tls = node.tls.copy(realityPublicKey = it))) }, label = { Text("REALITY PublicKey (可选)") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.65f))
                        OutlinedTextField(node.tls.realityShortId, { onChange(node.copy(tls = node.tls.copy(realityShortId = it))) }, label = { Text("ShortId") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.35f))
                    }
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(node.tls.echQueryServerName, { onChange(node.copy(tls = node.tls.copy(echMode = if (it.isNotBlank() || node.tls.echConfig.isNotBlank()) "dns" else "", echQueryServerName = it))) }, label = { Text("ECH 查询域名 (可选)") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.5f))
                        OutlinedTextField(node.tls.certSha256.joinToString(","), { raw -> onChange(node.copy(tls = node.tls.copy(certSha256 = raw.split(',').map { it.trim() }.filter { it.isNotEmpty() }))) }, label = { Text("证书 SHA256 固定") }, shape = RoundedCornerShape(8.dp), singleLine = true, modifier = Modifier.weight(0.5f))
                    }
                    HorizontalDivider(color = ext.hairline)
                    EditorSwitchRow("TLS ClientHello 分片 (防 SNI 阻断)", node.tls.fragment) { onChange(node.copy(tls = node.tls.copy(fragment = it))) }
                    EditorSwitchRow("TLS Record 分片", node.tls.recordFragment) { onChange(node.copy(tls = node.tls.copy(recordFragment = it))) }
                }
            }
        }
    }

    if (usesMux) {
        Surface(shape = RoundedCornerShape(8.dp), color = ext.wellSurface, modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                EditorSwitchRow("启用多路复用 (Multiplex)", node.multiplex.enabled) { onChange(node.copy(multiplex = node.multiplex.copy(enabled = it, protocol = node.multiplex.protocol.ifBlank { "h2mux" }))) }
                if (node.multiplex.enabled) {
                    Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        MUX_PROTOS.forEach { mp -> EditorChoiceChip(mp, node.multiplex.protocol.ifBlank { "h2mux" } == mp) { onChange(node.copy(multiplex = node.multiplex.copy(protocol = mp))) } }
                        EditorChoiceChip("Padding 填充", node.multiplex.padding) { onChange(node.copy(multiplex = node.multiplex.copy(padding = !node.multiplex.padding))) }
                    }
                }
            }
        }
    }
}

@Composable
internal fun EditorChoiceChip(label: String, selected: Boolean, onClick: () -> Unit) {
    val ext = NexusTheme.colors
    val primary = MaterialTheme.colorScheme.primary
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(8.dp),
        color = if (selected) primary.copy(alpha = if (ext.isDark) 0.24f else 0.12f) else ext.wellSurface,
        border = if (selected) BorderStroke(1.2.dp, primary) else null,
        modifier = Modifier.minimumInteractiveComponentSize().heightIn(min = 38.dp),
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
            color = if (selected) primary else MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 11.dp, vertical = 9.dp),
        )
    }
}

@Composable
internal fun EditorSwitchRow(title: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
        Text(title, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}
