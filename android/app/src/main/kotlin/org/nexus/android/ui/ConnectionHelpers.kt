package org.nexus.android.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import org.nexus.android.bridge.workspace.AndroidPerAppMode
import org.nexus.android.ui.theme.NexusTheme
import java.util.Locale

data class PerAppConnectionAction(
    val enabled: Boolean,
    val label: String,
    val feedbackText: String,
    val removeFromList: Boolean,
    val switchToExcludeMode: Boolean,
)

/**
 * Pure mode-aware per-app bypass decision for the Connection Inspector action button:
 * - `EXCLUDE`: adds package to `perAppPackages` (or shows disabled "已绕过应用" if already excluded)
 * - `INCLUDE`: removes package from `perAppPackages` so it bypasses VPN (or disabled "已直连绕过" if not in list)
 * - `OFF`: switches mode to `EXCLUDE` and adds package so user's intent actually takes effect
 */
fun computePerAppConnectionAction(
    perAppMode: AndroidPerAppMode,
    packageName: String,
    perAppPackages: Set<String>,
): PerAppConnectionAction {
    val inList = perAppPackages.contains(packageName)
    return when (perAppMode) {
        AndroidPerAppMode.EXCLUDE -> if (inList) {
            PerAppConnectionAction(
                enabled = false,
                label = "已绕过应用",
                feedbackText = "$packageName 已在绕过列表中",
                removeFromList = false,
                switchToExcludeMode = false,
            )
        } else {
            PerAppConnectionAction(
                enabled = true,
                label = "绕过应用",
                feedbackText = "已加入绕过列表: $packageName（重启隧道生效）",
                removeFromList = false,
                switchToExcludeMode = false,
            )
        }
        AndroidPerAppMode.INCLUDE -> if (inList) {
            PerAppConnectionAction(
                enabled = true,
                label = "移出代理列表",
                feedbackText = "已将 $packageName 移出代理列表（重启隧道生效）",
                removeFromList = true,
                switchToExcludeMode = false,
            )
        } else {
            PerAppConnectionAction(
                enabled = false,
                label = "已直连绕过",
                feedbackText = "$packageName 未在仅代理列表中，已直连",
                removeFromList = false,
                switchToExcludeMode = false,
            )
        }
        AndroidPerAppMode.OFF -> PerAppConnectionAction(
            enabled = true,
            label = "启用并绕过应用",
            feedbackText = "已切换至「排除所选」并绕过 $packageName（重启隧道生效）",
            removeFromList = false,
            switchToExcludeMode = true,
        )
    }
}

internal fun extractOwnerPackageName(ownerDisplay: String?): String? {
    val raw = ownerDisplay?.trim().orEmpty()
    if (raw.isEmpty()) return null
    val beforeUid = raw.substringBefore(" (UID").trim()
    val firstPkg = beforeUid.substringBefore(',').trim()
    return firstPkg.takeIf {
        it.contains('.') &&
            !it.startsWith("UID") &&
            it.all { ch -> ch.isLetterOrDigit() || ch == '.' || ch == '_' || ch == '-' }
    }
}

internal fun formatCompactDuration(durationMs: Long): String = when {
    durationMs < 1_000L -> "${durationMs.coerceAtLeast(0L)} ms"
    durationMs < 60_000L -> String.format(Locale.US, "%.1f s", durationMs / 1000.0)
    else -> "${durationMs / 60_000L}m ${(durationMs / 1000L) % 60L}s"
}

internal fun formatShortAppLabel(pkg: String?, fallback: String): String {
    val raw = pkg?.trim().orEmpty().ifEmpty { fallback.trim() }
    if (raw.isEmpty()) return "系统"
    val leaf = raw.substringBefore(" (UID").substringAfterLast('.').ifEmpty { raw }
    return leaf.replaceFirstChar { if (it.isLowerCase()) it.titlecase(Locale.US) else it.toString() }
}

internal fun formatProtocolLabel(protocol: String): String = when (protocol.lowercase()) {
    "udp/quic" -> "QUIC"
    "udp" -> "UDP"
    "tcp/tls" -> "TLS"
    "tcp" -> "TCP"
    else -> protocol.uppercase()
}

@Composable
internal fun protocolContainerColor(protocol: String) = when (formatProtocolLabel(protocol)) {
    "QUIC", "UDP" -> NexusTheme.colors.protocolQuicContainer
    "TLS" -> NexusTheme.colors.protocolTlsContainer
    else -> MaterialTheme.colorScheme.surfaceContainerHigh
}

@Composable
internal fun protocolContentColor(protocol: String) = when (formatProtocolLabel(protocol)) {
    "QUIC", "UDP" -> NexusTheme.colors.protocolQuic
    "TLS" -> NexusTheme.colors.protocolTls
    else -> MaterialTheme.colorScheme.onSurfaceVariant
}
