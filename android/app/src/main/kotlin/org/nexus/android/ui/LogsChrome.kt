package org.nexus.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import org.nexus.android.R
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

private val LOG_LEVELS = listOf("trace", "error", "warn", "info", "debug")
private val CORE_LOG_LEVELS = listOf("error", "warn", "info", "debug", "trace")
internal val LOG_DOMAIN_OPTIONS = listOf(
    "all" to "全部",
    "core" to "core",
    "net" to "net",
    "tls" to "tls",
    "quic" to "quic",
    "dns" to "dns",
    "route" to "route",
    "tun" to "tun",
    "proxy" to "proxy",
    "control" to "control",
    "state" to "state",
)
private val LOG_TIMESTAMP_REGEX = Regex("^(\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,3})?)\\s+(.*)$")
private val LOG_LEVEL_TAG_REGEX = Regex("^\\[(error|warn|warning|info|debug|trace)]\\s*(.*)$", RegexOption.IGNORE_CASE)
private val LOG_DOMAIN_PREFIX_REGEX = Regex("^([a-zA-Z0-9_-]{2,20}):\\s+.*$")

/**
 * Extracts normalized log domain prefix (e.g. `dns`, `route`, `quic`, `core`, `control`)
 * from either `[level] domain: message` or `HH:mm:ss [level] domain: message`.
 */
fun parseLogDomain(raw: String): String {
    var rest = raw.trim()
    LOG_TIMESTAMP_REGEX.matchEntire(rest)?.let { rest = it.groupValues[2].trimStart() }
    LOG_LEVEL_TAG_REGEX.matchEntire(rest)?.let { rest = it.groupValues[2].trimStart() }
    LOG_TIMESTAMP_REGEX.matchEntire(rest)?.let { rest = it.groupValues[2].trimStart() }
    val domain = LOG_DOMAIN_PREFIX_REGEX.matchEntire(rest)?.groupValues?.get(1)?.lowercase().orEmpty()
    return when (domain) {
        "vpn" -> "tun"
        "outbound", "probe" -> "proxy"
        else -> domain
    }
}

@Composable
internal fun LogDomainFilterRow(
    selectedDomain: String,
    onSelectDomain: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    LazyRow(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        items(items = LOG_DOMAIN_OPTIONS, key = { it.first }) { (key, label) ->
            val selected = selectedDomain == key
            FilterChip(
                selected = selected,
                onClick = { onSelectDomain(key) },
                shape = RoundedCornerShape(999.dp),
                label = {
                    Text(
                        text = label,
                        style = if (key == "all") MaterialTheme.typography.labelMedium else NexusNumericStyles.monoBadge,
                        maxLines = 1,
                        softWrap = false,
                    )
                },
                colors = FilterChipDefaults.filterChipColors(
                    containerColor = ext.wellSurface,
                    labelColor = MaterialTheme.colorScheme.onSurfaceVariant,
                    selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                    selectedLabelColor = MaterialTheme.colorScheme.onPrimaryContainer,
                ),
                border = FilterChipDefaults.filterChipBorder(
                    enabled = true,
                    selected = selected,
                    borderColor = ext.hairline,
                    selectedBorderColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.45f),
                ),
                modifier = Modifier.heightIn(min = 36.dp),
            )
        }
    }
}

@Composable
internal fun CoreLogLevelDropdownPill(
    currentLevel: String,
    expanded: Boolean,
    onExpandedChange: (Boolean) -> Unit,
    onSelectLevel: (String) -> Unit,
) {
    Box {
        Surface(
            onClick = { onExpandedChange(!expanded) },
            modifier = Modifier.minimumInteractiveComponentSize(),
            shape = RoundedCornerShape(999.dp),
            color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.7f),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.45f)),
        ) {
            Text(
                text = "内核:${currentLevel.uppercase()} ▾",
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
                maxLines = 1,
                softWrap = false,
                modifier = Modifier.padding(horizontal = 9.dp, vertical = 5.dp),
            )
        }
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { onExpandedChange(false) },
            shape = RoundedCornerShape(14.dp),
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
        ) {
            CORE_LOG_LEVELS.forEach { lvl ->
                val isSel = currentLevel.equals(lvl, ignoreCase = true)
                DropdownMenuItem(
                    text = {
                        Text(
                            text = "内核输出: ${lvl.uppercase()}",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = if (isSel) FontWeight.Bold else FontWeight.Medium,
                            color = if (isSel) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                        )
                    },
                    onClick = { onSelectLevel(lvl) },
                )
            }
        }
    }
}

@Composable
internal fun LogLevelDropdownPill(
    selectedLevel: String,
    expanded: Boolean,
    onExpandedChange: (Boolean) -> Unit,
    onSelectLevel: (String) -> Unit,
) {
    val ext = NexusTheme.colors
    val (pillBg, pillFg, pillText) = when (selectedLevel) {
        "error" -> Triple(ext.dangerContainer, ext.danger, "ERR ▾")
        "warn" -> Triple(ext.warningContainer, ext.warning, "WRN ▾")
        "info" -> Triple(ext.telemetryDownloadContainer, ext.telemetryDownload, "INF ▾")
        "debug" -> Triple(ext.insetSurface, MaterialTheme.colorScheme.onSurfaceVariant, "DBG ▾")
        else -> Triple(ext.insetSurface, MaterialTheme.colorScheme.onSurface, "全部 ▾")
    }

    Box {
        Surface(
            onClick = { onExpandedChange(!expanded) },
            modifier = Modifier.minimumInteractiveComponentSize(),
            shape = RoundedCornerShape(999.dp),
            color = pillBg,
            border = BorderStroke(
                width = 1.dp,
                color = if (selectedLevel == "trace") ext.hairline else pillFg.copy(alpha = 0.45f),
            ),
        ) {
            Text(
                text = pillText,
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.SemiBold,
                color = pillFg,
                maxLines = 1,
                softWrap = false,
                modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
            )
        }
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { onExpandedChange(false) },
            shape = RoundedCornerShape(14.dp),
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
        ) {
            LOG_LEVELS.forEach { lvl ->
                val isSelected = selectedLevel == lvl
                val dotColor = when (lvl) {
                    "error" -> ext.danger
                    "warn" -> ext.warning
                    "info" -> ext.telemetryDownload
                    "debug" -> ext.muted
                    else -> MaterialTheme.colorScheme.primary
                }
                val itemLabel = if (lvl == "trace") "筛选: 全部" else "筛选: ${lvl.uppercase()}"
                DropdownMenuItem(
                    text = {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Box(Modifier.size(7.dp).background(dotColor, CircleShape))
                            Text(
                                text = itemLabel,
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium,
                                color = if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                            )
                        }
                    },
                    trailingIcon = if (isSelected) {
                        {
                            Icon(
                                painter = painterResource(R.drawable.ic_check),
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(16.dp),
                            )
                        }
                    } else null,
                    onClick = { onSelectLevel(lvl) },
                )
            }
        }
    }
}

private data class ParsedLogEntry(
    val level: String,
    val timestamp: String,
    val message: String,
)

private fun parseLogEntry(raw: String): ParsedLogEntry {
    var rest = raw.trim()
    var timestamp = ""
    LOG_TIMESTAMP_REGEX.matchEntire(rest)?.let { m ->
        timestamp = m.groupValues[1]
        rest = m.groupValues[2].trimStart()
    }
    var level = "LOG"
    LOG_LEVEL_TAG_REGEX.matchEntire(rest)?.let { m ->
        level = when (m.groupValues[1].lowercase()) {
            "error" -> "ERR"
            "warn", "warning" -> "WRN"
            "info" -> "INF"
            "debug", "trace" -> "DBG"
            else -> "LOG"
        }
        rest = m.groupValues[2]
    }
    if (timestamp.isEmpty()) {
        LOG_TIMESTAMP_REGEX.matchEntire(rest)?.let { m ->
            timestamp = m.groupValues[1]
            rest = m.groupValues[2].trimStart()
        }
    }
    return ParsedLogEntry(level = level, timestamp = timestamp, message = rest.ifEmpty { raw })
}

@Composable
internal fun LogLineRow(line: String) {
    val ext = NexusTheme.colors
    val parsed = remember(line) { parseLogEntry(line) }
    val (badgeBg, badgeFg, railColor) = when (parsed.level) {
        "ERR" -> Triple(ext.dangerContainer, ext.danger, ext.danger)
        "WRN" -> Triple(ext.warningContainer, ext.warning, ext.warning)
        "INF" -> Triple(ext.telemetryDownloadContainer, ext.telemetryDownload, ext.telemetryDownload.copy(alpha = 0.72f))
        else -> Triple(ext.mutedContainer, ext.muted, ext.muted.copy(alpha = 0.40f))
    }
    val rowTint = if (parsed.level == "ERR") ext.dangerContainer.copy(alpha = 0.16f) else Color.Transparent

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .height(IntrinsicSize.Min)
            .background(rowTint, RoundedCornerShape(6.dp))
            .padding(end = 6.dp, top = 4.dp, bottom = 4.dp),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Box(
            modifier = Modifier
                .width(2.dp)
                .fillMaxHeight()
                .background(railColor, CircleShape),
        )
        Surface(
            modifier = Modifier.width(30.dp),
            shape = RoundedCornerShape(4.dp),
            color = badgeBg,
        ) {
            Text(
                text = parsed.level,
                style = NexusNumericStyles.monoBadge,
                color = badgeFg,
                textAlign = TextAlign.Center,
                maxLines = 1,
                softWrap = false,
                modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
            )
        }
        if (parsed.timestamp.isNotEmpty()) {
            Text(
                text = parsed.timestamp,
                style = NexusNumericStyles.monoBadge,
                color = ext.muted,
                maxLines = 1,
                softWrap = false,
                modifier = Modifier.padding(top = 2.dp),
            )
        }
        Text(
            text = parsed.message,
            style = NexusNumericStyles.codeBlock,
            color = if (parsed.level == "ERR") ext.danger else MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f),
        )
    }
}
