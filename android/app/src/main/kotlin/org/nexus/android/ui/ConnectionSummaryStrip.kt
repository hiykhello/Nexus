package org.nexus.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.nexus.android.R
import org.nexus.android.bridge.ipc.ActiveConnectionSnapshot
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

/**
 * Wave 9 Live Connections KPI Strip (`活跃连接 · 实时下行 · 实时上行 · 代理占比`):
 * - Tablet / Foldable (`>= 600dp`): 4-column elevated smoked-graphite Bento KPI cards
 * - Compact Phone (`< 600dp`): sleek compact 2x2 stepped-graphite KPI pills
 */
@Composable
internal fun ConnectionsKpiStrip(
    activeCount: Int,
    tcpCount: Int,
    udpCount: Int,
    downloadRateBps: Long,
    uploadRateBps: Long,
    totalDownload: Long,
    totalUpload: Long,
    proxyPercent: Int,
    compact: Boolean,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val hasLiveRate = downloadRateBps >= 0L && uploadRateBps >= 0L
    val dlLabel = if (hasLiveRate) "实时下行" else "累计下行"
    val dlPrimary = if (hasLiveRate) formatTrafficRate(downloadRateBps) else formatTrafficBytes(totalDownload)
    val dlSub = if (hasLiveRate) "总计 ${formatTrafficBytes(totalDownload)}" else "活跃会话"
    val ulLabel = if (hasLiveRate) "实时上行" else "累计上行"
    val ulPrimary = if (hasLiveRate) formatTrafficRate(uploadRateBps) else formatTrafficBytes(totalUpload)
    val ulSub = if (hasLiveRate) "总计 ${formatTrafficBytes(totalUpload)}" else "活跃会话"
    val proxyLabel = if (activeCount > 0) "$proxyPercent% 代理" else "--"
    val proxySub = if (activeCount > 0) "${100 - proxyPercent}% 直连" else "等待连接"

    if (compact) {
        Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                CompactKpiPill("活跃连接", "$activeCount", "TCP $tcpCount · UDP $udpCount", MaterialTheme.colorScheme.onSurface, Modifier.weight(1f))
                CompactKpiPill("代理占比", proxyLabel, proxySub, ext.success, Modifier.weight(1f))
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                CompactKpiPill(dlLabel, dlPrimary, dlSub, ext.telemetryDownload, Modifier.weight(1f))
                CompactKpiPill(ulLabel, ulPrimary, ulSub, ext.telemetryUpload, Modifier.weight(1f))
            }
        }
    } else {
        Row(
            modifier = modifier.fillMaxWidth().height(IntrinsicSize.Max),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            ExpandedKpiTile("活跃连接", "$activeCount", "TCP $tcpCount · UDP $udpCount", MaterialTheme.colorScheme.onSurface, Color.Transparent, Modifier.weight(1f).fillMaxHeight())
            ExpandedKpiTile(dlLabel, dlPrimary, dlSub, ext.telemetryDownload, ext.telemetryDownload.copy(alpha = if (ext.isDark) 0.11f else 0.06f), Modifier.weight(1f).fillMaxHeight())
            ExpandedKpiTile(ulLabel, ulPrimary, ulSub, ext.telemetryUpload, ext.telemetryUpload.copy(alpha = if (ext.isDark) 0.11f else 0.06f), Modifier.weight(1f).fillMaxHeight())
            ExpandedKpiTile("代理占比", proxyLabel, proxySub, ext.success, ext.success.copy(alpha = if (ext.isDark) 0.10f else 0.06f), Modifier.weight(1f).fillMaxHeight())
        }
    }
}

@Composable
private fun ExpandedKpiTile(
    label: String,
    value: String,
    subtitle: String,
    valueColor: Color,
    accentTint: Color,
    modifier: Modifier = Modifier,
) {
    OpticalCard(
        modifier = modifier,
        cornerRadius = 18.dp,
        accentTint = accentTint,
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 11.dp),
            verticalArrangement = Arrangement.spacedBy(3.dp),
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = value,
                style = MaterialTheme.typography.titleLarge.copy(
                    fontFamily = FontFamily.SansSerif,
                    fontWeight = FontWeight.ExtraBold,
                    fontSize = 20.sp,
                    letterSpacing = (-0.5).sp,
                    fontFeatureSettings = "tnum",
                ),
                color = valueColor,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = subtitle,
                style = NexusNumericStyles.monoBadge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun CompactKpiPill(
    label: String,
    value: String,
    subtitle: String,
    valueColor: Color,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(14.dp),
        color = ext.cardGradientTop,
        border = BorderStroke(1.dp, ext.hairline),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 11.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
                Text(subtitle, style = NexusNumericStyles.monoBadge, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Text(
                text = value,
                style = MaterialTheme.typography.titleMedium.copy(
                    fontFamily = FontFamily.SansSerif,
                    fontWeight = FontWeight.ExtraBold,
                    fontFeatureSettings = "tnum",
                ),
                color = valueColor,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
internal fun ConnectionItemCard(
    conn: ActiveConnectionSnapshot,
    selected: Boolean,
    onInspect: () -> Unit,
    onClose: () -> Unit,
) {
    val ext = NexusTheme.colors
    val primary = MaterialTheme.colorScheme.primary
    val targetHost = conn.target.ifEmpty {
        if (conn.destinationPort > 0) "${conn.path}:${conn.destinationPort}" else conn.path
    }
    val ruleBadge = conn.routeRule.substringBefore("->").trim().take(22)

    OpticalCard(
        modifier = Modifier.fillMaxWidth(),
        cornerRadius = 18.dp,
        borderColor = if (selected) primary.copy(alpha = 0.80f) else ext.hairline,
        borderWidth = if (selected) 1.5.dp else 1.dp,
        accentTint = if (selected) primary.copy(alpha = if (ext.isDark) 0.12f else 0.06f) else Color.Transparent,
        onClick = onInspect,
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(start = 12.dp, top = 10.dp, bottom = 10.dp, end = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            StatusPill(
                text = formatProtocolLabel(conn.protocol),
                containerColor = protocolContainerColor(conn.protocol),
                contentColor = protocolContentColor(conn.protocol),
                mono = true,
            )
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(
                        text = targetHost,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false),
                    )
                    if (ruleBadge.isNotEmpty()) {
                        StatusPill(
                            text = ruleBadge,
                            containerColor = ext.wellSurface,
                            contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = conn.outbound.ifEmpty { conn.path },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false),
                    )
                    Text(
                        text = "↓${formatTrafficBytes(conn.downloadBytes)}",
                        style = NexusNumericStyles.monoBadge,
                        color = ext.telemetryDownload,
                    )
                    Text(
                        text = "↑${formatTrafficBytes(conn.uploadBytes)}",
                        style = NexusNumericStyles.monoBadge,
                        color = ext.telemetryUpload,
                    )
                }
            }
            IconButton(onClick = onClose) {
                Icon(
                    painter = painterResource(R.drawable.ic_close),
                    contentDescription = "断开连接",
                    tint = ext.danger,
                    modifier = Modifier.size(18.dp),
                )
            }
        }
    }
}
