package org.nexus.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
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
 * Single-level Material 3 Adaptive Connections KPI Card (`12dp` radius, decoupled Cobalt RX / Emerald TX telemetry).
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
    val ulLabel = if (hasLiveRate) "实时上行" else "累计上行"
    val ulPrimary = if (hasLiveRate) formatTrafficRate(uploadRateBps) else formatTrafficBytes(totalUpload)
    val proxyLabel = if (activeCount > 0) "$proxyPercent%" else "--"

    OpticalCard(
        modifier = modifier.fillMaxWidth(),
        cornerRadius = 12.dp,
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min).padding(horizontal = 14.dp, vertical = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            LedgerMetricColumn(
                label = "活跃流",
                value = "$activeCount",
                sub = "T:$tcpCount U:$udpCount",
                valueColor = MaterialTheme.colorScheme.onSurface,
                compact = compact,
                modifier = Modifier.weight(1f),
            )
            Box(Modifier.width(1.dp).fillMaxHeight().background(ext.hairline))
            LedgerMetricColumn(
                label = dlLabel,
                value = dlPrimary,
                sub = formatTrafficBytes(totalDownload),
                valueColor = ext.telemetryDownload,
                compact = compact,
                modifier = Modifier.weight(1.1f),
            )
            Box(Modifier.width(1.dp).fillMaxHeight().background(ext.hairline))
            LedgerMetricColumn(
                label = ulLabel,
                value = ulPrimary,
                sub = formatTrafficBytes(totalUpload),
                valueColor = ext.telemetryUpload,
                compact = compact,
                modifier = Modifier.weight(1.1f),
            )
            if (!compact) {
                Box(Modifier.width(1.dp).fillMaxHeight().background(ext.hairline))
                LedgerMetricColumn(
                    label = "代理分流",
                    value = proxyLabel,
                    sub = if (activeCount > 0) "直连 ${100 - proxyPercent}%" else "空闲",
                    valueColor = ext.success,
                    compact = false,
                    modifier = Modifier.weight(0.9f),
                )
            }
        }
    }
}

@Composable
private fun LedgerMetricColumn(
    label: String,
    value: String,
    sub: String,
    valueColor: Color,
    compact: Boolean,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier,
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.titleMedium.copy(
                fontFamily = FontFamily.SansSerif,
                fontWeight = FontWeight.ExtraBold,
                fontSize = if (compact) 16.sp else 19.sp,
                fontFeatureSettings = "tnum",
            ),
            color = valueColor,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Text(
            text = sub,
            style = NexusNumericStyles.monoBadge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
internal fun ConnectionItemCard(
    conn: ActiveConnectionSnapshot,
    selected: Boolean,
    maxTotalBytes: Long = 0L,
    onInspect: () -> Unit,
    onClose: () -> Unit,
) {
    val ext = NexusTheme.colors
    val targetHost = conn.target.ifEmpty {
        if (conn.destinationPort > 0) "${conn.path}:${conn.destinationPort}" else conn.path
    }
    val ruleBadge = conn.routeRule.substringBefore("->").trim().take(20)
    val isDirect = conn.outbound.equals("direct", ignoreCase = true)
    val connTotal = (conn.downloadBytes + conn.uploadBytes).coerceAtLeast(0L)
    val shareFrac = if (maxTotalBytes > 0L && connTotal > 0L) {
        (connTotal.toFloat() / maxTotalBytes.toFloat()).coerceIn(0.05f, 1f)
    } else 0f
    val rxFrac = if (connTotal > 0L) (conn.downloadBytes.toFloat() / connTotal.toFloat()).coerceIn(0f, 1f) else 0f

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                if (selected) MaterialTheme.colorScheme.primary.copy(alpha = if (ext.isDark) 0.15f else 0.08f)
                else Color.Transparent,
            )
            .clickable(onClick = onInspect),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 54.dp)
                .padding(start = 6.dp, top = 8.dp, bottom = if (shareFrac > 0f) 4.dp else 8.dp, end = 2.dp),
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
                verticalArrangement = Arrangement.spacedBy(3.dp),
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(
                        text = targetHost,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = if (selected) FontWeight.ExtraBold else FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false),
                    )
                    if (ruleBadge.isNotEmpty()) {
                        StatusPill(
                            text = ruleBadge,
                            containerColor = if (isDirect) ext.successContainer else ext.ruleVermilionContainer,
                            contentColor = if (isDirect) ext.success else ext.ruleVermilion,
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
                        color = if (isDirect) ext.success else MaterialTheme.colorScheme.primary,
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
        if (shareFrac > 0f) {
            val trackColor = ext.insetSurface.copy(alpha = 0.65f)
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 6.dp, end = 12.dp, bottom = 6.dp)
                    .height(2.dp)
                    .clip(CircleShape)
                    .drawBehind {
                        drawRect(color = trackColor)
                        val barW = size.width * shareFrac
                        val rxW = barW * rxFrac
                        val txW = (barW - rxW).coerceAtLeast(0f)
                        if (rxW > 0.5f) drawRect(ext.telemetryDownload, Offset.Zero, Size(rxW, size.height))
                        if (txW > 0.5f) drawRect(ext.telemetryUpload, Offset(rxW, 0f), Size(txW, size.height))
                    },
            )
        }
        HorizontalDivider(color = ext.hairline)
    }
}
