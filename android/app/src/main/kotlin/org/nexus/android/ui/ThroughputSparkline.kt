package org.nexus.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

/**
 * Card 2 — Realtime Network Throughput Card (`12dp` single-level Card Console container):
 * - Tabular Cobalt RX & Signal Emerald TX live rates + cumulative totals
 * - Borderless `wellSurface` dual-track Bezier area plot with clean Standby state hint
 * - Bottom cumulative RX/TX proportion bar
 */
@Composable
fun ThroughputSparklineCard(
    running: Boolean,
    downloadRateBps: Long,
    uploadRateBps: Long,
    downloadSamples: List<Long>,
    uploadSamples: List<Long>,
    downloadTotalBytes: Long = 0L,
    uploadTotalBytes: Long = 0L,
    activeSessions: Long = 0L,
    onsetMarkers: List<SparklineOnset> = emptyList(),
    onClick: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val rxLinePath = remember { Path() }
    val rxAreaPath = remember { Path() }
    val txLinePath = remember { Path() }
    val scratch = remember { WaveScratchBuffers() }

    val activeRx = if (running) downloadSamples else emptyList()
    val activeTx = if (running) uploadSamples else emptyList()
    val activeOnsets = if (running) onsetMarkers else emptyList()
    val sharedScaleBps = remember(activeRx, activeTx) {
        computeSharedPeakScaleBps(activeRx, activeTx)
    }
    val ceilingText = remember(sharedScaleBps, running) {
        if (running) formatTrafficRate(sharedScaleBps.toLong()) else "0.0 KB/s"
    }
    val latestOnset = activeOnsets.lastOrNull()

    val a11ySummary = if (running) {
        "下载 ${formatTrafficRate(downloadRateBps)}，上传 ${formatTrafficRate(uploadRateBps)}，量程 $ceilingText" +
            (latestOnset?.let { "，最近切换 ${it.label}" }.orEmpty())
    } else {
        "实时网络速率待机"
    }

    OpticalCard(
        cornerRadius = 12.dp,
        modifier = modifier
            .fillMaxWidth()
            .semantics(mergeDescendants = true) { contentDescription = a11ySummary },
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text(
                    text = "实时网络速率",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                StatusPill(
                    text = if (running && activeSessions > 0L) "$activeSessions 流 · $ceilingText" else "峰值 $ceilingText",
                    containerColor = if (running) ext.telemetryDownloadContainer else ext.wellSurface,
                    contentColor = if (running) ext.telemetryDownload else MaterialTheme.colorScheme.onSurfaceVariant,
                    mono = true,
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                ChannelReadoutColumn(
                    label = "下行",
                    rateBps = if (running) downloadRateBps else 0L,
                    totalBytes = downloadTotalBytes,
                    accentColor = ext.telemetryDownload,
                    dashedLegend = false,
                    modifier = Modifier.weight(1f),
                )
                Box(modifier = Modifier.width(1.dp).height(38.dp).background(ext.hairline))
                ChannelReadoutColumn(
                    label = "上行",
                    rateBps = if (running) uploadRateBps else 0L,
                    totalBytes = uploadTotalBytes,
                    accentColor = ext.telemetryUpload,
                    dashedLegend = true,
                    modifier = Modifier.weight(1f),
                )
            }

            val fontScale = LocalDensity.current.fontScale
            val chartHeight = if (fontScale > 1.3f) 110.dp else 98.dp
            val topReserveDp = (20f * fontScale.coerceIn(1f, 1.5f)).dp

            // Borderless inner plot well (never a nested bordered card)
            Surface(
                shape = RoundedCornerShape(8.dp),
                color = ext.wellSurface,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(chartHeight)
                    .clip(RoundedCornerShape(8.dp))
                    .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier),
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .clipToBounds()
                        .drawWithCache {
                            val padTop = topReserveDp.toPx()
                            val padBottom = 4.dp.toPx()
                            val baselineY = size.height - padBottom
                            val q1Y = padTop + (baselineY - padTop) * 0.25f
                            val midY = padTop + (baselineY - padTop) * 0.50f
                            val q3Y = padTop + (baselineY - padTop) * 0.75f

                            val rxStrokePx = 2.2.dp.toPx()
                            val rxStroke = Stroke(width = rxStrokePx, cap = StrokeCap.Round, join = StrokeJoin.Round)
                            val txStrokePx = 1.7.dp.toPx()
                            val txDash = PathEffect.dashPathEffect(floatArrayOf(5.dp.toPx(), 4.dp.toPx()), 0f)
                            val txStroke = Stroke(width = txStrokePx, cap = StrokeCap.Round, join = StrokeJoin.Round, pathEffect = txDash)
                            val onsetDash = PathEffect.dashPathEffect(floatArrayOf(3.dp.toPx(), 3.dp.toPx()), 0f)

                            val rxFillColor = ext.telemetryDownload.copy(alpha = if (ext.isDark) 0.20f else 0.12f)
                            val gridMinor = ext.hairline.copy(alpha = 0.70f)
                            val gridMajor = ext.hairlineStrong.copy(alpha = 0.55f)
                            val amber = ext.warning
                            val sampleCount = maxOf(activeRx.size, activeTx.size, 12)

                            val hasRx = buildCalibratedWavePaths(
                                samples = activeRx,
                                topScale = sharedScaleBps,
                                width = size.width,
                                leftOffset = 0f,
                                chartTop = padTop,
                                baselineY = baselineY,
                                strokeWidthPx = rxStrokePx,
                                linePath = rxLinePath,
                                areaPath = rxAreaPath,
                                scratch = scratch,
                            )
                            val hasTx = buildCalibratedWavePaths(
                                samples = activeTx,
                                topScale = sharedScaleBps,
                                width = size.width,
                                leftOffset = 0f,
                                chartTop = padTop,
                                baselineY = baselineY,
                                strokeWidthPx = txStrokePx,
                                linePath = txLinePath,
                                areaPath = null,
                                scratch = scratch,
                            )
                            val onsetXs = activeOnsets.map { m ->
                                onsetSampleX(m.sampleIndex, sampleCount, size.width, 0f)
                            }

                            onDrawBehind {
                                drawLine(gridMinor, Offset(0f, q1Y), Offset(size.width, q1Y), 1f)
                                drawLine(gridMajor, Offset(0f, midY), Offset(size.width, midY), 1f)
                                drawLine(gridMinor, Offset(0f, q3Y), Offset(size.width, q3Y), 1f)
                                drawLine(gridMinor, Offset(size.width * 0.25f, 0f), Offset(size.width * 0.25f, size.height), 1f)
                                drawLine(gridMinor, Offset(size.width * 0.50f, 0f), Offset(size.width * 0.50f, size.height), 1f)
                                drawLine(gridMinor, Offset(size.width * 0.75f, 0f), Offset(size.width * 0.75f, size.height), 1f)

                                if (hasRx) {
                                    drawPath(path = rxAreaPath, color = rxFillColor)
                                    drawPath(path = rxLinePath, color = ext.telemetryDownload, style = rxStroke)
                                } else {
                                    drawLine(
                                        color = ext.telemetryDownload.copy(alpha = 0.45f),
                                        start = Offset(0f, baselineY),
                                        end = Offset(size.width, baselineY),
                                        strokeWidth = 1.6.dp.toPx(),
                                    )
                                }
                                if (hasTx) {
                                    drawPath(path = txLinePath, color = ext.telemetryUpload, style = txStroke)
                                }
                                onsetXs.forEach { x ->
                                    drawLine(
                                        color = amber,
                                        start = Offset(x, 0f),
                                        end = Offset(x, baselineY),
                                        strokeWidth = 1.dp.toPx(),
                                        pathEffect = onsetDash,
                                    )
                                }
                            }
                        },
                ) {
                    if (!running) {
                        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                            Text(
                                text = "待机中 · 启动连接后实时采样上下行曲线",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    } else if (latestOnset != null) {
                        Surface(
                            modifier = Modifier.align(Alignment.TopStart).padding(8.dp),
                            shape = RoundedCornerShape(6.dp),
                            color = ext.warningContainer,
                        ) {
                            Row(
                                modifier = Modifier.padding(horizontal = 7.dp, vertical = 3.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(4.dp),
                            ) {
                                Text(
                                    text = "切换",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = FontWeight.Bold,
                                    color = ext.warning,
                                )
                                Text(
                                    text = latestOnset.label,
                                    style = NexusNumericStyles.monoBadge,
                                    fontWeight = FontWeight.Bold,
                                    color = ext.warning,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                        }
                    }
                }
            }

            NexusProportionBar(
                firstBytes = downloadTotalBytes,
                secondBytes = uploadTotalBytes,
                firstColor = ext.telemetryDownload,
                secondColor = ext.telemetryUpload,
            )
        }
    }
}

@Composable
private fun ChannelReadoutColumn(
    label: String,
    rateBps: Long,
    totalBytes: Long,
    accentColor: Color,
    dashedLegend: Boolean,
    modifier: Modifier = Modifier,
) {
    val (figureValue, figureUnit) = remember(rateBps) { splitTrafficRate(rateBps) }
    val unitColor = MaterialTheme.colorScheme.onSurfaceVariant
    val figureText = remember(figureValue, figureUnit, unitColor, accentColor) {
        buildAnnotatedString {
            withStyle(
                SpanStyle(
                    color = accentColor,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.ExtraBold,
                    fontSize = 19.sp,
                    letterSpacing = (-0.3).sp,
                    fontFeatureSettings = "tnum",
                ),
            ) {
                append(figureValue)
            }
            withStyle(
                SpanStyle(
                    color = unitColor,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    fontSize = 11.sp,
                    fontFeatureSettings = "tnum",
                ),
            ) {
                append(" ")
                append(figureUnit)
            }
        }
    }

    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(5.dp),
        ) {
            if (dashedLegend) {
                Row(horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                    Box(Modifier.width(5.dp).height(2.5.dp).background(accentColor))
                    Box(Modifier.width(4.dp).height(2.5.dp).background(accentColor))
                }
            } else {
                Box(Modifier.width(10.dp).height(2.5.dp).background(accentColor))
            }
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
            )
            Spacer(Modifier.weight(1f))
            Text(
                text = formatTrafficBytes(totalBytes),
                style = NexusNumericStyles.monoBadge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                softWrap = false,
            )
        }
        Text(
            text = figureText,
            maxLines = 1,
            softWrap = false,
            overflow = TextOverflow.Ellipsis,
        )
    }
}
