package org.nexus.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
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
 * Unified Dual-Track RX/TX Instrument Sparkline Card:
 * - Single calibrated Y-axis shared by Download (solid `2.2.dp` stroke + matte low-alpha fill)
 *   and Upload (dashed `1.8.dp` stroke, distinguishable without relying on color alone)
 * - Calibrated Peak Scale Ceiling label + 50% horizontal reference hairline
 * - Vertical dashed Onset Marker lines on node/mode switches with top tag for newest event
 * - Zero per-tick heap allocations (`Path.rewind()` + preallocated `WaveScratchBuffers`)
 */
@Composable
fun ThroughputSparklineCard(
    running: Boolean,
    downloadRateBps: Long,
    uploadRateBps: Long,
    @Suppress("UNUSED_PARAMETER") peakRateBps: Long,
    downloadSamples: List<Long>,
    uploadSamples: List<Long>,
    downloadTotalBytes: Long = 0L,
    uploadTotalBytes: Long = 0L,
    onsetMarkers: List<SparklineOnset> = emptyList(),
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val primary = MaterialTheme.colorScheme.primary
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
        if (running) "峰值 ${formatTrafficRate(sharedScaleBps.toLong())}" else "待机"
    }
    val latestOnset = activeOnsets.lastOrNull()

    val a11ySummary = if (running) {
        "下载 ${formatTrafficRate(downloadRateBps)}，上传 ${formatTrafficRate(uploadRateBps)}，$ceilingText" +
            (latestOnset?.let { "，最近切换 ${it.label}" }.orEmpty())
    } else {
        "实时吞吐待机"
    }

    OpticalCard(
        modifier = modifier
            .fillMaxWidth()
            .semantics(mergeDescendants = true) { contentDescription = a11ySummary },
        cornerRadius = 16.dp,
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalAlignment = Alignment.Top,
            ) {
                ChannelReadoutColumn(
                    label = "下载",
                    rateBps = if (running) downloadRateBps else 0L,
                    totalBytes = downloadTotalBytes,
                    accentColor = ext.telemetryDownload,
                    dashedLegend = false,
                    modifier = Modifier.weight(1f),
                )
                ChannelReadoutColumn(
                    label = "上传",
                    rateBps = if (running) uploadRateBps else 0L,
                    totalBytes = uploadTotalBytes,
                    accentColor = ext.telemetryUpload,
                    dashedLegend = true,
                    modifier = Modifier.weight(1f),
                )
            }

            val fontScale = LocalDensity.current.fontScale
            val chartHeight = if (fontScale > 1.3f) 108.dp else 96.dp
            val topReserveDp = (24f * fontScale.coerceIn(1f, 1.55f)).dp

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(chartHeight)
                    .clip(RoundedCornerShape(10.dp))
                    .background(ext.wellSurface.copy(alpha = if (ext.isDark) 0.55f else 0.60f))
                    .clipToBounds()
                    .drawWithCache {
                        val padTop = topReserveDp.toPx()
                        val padBottom = 3.dp.toPx()
                        val baselineY = size.height - padBottom
                        val midY = padTop + (baselineY - padTop) * 0.5f

                        val rxStrokePx = 2.2.dp.toPx()
                        val rxStroke = Stroke(width = rxStrokePx, cap = StrokeCap.Round, join = StrokeJoin.Round)
                        val txStrokePx = 1.8.dp.toPx()
                        val txDash = PathEffect.dashPathEffect(floatArrayOf(5.dp.toPx(), 4.dp.toPx()), 0f)
                        val txStroke = Stroke(
                            width = txStrokePx,
                            cap = StrokeCap.Round,
                            join = StrokeJoin.Round,
                            pathEffect = txDash,
                        )
                        val onsetDash = PathEffect.dashPathEffect(floatArrayOf(3.dp.toPx(), 3.dp.toPx()), 0f)
                        val refDash = PathEffect.dashPathEffect(floatArrayOf(4.dp.toPx(), 4.dp.toPx()), 0f)

                        val rxFillColor = ext.telemetryDownload.copy(alpha = if (ext.isDark) 0.16f else 0.11f)
                        val refLineColor = ext.hairlineStrong.copy(alpha = if (ext.isDark) 0.55f else 0.65f)
                        val onsetColor = primary.copy(alpha = 0.72f)
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
                        val onsetDotRadius = 2.5.dp.toPx()
                        val onsetTopY = padTop + onsetDotRadius

                        onDrawBehind {
                            drawLine(
                                color = refLineColor,
                                start = Offset(0f, midY),
                                end = Offset(size.width, midY),
                                strokeWidth = 1.dp.toPx(),
                                pathEffect = refDash,
                            )
                            if (hasRx) {
                                drawPath(path = rxAreaPath, color = rxFillColor)
                                drawPath(path = rxLinePath, color = ext.telemetryDownload, style = rxStroke)
                            }
                            if (hasTx) {
                                drawPath(path = txLinePath, color = ext.telemetryUpload, style = txStroke)
                            }
                            onsetXs.forEach { x ->
                                drawLine(
                                    color = onsetColor,
                                    start = Offset(x, onsetTopY),
                                    end = Offset(x, baselineY),
                                    strokeWidth = 1.dp.toPx(),
                                    pathEffect = onsetDash,
                                )
                                drawCircle(
                                    color = primary,
                                    radius = onsetDotRadius,
                                    center = Offset(x, onsetTopY),
                                )
                            }
                        }
                    },
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .align(Alignment.TopCenter)
                        .padding(horizontal = 8.dp, vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    if (latestOnset != null) {
                        Surface(
                            modifier = Modifier.weight(1f, fill = false).padding(end = 6.dp),
                            shape = RoundedCornerShape(4.dp),
                            color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.85f),
                        ) {
                            Text(
                                text = "切换 · ${latestOnset.label}",
                                style = NexusNumericStyles.monoBadge,
                                color = MaterialTheme.colorScheme.onPrimaryContainer,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.padding(horizontal = 5.dp, vertical = 1.dp),
                            )
                        }
                    } else {
                        Box(Modifier.size(1.dp))
                    }
                    Text(
                        text = ceilingText,
                        style = NexusNumericStyles.monoBadge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        softWrap = false,
                    )
                }
            }
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
    val figureText = remember(figureValue, figureUnit, unitColor) {
        buildAnnotatedString {
            withStyle(
                SpanStyle(
                    fontFamily = FontFamily.SansSerif,
                    fontWeight = FontWeight.ExtraBold,
                    fontSize = 19.sp,
                    letterSpacing = (-0.5).sp,
                    fontFeatureSettings = "tnum",
                ),
            ) {
                append(figureValue)
            }
            withStyle(
                SpanStyle(
                    color = unitColor,
                    fontFamily = FontFamily.SansSerif,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 11.5.sp,
                    fontFeatureSettings = "tnum",
                ),
            ) {
                append(" ")
                append(figureUnit)
            }
        }
    }

    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(5.dp),
        ) {
            if (dashedLegend) {
                Row(horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                    Box(Modifier.width(5.dp).height(2.dp).background(accentColor, CircleShape))
                    Box(Modifier.width(4.dp).height(2.dp).background(accentColor, CircleShape))
                }
            } else {
                Box(Modifier.size(7.dp).background(accentColor, CircleShape))
            }
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = formatTrafficBytes(totalBytes),
                style = NexusNumericStyles.monoBadge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                softWrap = false,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Text(
            text = figureText,
            color = MaterialTheme.colorScheme.onSurface,
            maxLines = 1,
            softWrap = false,
            overflow = TextOverflow.Ellipsis,
        )
    }
}
