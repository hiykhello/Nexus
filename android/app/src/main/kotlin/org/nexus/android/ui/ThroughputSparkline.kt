package org.nexus.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
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
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.layout.layout
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.nexus.android.ui.theme.NexusTheme
import kotlin.math.abs
import kotlin.math.exp
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt

private const val WAVE_SIGMA = 1.5
private const val WAVE_RADIUS = 4
private const val WAVE_MIN_SCALE_BPS = 8f * 1024f
private const val SPEED_TILE_ASPECT_RATIO = 1.45f

private val GAUSSIAN_KERNEL = FloatArray(WAVE_RADIUS + 1) { d ->
    exp(-(d * d).toDouble() / (2.0 * WAVE_SIGMA * WAVE_SIGMA)).toFloat()
}

private class WaveScratchBuffers(initialLen: Int = 40) {
    var padded = FloatArray(initialLen)
    var heights = FloatArray(initialLen)
    var slopes = FloatArray(initialLen)

    fun ensureCapacity(len: Int) {
        if (padded.size < len) {
            padded = FloatArray(len)
            heights = FloatArray(len)
            slopes = FloatArray(len)
        } else {
            padded.fill(0f, 0, len)
            heights.fill(0f, 0, len)
            slopes.fill(0f, 0, len)
        }
    }
}

/**
 * Dual-channel Bento `NetworkSpeedCard`:
 * - Zero `BoxWithConstraints` subcomposition (single-pass `Modifier.layout` aspect sizing)
 * - Reusable `Path` (`rewind()`) + preallocated `WaveScratchBuffers` (zero per-tick FloatArray GC)
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
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        SpeedWaveTile(
            label = "下载",
            arrow = "↓",
            running = running,
            rateBps = downloadRateBps,
            totalBytes = downloadTotalBytes,
            samples = downloadSamples,
            accentColor = ext.telemetryDownload,
            modifier = Modifier.weight(1f),
        )
        SpeedWaveTile(
            label = "上传",
            arrow = "↑",
            running = running,
            rateBps = uploadRateBps,
            totalBytes = uploadTotalBytes,
            samples = uploadSamples,
            accentColor = ext.telemetryUpload,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun SpeedWaveTile(
    label: String,
    arrow: String,
    running: Boolean,
    rateBps: Long,
    totalBytes: Long,
    samples: List<Long>,
    accentColor: Color,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val fontScale = LocalDensity.current.fontScale
    val tileShape = RoundedCornerShape(20.dp)
    val linePath = remember { Path() }
    val areaPath = remember { Path() }
    val scratch = remember { WaveScratchBuffers() }
    val (figureValue, figureUnit) = remember(rateBps) { splitTrafficRate(rateBps) }
    val activeSamples = if (running) samples else emptyList()

    val unitColor = MaterialTheme.colorScheme.onSurfaceVariant
    val figureText = remember(figureValue, figureUnit, unitColor) {
        buildAnnotatedString {
            withStyle(
                SpanStyle(
                    fontFamily = FontFamily.SansSerif,
                    fontWeight = FontWeight.ExtraBold,
                    fontSize = 22.sp,
                    letterSpacing = (-0.6).sp,
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
                    fontSize = 12.sp,
                    fontFeatureSettings = "tnum",
                ),
            ) {
                append(" ")
                append(figureUnit)
            }
        }
    }

    val aspectMinHeightModifier = Modifier.layout { measurable, constraints ->
        val minH = 126.dp.roundToPx()
        val maxH = 148.dp.roundToPx()
        val targetMinH = if (constraints.hasBoundedWidth) {
            (constraints.maxWidth / SPEED_TILE_ASPECT_RATIO).roundToInt().coerceIn(minH, maxH)
        } else {
            minH
        }
        val adjusted = constraints.copy(
            minHeight = max(constraints.minHeight, targetMinH).coerceAtMost(constraints.maxHeight),
        )
        val placeable = measurable.measure(adjusted)
        layout(placeable.width, placeable.height) {
            placeable.placeRelative(0, 0)
        }
    }

    Surface(
        modifier = modifier
            .fillMaxWidth()
            .then(aspectMinHeightModifier),
        shape = tileShape,
        color = Color.Transparent,
        border = BorderStroke(
            width = 1.dp,
            color = if (running) accentColor.copy(alpha = 0.24f) else ext.hairline,
        ),
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(tileShape)
                .clipToBounds()
                .background(Brush.verticalGradient(listOf(ext.cardGradientTop, ext.cardGradientBottom)))
                .drawWithCache {
                    val bleedPx = 2.dp.toPx()
                    val clampedScale = fontScale.coerceIn(1f, 2.2f)
                    val scaledTextBandPx = 18.dp.toPx() + 58.dp.toPx() * clampedScale
                    val minWaveBandPx = 28.dp.toPx()
                    val chartTopPx = scaledTextBandPx.coerceIn(
                        minimumValue = 72.dp.toPx().coerceAtMost(size.height * 0.58f),
                        maximumValue = (size.height - minWaveBandPx).coerceAtLeast(size.height * 0.58f),
                    )
                    val strokePx = 2.2.dp.toPx()
                    val stroke = Stroke(
                        width = strokePx,
                        cap = StrokeCap.Round,
                        join = StrokeJoin.Round,
                    )
                    val glowStroke = Stroke(
                        width = 6.dp.toPx(),
                        cap = StrokeCap.Round,
                        join = StrokeJoin.Round,
                    )
                    val glowColor = accentColor.copy(alpha = if (ext.isDark) 0.28f else 0.16f)
                    val topStrokeColor = if (ext.isDark) lerp(accentColor, Color.White, 0.20f) else accentColor
                    val fillBrush = Brush.verticalGradient(
                        colorStops = arrayOf(
                            0.0f to accentColor.copy(alpha = if (ext.isDark) 0.42f else 0.30f),
                            0.58f to accentColor.copy(alpha = if (ext.isDark) 0.16f else 0.10f),
                            1.0f to accentColor.copy(alpha = if (ext.isDark) 0.02f else 0.01f),
                        ),
                        startY = chartTopPx,
                        endY = size.height + bleedPx,
                    )

                    val hasCurve = buildSpeedWavePaths(
                        samples = activeSamples,
                        width = size.width + bleedPx * 2f,
                        leftOffset = -bleedPx,
                        chartTop = chartTopPx,
                        baselineY = size.height + bleedPx,
                        strokeWidthPx = strokePx,
                        linePath = linePath,
                        areaPath = areaPath,
                        scratch = scratch,
                    )

                    onDrawBehind {
                        if (hasCurve) {
                            drawPath(path = areaPath, brush = fillBrush)
                            drawPath(path = linePath, color = glowColor, style = glowStroke)
                            drawPath(path = linePath, color = topStrokeColor, style = stroke)
                        }
                    }
                },
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
                    .height(1.dp)
                    .background(
                        Brush.horizontalGradient(
                            listOf(Color.Transparent, ext.topSpeculum, ext.topSpeculum, Color.Transparent),
                        ),
                    ),
            )
            val extraWaveClearance = ((fontScale - 1f).coerceIn(0f, 1.2f) * 32f).dp
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 14.dp, end = 12.dp, top = 12.dp, bottom = 10.dp + extraWaveClearance),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(
                        text = arrow,
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.ExtraBold,
                        color = accentColor,
                        maxLines = 1,
                    )
                    Text(
                        text = label,
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
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
                Text(
                    text = "总计 ${formatTrafficBytes(totalBytes)}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    softWrap = false,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

private fun buildSpeedWavePaths(
    samples: List<Long>,
    width: Float,
    leftOffset: Float,
    chartTop: Float,
    baselineY: Float,
    strokeWidthPx: Float,
    linePath: Path,
    areaPath: Path,
    scratch: WaveScratchBuffers,
): Boolean {
    linePath.rewind()
    areaPath.rewind()
    if (width <= 0f || baselineY <= chartTop || samples.isEmpty()) return false
    var anyPositive = false
    for (i in samples.indices) {
        if (samples[i] > 0L) {
            anyPositive = true
            break
        }
    }
    if (!anyPositive) return false

    val capacity = max(samples.size, 12)
    val len = capacity + WAVE_RADIUS + 1
    scratch.ensureCapacity(len)
    val padded = scratch.padded
    val heights = scratch.heights
    val slopes = scratch.slopes

    val copyCount = min(samples.size, len)
    val srcStart = samples.size - copyCount
    val dstStart = len - copyCount
    for (i in 0 until copyCount) {
        padded[dstStart + i] = samples[srcStart + i].coerceAtLeast(0L).toFloat()
    }

    var peakHeight = 0f
    for (i in 0 until len) {
        var sum = 0f
        var weight = 0f
        val from = max(i - WAVE_RADIUS, 0)
        val to = min(i + WAVE_RADIUS, len - 1)
        for (j in from..to) {
            val w = GAUSSIAN_KERNEL[abs(j - i)]
            sum += w * padded[j]
            weight += w
        }
        val blurred = if (weight > 0f) sum / weight else 0f
        heights[i] = blurred
        if (blurred > peakHeight) peakHeight = blurred
    }

    val last = len - 1
    for (i in 1 until last) {
        val raw = (heights[i + 1] - heights[i - 1]) * 0.5f
        val bound = 3f * heights[i]
        slopes[i] = raw.coerceIn(-bound, bound)
    }

    val topScale = max(WAVE_MIN_SCALE_BPS, peakHeight * 1.12f)
    val usableHeight = (baselineY - chartTop - strokeWidthPx).coerceAtLeast(4f)
    val yScale = usableHeight / topScale
    val stepX = width / (capacity - 1).toFloat()
    val firstX = leftOffset + width - last * stepX

    var prevX = firstX
    var prevY = baselineY - heights[0] * yScale
    linePath.moveTo(prevX, prevY)
    for (i in 1 until len) {
        val nextX = prevX + stepX
        val nextY = baselineY - heights[i] * yScale
        linePath.cubicTo(
            prevX + stepX / 3f,
            prevY - slopes[i - 1] * yScale / 3f,
            nextX - stepX / 3f,
            nextY + slopes[i] * yScale / 3f,
            nextX,
            nextY,
        )
        prevX = nextX
        prevY = nextY
    }

    areaPath.addPath(linePath)
    areaPath.lineTo(prevX, baselineY)
    areaPath.lineTo(firstX, baselineY)
    areaPath.close()
    return true
}
