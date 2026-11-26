package org.nexus.android.ui

import androidx.compose.ui.graphics.Path
import kotlin.math.abs
import kotlin.math.exp
import kotlin.math.max
import kotlin.math.min

private const val WAVE_SIGMA = 1.5
private const val WAVE_RADIUS = 4
internal const val WAVE_MIN_SCALE_BPS = 8f * 1024f
internal const val MAX_SPARKLINE_ONSETS = 3

private val GAUSSIAN_KERNEL = FloatArray(WAVE_RADIUS + 1) { d ->
    exp(-(d * d).toDouble() / (2.0 * WAVE_SIGMA * WAVE_SIGMA)).toFloat()
}

data class SparklineOnset(
    val sampleIndex: Int,
    val label: String,
)

/**
 * Advances onset markers one tick leftward along the rolling 1Hz window and drops markers
 * that have scrolled off the left edge (`sampleIndex < 0`).
 */
fun shiftOnsetMarkers(markers: List<SparklineOnset>): List<SparklineOnset> {
    if (markers.isEmpty()) return emptyList()
    return markers
        .mapNotNull { m ->
            val shifted = m.sampleIndex - 1
            if (shifted >= 0) m.copy(sampleIndex = shifted) else null
        }
        .takeLast(MAX_SPARKLINE_ONSETS)
}

/**
 * Appends (or replaces at the same rightmost sample slot) a compact onset event marker.
 */
fun appendOnsetMarker(
    markers: List<SparklineOnset>,
    sampleCount: Int,
    label: String,
): List<SparklineOnset> {
    val clean = label.trim().take(12)
    if (clean.isEmpty()) return markers
    val slot = (sampleCount - 1).coerceAtLeast(0)
    val deduped = markers.filterNot { it.sampleIndex == slot }
    return (deduped + SparklineOnset(sampleIndex = slot, label = clean)).takeLast(MAX_SPARKLINE_ONSETS)
}

internal class WaveScratchBuffers(initialLen: Int = 40) {
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

internal fun computeSharedPeakScaleBps(
    downloadSamples: List<Long>,
    uploadSamples: List<Long>,
): Float {
    var peak = 0L
    for (i in downloadSamples.indices) {
        if (downloadSamples[i] > peak) peak = downloadSamples[i]
    }
    for (i in uploadSamples.indices) {
        if (uploadSamples[i] > peak) peak = uploadSamples[i]
    }
    return max(WAVE_MIN_SCALE_BPS, peak.toFloat() * 1.14f)
}

internal fun onsetSampleX(
    sampleIndex: Int,
    sampleCount: Int,
    width: Float,
    leftOffset: Float,
): Float {
    val capacity = max(sampleCount, 12)
    val clamped = sampleIndex.coerceIn(0, capacity - 1)
    val stepX = width / (capacity - 1).toFloat()
    val rightOffset = (capacity - 1 - clamped).coerceAtLeast(0)
    return leftOffset + width - rightOffset * stepX
}

/**
 * Builds smoothed monotonic-clamped cubic spline paths onto a calibrated shared [topScale]
 * using preallocated [WaveScratchBuffers] and `Path.rewind()` (zero per-tick heap allocations).
 */
internal fun buildCalibratedWavePaths(
    samples: List<Long>,
    topScale: Float,
    width: Float,
    leftOffset: Float,
    chartTop: Float,
    baselineY: Float,
    strokeWidthPx: Float,
    linePath: Path,
    areaPath: Path?,
    scratch: WaveScratchBuffers,
): Boolean {
    linePath.rewind()
    areaPath?.rewind()
    if (width <= 0f || baselineY <= chartTop || samples.isEmpty() || topScale <= 0f) return false
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
        heights[i] = if (weight > 0f) sum / weight else 0f
    }

    val last = len - 1
    for (i in 1 until last) {
        val raw = (heights[i + 1] - heights[i - 1]) * 0.5f
        val bound = 3f * heights[i]
        slopes[i] = raw.coerceIn(-bound, bound)
    }

    val usableHeight = (baselineY - chartTop - strokeWidthPx).coerceAtLeast(4f)
    val yScale = usableHeight / topScale
    val stepX = width / (capacity - 1).toFloat()
    val firstX = leftOffset + width - last * stepX

    var prevX = firstX
    var prevY = (baselineY - heights[0] * yScale).coerceIn(chartTop, baselineY)
    linePath.moveTo(prevX, prevY)
    for (i in 1 until len) {
        val nextX = prevX + stepX
        val nextY = (baselineY - heights[i] * yScale).coerceIn(chartTop, baselineY)
        linePath.cubicTo(
            prevX + stepX / 3f,
            (prevY - slopes[i - 1] * yScale / 3f).coerceIn(chartTop, baselineY),
            nextX - stepX / 3f,
            (nextY + slopes[i] * yScale / 3f).coerceIn(chartTop, baselineY),
            nextX,
            nextY,
        )
        prevX = nextX
        prevY = nextY
    }

    if (areaPath != null) {
        areaPath.addPath(linePath)
        areaPath.lineTo(prevX, baselineY)
        areaPath.lineTo(firstX, baselineY)
        areaPath.close()
    }
    return true
}
