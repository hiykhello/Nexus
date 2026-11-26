package org.nexus.android.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import org.nexus.android.bridge.ipc.OutboundMemberSnapshot
import org.nexus.android.ui.theme.NexusTheme

data class GroupLatencyStats(
    val total: Int,
    val healthyCount: Int,
    val p50Ms: Long?,
    val maxHealthyMs: Long,
    val fastCount: Int,
    val goodCount: Int,
    val slowCount: Int,
    val badCount: Int,
    val unprobedCount: Int,
)

internal fun isLatencyTimeout(latencyMs: Long, state: String): Boolean =
    state.equals("timeout", ignoreCase = true) ||
        state.equals("unreachable", ignoreCase = true) ||
        latencyMs == 0L

/**
 * Computes P50 median latency, max measured healthy latency, and 5-tier bucket counts
 * (`<80ms`, `80–179ms`, `180–349ms`, `>=350ms`/timeout, unprobed) for a policy group.
 */
fun computeGroupLatencyStats(members: List<OutboundMemberSnapshot>): GroupLatencyStats {
    if (members.isEmpty()) {
        return GroupLatencyStats(0, 0, null, 0L, 0, 0, 0, 0, 0)
    }
    var fast = 0
    var good = 0
    var slow = 0
    var bad = 0
    var unprobed = 0
    val measured = ArrayList<Long>(members.size)

    members.forEach { m ->
        val timeout = isLatencyTimeout(m.latencyMs, m.state)
        when {
            timeout -> bad++
            m.latencyMs < 0L -> unprobed++
            else -> {
                measured.add(m.latencyMs)
                when {
                    m.latencyMs < 80L -> fast++
                    m.latencyMs < 180L -> good++
                    m.latencyMs < 350L -> slow++
                    else -> bad++
                }
            }
        }
    }
    measured.sort()
    val p50 = if (measured.isEmpty()) {
        null
    } else {
        val mid = measured.size / 2
        if (measured.size % 2 == 1) measured[mid] else (measured[mid - 1] + measured[mid]) / 2L
    }
    val maxHealthy = measured.lastOrNull() ?: 0L
    return GroupLatencyStats(
        total = members.size,
        healthyCount = measured.size,
        p50Ms = p50,
        maxHealthyMs = maxHealthy,
        fastCount = fast,
        goodCount = good,
        slowCount = slow,
        badCount = bad,
        unprobedCount = unprobed,
    )
}

/**
 * Returns the relative width fraction `[0.06, 1.0]` for a healthy node's background meter,
 * or `0f` for timeout / unprobed members.
 */
fun computeMemberRelativeFraction(
    latencyMs: Long,
    state: String,
    maxHealthyMs: Long,
): Float {
    if (maxHealthyMs <= 0L || latencyMs <= 0L || isLatencyTimeout(latencyMs, state)) return 0f
    return (latencyMs.toFloat() / maxHealthyMs.toFloat()).coerceIn(0.06f, 1f)
}

/**
 * Flat `3.dp` (or `2.dp` in rail) 5-tier Latency Spectrum Bar rendered purely in `drawBehind`
 * with `0ms` instantaneous state reflection and zero gradients.
 */
@Composable
internal fun LatencySpectrumBar(
    stats: GroupLatencyStats,
    modifier: Modifier = Modifier,
    height: Dp = 3.dp,
) {
    val ext = NexusTheme.colors
    val total = stats.total
    val trackColor = ext.insetSurface
    val segments = listOf(
        stats.fastCount to ext.success,
        stats.goodCount to ext.warning,
        stats.slowCount to ext.slow,
        stats.badCount to ext.danger,
        stats.unprobedCount to ext.muted.copy(alpha = 0.45f),
    )

    Box(
        modifier = modifier
            .fillMaxWidth()
            .height(height)
            .clip(CircleShape)
            .drawBehind {
                drawRect(color = trackColor)
                if (total <= 0 || size.width <= 0f) return@drawBehind
                val nonZero = segments.count { it.first > 0 }
                val gapPx = if (nonZero > 1) 1.5.dp.toPx() else 0f
                val totalGap = gapPx * (nonZero - 1).coerceAtLeast(0)
                val usableW = (size.width - totalGap).coerceAtLeast(0f)
                var cursorX = 0f
                var drawn = 0
                segments.forEach { (count, color: Color) ->
                    if (count > 0) {
                        val w = usableW * (count.toFloat() / total.toFloat())
                        if (w > 0.5f) {
                            drawRect(
                                color = color,
                                topLeft = Offset(cursorX, 0f),
                                size = Size(w, size.height),
                            )
                        }
                        cursorX += w
                        drawn++
                        if (drawn < nonZero) cursorX += gapPx
                    }
                }
            },
    )
}
