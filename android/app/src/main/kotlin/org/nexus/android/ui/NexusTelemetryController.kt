package org.nexus.android.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.isActive
import org.nexus.android.bridge.ipc.LiveStatusSnapshot
import org.nexus.android.bridge.ipc.LogRingEntry
import org.nexus.android.bridge.ipc.MetricsSummary
import org.nexus.android.bridge.ipc.OutboundGroupSnapshot
import org.nexus.android.bridge.ipc.OutboundMemberSnapshot

internal const val MAX_SPARKLINE_SAMPLES = 32
private const val MAX_RING_LOGS = 500

@Stable
internal class NexusTelemetryState(
    initialMetrics: MetricsSummary,
    initialDownloadSamples: List<Long>,
    initialUploadSamples: List<Long>,
    initialActiveExit: ActiveExitSummary,
    initialQuickNodes: List<OutboundMemberSnapshot>,
    initialMemoryText: String,
    initialUptimeMs: Long,
) {
    var metrics by mutableStateOf(initialMetrics)
    var downloadRateBps by mutableLongStateOf(initialDownloadSamples.lastOrNull() ?: 0L)
    var uploadRateBps by mutableLongStateOf(initialUploadSamples.lastOrNull() ?: 0L)
    var peakRateBps by mutableLongStateOf(
        maxOf(initialDownloadSamples.maxOrNull() ?: 0L, initialUploadSamples.maxOrNull() ?: 0L),
    )
    var downloadSamples by mutableStateOf(initialDownloadSamples)
    var uploadSamples by mutableStateOf(initialUploadSamples)
    var activeExit by mutableStateOf(initialActiveExit)
    var quickNodes by mutableStateOf(initialQuickNodes)
    var memoryText by mutableStateOf(initialMemoryText)
    var uptimeMs by mutableLongStateOf(initialUptimeMs)
    var ringLogs by mutableStateOf<List<UiLogLine>>(emptyList())
    var logsSseActive by mutableStateOf(false)

    fun resetOffline() {
        downloadRateBps = 0L
        uploadRateBps = 0L
        peakRateBps = 0L
        uptimeMs = 0L
        downloadSamples = List(MAX_SPARKLINE_SAMPLES) { 0L }
        uploadSamples = List(MAX_SPARKLINE_SAMPLES) { 0L }
        activeExit = ActiveExitSummary()
        quickNodes = emptyList()
        logsSseActive = false
    }

    fun applyPrimaryGroups(loaded: List<OutboundGroupSnapshot>, preferredTag: String = activeExit.groupTag) {
        val primary = loaded.firstOrNull { preferredTag.isNotEmpty() && it.tag == preferredTag } ?: loaded.firstOrNull()
        if (primary != null) {
            val sel = primary.members.firstOrNull { it.selected }
            activeExit = ActiveExitSummary(
                groupTag = primary.tag,
                memberName = sel?.name ?: primary.active,
                latencyMs = sel?.latencyMs ?: -1L,
                state = sel?.state ?: "unknown",
            )
            quickNodes = primary.members.take(6)
        }
    }

    fun appendLogEntry(entry: LogRingEntry) {
        val line = UiLogLine(seq = entry.seq, text = "[${entry.level}] ${entry.domain}: ${entry.message}")
        val cur = ringLogs
        if (cur.any { it.seq == line.seq }) return
        ringLogs = if (cur.size >= MAX_RING_LOGS) cur.drop(cur.size - MAX_RING_LOGS + 1) + line else cur + line
    }
}

@Composable
internal fun rememberNexusTelemetryState(
    running: Boolean,
    powerSave: Boolean,
    startedAtMs: Long,
    currentTab: NexusTab,
    logLevel: String,
    logSearch: String,
    lifecycleOwner: LifecycleOwner,
    onRefreshMetrics: suspend () -> MetricsSummary,
    onFetchGroups: suspend () -> List<OutboundGroupSnapshot>,
    onFetchLogs: suspend (String, String) -> List<UiLogLine>,
    statusStream: (() -> Flow<LiveStatusSnapshot>)? = null,
    logsStream: ((since: Long, level: String, search: String) -> Flow<LogRingEntry>)? = null,
    previewMetrics: MetricsSummary? = null,
    previewDownloadSamples: List<Long>? = null,
    previewUploadSamples: List<Long>? = null,
    previewActiveExit: ActiveExitSummary? = null,
    previewQuickNodes: List<OutboundMemberSnapshot>? = null,
    previewMemoryText: String? = null,
): NexusTelemetryState {
    val state = remember(
        previewMetrics,
        previewDownloadSamples,
        previewUploadSamples,
        previewActiveExit,
        previewQuickNodes,
        previewMemoryText,
    ) {
        NexusTelemetryState(
            initialMetrics = previewMetrics ?: MetricsSummary(),
            initialDownloadSamples = previewDownloadSamples ?: List(MAX_SPARKLINE_SAMPLES) { 0L },
            initialUploadSamples = previewUploadSamples ?: List(MAX_SPARKLINE_SAMPLES) { 0L },
            initialActiveExit = previewActiveExit ?: ActiveExitSummary(),
            initialQuickNodes = previewQuickNodes ?: emptyList(),
            initialMemoryText = previewMemoryText ?: sampleRuntimeMemoryText(),
            initialUptimeMs = if (running && startedAtMs > 0L) (System.currentTimeMillis() - startedAtMs).coerceAtLeast(0L) else 0L,
        )
    }

    val latestRefreshMetrics by rememberUpdatedState(onRefreshMetrics)
    val latestFetchGroups by rememberUpdatedState(onFetchGroups)
    val latestFetchLogs by rememberUpdatedState(onFetchLogs)
    val latestStatusStream by rememberUpdatedState(statusStream)
    val latestLogsStream by rememberUpdatedState(logsStream)

    // Lifecycle-aware SSE / polling status & sparkline loop (pauses cleanly in background / powerSave)
    LaunchedEffect(running, powerSave, startedAtMs, lifecycleOwner, previewMetrics) {
        if (previewMetrics != null) return@LaunchedEffect
        if (!running) {
            state.resetOffline()
            return@LaunchedEffect
        }
        lifecycleOwner.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            var prevMetrics: MetricsSummary? = null
            var prevTimestampMs = 0L
            var groupTick = 0

            suspend fun ingestSample(latest: MetricsSummary) {
                val now = System.currentTimeMillis()
                if (startedAtMs > 0L) {
                    state.uptimeMs = (now - startedAtMs).coerceAtLeast(0L)
                }
                state.metrics = latest
                val prior = prevMetrics
                if (prior != null && prevTimestampMs > 0L) {
                    val elapsedMs = (now - prevTimestampMs).coerceAtLeast(250L)
                    val downRate = ((latest.downloadBytes - prior.downloadBytes).coerceAtLeast(0L) * 1000L) / elapsedMs
                    val upRate = ((latest.uploadBytes - prior.uploadBytes).coerceAtLeast(0L) * 1000L) / elapsedMs
                    state.downloadRateBps = downRate
                    state.uploadRateBps = upRate
                    if (downRate > state.peakRateBps) state.peakRateBps = downRate
                    if (upRate > state.peakRateBps) state.peakRateBps = upRate
                    state.downloadSamples = state.downloadSamples.drop(1) + downRate
                    state.uploadSamples = state.uploadSamples.drop(1) + upRate
                }
                prevMetrics = latest
                prevTimestampMs = now
                if (groupTick % 5 == 0) {
                    state.applyPrimaryGroups(latestFetchGroups())
                    state.memoryText = sampleRuntimeMemoryText()
                }
                groupTick++
            }

            val sseFactory = latestStatusStream
            if (!powerSave && sseFactory != null) {
                sseFactory().collect { snap ->
                    ingestSample(snap.toMetricsSummary())
                }
            } else {
                while (isActive) {
                    ingestSample(latestRefreshMetrics())
                    delay(if (powerSave) 4_000L else 1_000L)
                }
            }
        }
    }

    // Lifecycle-aware SSE log stream while on Logs tab (pauses on powerSave / off-tab)
    LaunchedEffect(running, powerSave, currentTab, logLevel, logSearch, lifecycleOwner, previewMetrics) {
        if (!running || previewMetrics != null || currentTab != NexusTab.LOGS) {
            state.logsSseActive = false
            return@LaunchedEffect
        }
        lifecycleOwner.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            val initial = latestFetchLogs(logLevel, logSearch)
            state.ringLogs = initial
            val streamFactory = latestLogsStream
            if (!powerSave && streamFactory != null) {
                state.logsSseActive = true
                try {
                    val sinceSeq = initial.maxOfOrNull { it.seq } ?: 0L
                    streamFactory(sinceSeq, logLevel, logSearch).collect { entry ->
                        state.appendLogEntry(entry)
                    }
                } finally {
                    state.logsSseActive = false
                }
            } else {
                state.logsSseActive = false
            }
        }
    }

    return state
}
