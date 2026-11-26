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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.nexus.android.bridge.ipc.ActiveConnectionSnapshot
import org.nexus.android.bridge.ipc.LiveStatusSnapshot
import org.nexus.android.bridge.ipc.LogRingEntry
import org.nexus.android.bridge.ipc.MetricsSummary
import org.nexus.android.bridge.ipc.OutboundGroupSnapshot
import org.nexus.android.bridge.ipc.OutboundMemberSnapshot
import org.nexus.android.bridge.ipc.WsEvent
import org.nexus.android.bridge.ipc.WsUpgradeRejectedException

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
    var wsActive by mutableStateOf(false)
    var wsLiveConnections by mutableStateOf<List<ActiveConnectionSnapshot>?>(null)

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
        wsActive = false
        wsLiveConnections = null
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
    wsStream: ((channels: List<String>, since: Long, intervalMs: Int) -> Flow<WsEvent>)? = null,
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
    val latestWsStream by rememberUpdatedState(wsStream)
    val latestStatusStream by rememberUpdatedState(statusStream)
    val latestLogsStream by rememberUpdatedState(logsStream)
    val latestLogLevel by rememberUpdatedState(logLevel)
    val latestLogSearch by rememberUpdatedState(logSearch)

    val onLogsTab = currentTab == NexusTab.LOGS
    val onConnectionsTab = currentTab == NexusTab.CONNECTIONS
    var wsFallbackToSse by remember(running, powerSave) { mutableStateOf(false) }

    // Primary lifecycle-aware telemetry loop:
    // 1. Prefers single multiplexed RFC 6455 WebSocket (/v1/ws) for metrics + active tab channels
    // 2. Falls back transparently to existing NexusSseClient (/v1/status + /v1/logs) on upgrade rejection
    // 3. Preserves throttled 4s polling when powerSave is enabled
    LaunchedEffect(running, powerSave, startedAtMs, onLogsTab, onConnectionsTab, lifecycleOwner, previewMetrics) {
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

            if (powerSave) {
                state.logsSseActive = false
                state.wsActive = false
                state.wsLiveConnections = null
                while (isActive) {
                    ingestSample(latestRefreshMetrics())
                    delay(4_000L)
                }
                return@repeatOnLifecycle
            }

            val wsFactory = latestWsStream
            if (wsFactory != null && !wsFallbackToSse) {
                val channels = buildList {
                    add("metrics")
                    if (onLogsTab) add("logs")
                    if (onConnectionsTab) add("connections")
                }
                var sinceSeq = state.ringLogs.maxOfOrNull { it.seq } ?: 0L
                if (onLogsTab) {
                    val initial = latestFetchLogs(latestLogLevel, latestLogSearch)
                    state.ringLogs = initial
                    sinceSeq = initial.maxOfOrNull { it.seq } ?: sinceSeq
                }
                if (!onConnectionsTab) state.wsLiveConnections = null
                try {
                    wsFactory(channels, sinceSeq, 1_000).collect { ev ->
                        when (ev) {
                            is WsEvent.Connected -> {
                                state.wsActive = true
                                if (onLogsTab) state.logsSseActive = true
                            }
                            is WsEvent.Metrics -> ingestSample(ev.status.toMetricsSummary())
                            is WsEvent.Log -> state.appendLogEntry(ev.entry)
                            is WsEvent.Connections -> state.wsLiveConnections = ev.connections
                        }
                    }
                    return@repeatOnLifecycle
                } catch (ce: CancellationException) {
                    throw ce
                } catch (_: WsUpgradeRejectedException) {
                    wsFallbackToSse = true
                } catch (_: Throwable) {
                    wsFallbackToSse = true
                } finally {
                    if (wsFallbackToSse) state.wsActive = false
                    if (!onLogsTab || wsFallbackToSse) state.logsSseActive = false
                    if (!onConnectionsTab || wsFallbackToSse) state.wsLiveConnections = null
                }
            }

            // Fallback path: existing SSE streams (status + logs) or 1s polling
            state.wsActive = false
            state.wsLiveConnections = null
            coroutineScope {
                if (onLogsTab) {
                    launch {
                        val initial = latestFetchLogs(latestLogLevel, latestLogSearch)
                        state.ringLogs = initial
                        val streamFactory = latestLogsStream
                        if (streamFactory != null) {
                            state.logsSseActive = true
                            try {
                                val sinceSeq = initial.maxOfOrNull { it.seq } ?: 0L
                                streamFactory(sinceSeq, latestLogLevel, latestLogSearch).collect { entry ->
                                    state.appendLogEntry(entry)
                                }
                            } finally {
                                state.logsSseActive = false
                            }
                        }
                    }
                } else {
                    state.logsSseActive = false
                }
                val sseFactory = latestStatusStream
                if (sseFactory != null) {
                    sseFactory().collect { snap ->
                        ingestSample(snap.toMetricsSummary())
                    }
                } else {
                    while (isActive) {
                        ingestSample(latestRefreshMetrics())
                        delay(1_000L)
                    }
                }
            }
        }
    }

    return state
}
