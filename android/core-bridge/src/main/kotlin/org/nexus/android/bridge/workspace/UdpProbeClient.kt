package org.nexus.android.bridge.workspace

import org.nexus.android.bridge.core.CoreProcessSupervisor

enum class UdpProbeKind(val wire: String, val label: String) {
    STUN("stun", "STUN"),
    DNS("dns", "DNS"),
    NTP("ntp", "NTP");

    companion object {
        fun fromWire(raw: String?): UdpProbeKind =
            entries.firstOrNull { it.wire == raw?.trim()?.lowercase() } ?: STUN
    }
}

data class UdpProbeResult(
    val ok: Boolean,
    val kind: String,
    val viaSocks5: Boolean = false,
    val rttMs: Long = -1L,
    val attempts: Int = 0,
    val detail: String = "",
    val error: String = "",
)

/**
 * Bridge to `libnexus.so tools udp-probe --kind <ntp|dns|stun> [--socks5 ...] --json`.
 */
class UdpProbeClient(
    private val supervisor: CoreProcessSupervisor,
) {
    suspend fun probe(
        kind: UdpProbeKind,
        socks5Listen: String = "",
        target: String = "",
        timeoutMs: Int = 3_000,
        attempts: Int = 2,
    ): UdpProbeResult {
        val args = buildList {
            add("tools")
            add("udp-probe")
            add("--kind")
            add(kind.wire)
            if (target.isNotBlank()) {
                add("--target")
                add(target.trim())
            }
            if (socks5Listen.isNotBlank()) {
                add("--socks5")
                add(socks5Listen.trim())
            }
            add("--timeout-ms")
            add(timeoutMs.coerceIn(500, 15_000).toString())
            add("--attempts")
            add(attempts.coerceIn(1, 5).toString())
            add("--json")
        }
        val raw = supervisor.runCoreCommand(args, timeoutSeconds = 12L)
        return parseProbeResultJson(raw.output, fallbackKind = kind.wire, fallbackOk = raw.ok)
    }

    companion object {
        fun parseProbeResultJson(
            rawOutput: String,
            fallbackKind: String = "stun",
            fallbackOk: Boolean = false,
        ): UdpProbeResult {
            val obj = WorkspaceSyncBridge.extractJsonObject(rawOutput)
                ?: return UdpProbeResult(
                    ok = false,
                    kind = fallbackKind,
                    error = rawOutput.trim().ifEmpty { "Empty udp-probe response" },
                )
            val ok = obj.optBoolean("ok", fallbackOk)
            val err = obj.optString("error", "")
            return UdpProbeResult(
                ok = ok && err.isEmpty(),
                kind = obj.optString("kind", fallbackKind).ifBlank { fallbackKind },
                viaSocks5 = obj.optBoolean("via_socks5", false),
                rttMs = obj.optLong("rtt_ms", -1L),
                attempts = obj.optInt("attempts", 0),
                detail = obj.optString("detail", ""),
                error = if (!ok && err.isEmpty()) "UDP 探测失败" else err,
            )
        }
    }
}
