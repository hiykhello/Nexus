package org.nexus.android.bridge.workspace

import org.json.JSONObject
import org.nexus.android.bridge.core.CoreProcessSupervisor
import org.nexus.android.bridge.profile.SecretFileIO
import java.io.File

data class ComposeResult(
    val ok: Boolean,
    val activeTag: String = "",
    val selectorTag: String = "proxy",
    val selectorMembers: List<String> = emptyList(),
    val warnings: List<String> = emptyList(),
    val errors: List<String> = emptyList(),
    val secretFiles: List<String> = emptyList(),
    val kdl: String = "",
)

/**
 * Single-source Core workspace composer bridge + TUN zero-restart live-switch decision logic.
 */
class WorkspaceComposer(
    private val supervisor: CoreProcessSupervisor,
) {
    suspend fun composeWorkspace(
        workspaceFile: File,
        hostFile: File,
        secretsDir: File,
        activeProfileId: String,
        emitKdlFile: File,
    ): ComposeResult {
        secretsDir.mkdirs()
        emitKdlFile.parentFile?.mkdirs()
        val hostCfg = runCatching { AndroidHostConfig.fromJson(hostFile.readText(Charsets.UTF_8)) }.getOrNull()
        var tempHostFile: File? = null
        val effectiveHostFile = if (
            hostCfg != null &&
            hostCfg.android.runMode == AndroidRunMode.PROXY_ONLY &&
            !hostCfg.android.enableLocalProxy &&
            (hostCfg.android.enableHttp || hostCfg.android.enableSocks)
        ) {
            val tmp = File(hostFile.parentFile ?: secretsDir, ".compose-host-shim.json")
            val shim = hostCfg.copy(android = hostCfg.android.copy(enableLocalProxy = true))
            SecretFileIO.atomicWriteSecret0600(tmp, shim.toJson(indentSpaces = 2, includeSecrets = false))
            tempHostFile = tmp
            tmp
        } else {
            hostFile
        }
        val raw = try {
            supervisor.composeWorkspace(
                workspaceFile = workspaceFile,
                hostFile = effectiveHostFile,
                secretsDir = secretsDir,
                activeProfileId = activeProfileId,
                emitKdlFile = emitKdlFile,
            )
        } finally {
            tempHostFile?.let { WorkspaceSyncBridge.wipeAndDelete(it) }
        }
        var parsed = parseComposeResultJson(raw.output, fallbackOk = raw.ok)
        if (parsed.ok && hostCfg != null && parsed.kdl.isNotBlank()) {
            val overlaid = applyAndroidInboundsOverlay(parsed.kdl, hostCfg.android)
            if (overlaid != parsed.kdl) {
                SecretFileIO.atomicWriteSecret0600(emitKdlFile, overlaid)
                parsed = parsed.copy(kdl = overlaid)
            }
        }
        if (parsed.ok) {
            ProfileReplacement.gcOrphanSecretFiles(
                secretsDir = secretsDir,
                activeSecretFiles = parsed.secretFiles,
                composeOk = true,
            )
        }
        return parsed
    }

    companion object {
        fun parseComposeResultJson(rawOutput: String, fallbackOk: Boolean = false): ComposeResult {
            val trimmed = rawOutput.trim()
            if (trimmed.isEmpty()) {
                return ComposeResult(
                    ok = false,
                    errors = listOf("Empty response from nexus workspace compose"),
                )
            }
            val jsonStart = trimmed.indexOf('{')
            val jsonEnd = trimmed.lastIndexOf('}')
            if (jsonStart < 0 || jsonEnd <= jsonStart) {
                return ComposeResult(
                    ok = false,
                    errors = listOf(trimmed.take(512)),
                )
            }
            val slice = trimmed.substring(jsonStart, jsonEnd + 1)
            return runCatching {
                val obj = JSONObject(slice)
                val ok = obj.optBoolean("ok", fallbackOk)
                val errors = WorkspaceJsonCodec.readStringList(obj.optJSONArray("errors"))
                ComposeResult(
                    ok = ok && errors.isEmpty(),
                    activeTag = obj.optString("active_tag", ""),
                    selectorTag = obj.optString("selector_tag", "proxy").ifBlank { "proxy" },
                    selectorMembers = WorkspaceJsonCodec.readStringList(obj.optJSONArray("selector_members")),
                    warnings = WorkspaceJsonCodec.readStringList(obj.optJSONArray("warnings")),
                    errors = if (!ok && errors.isEmpty()) listOf("Workspace compose failed") else errors,
                    secretFiles = WorkspaceJsonCodec.readStringList(obj.optJSONArray("secret_files")),
                    kdl = obj.optString("kdl", ""),
                )
            }.getOrElse { err ->
                ComposeResult(
                    ok = false,
                    errors = listOf("Invalid composer JSON: ${err.message ?: trimmed.take(256)}"),
                )
            }
        }

        /**
         * Mirrors Core `src/provider/workspace_detail.cppm:sanitize_tag` verbatim so Android
         * can match non-ASCII / spaced profile remarks against `selector_members` cleanly.
         */
        fun sanitizeTag(raw: String, fallback: String = "node"): String {
            val sb = StringBuilder(raw.length)
            for (ch in raw) {
                when {
                    ch in 'a'..'z' || ch in 'A'..'Z' || ch in '0'..'9' || ch == '-' || ch == '_' -> sb.append(ch)
                    ch == ' ' || ch == '.' || ch == '+' || ch == '/' -> sb.append('-')
                }
            }
            var out = sb.toString().trim('-')
            if (out.isEmpty()) out = fallback
            if (out.length > 56) out = out.substring(0, 56)
            if (out == "direct" || out == "block" || out == "proxy") out += "-node"
            return out
        }

        /**
         * Resolves the Core-emitted tag for [target] when its sanitized base tag is unambiguous
         * across [allProfiles]; returns empty string when a collision would require `-2` suffixes.
         */
        fun resolveUnambiguousTag(target: ProfileItem, allProfiles: List<ProfileItem>): String {
            val base = sanitizeTag(target.remarks.ifEmpty { target.id }, "node")
            val sameCount = allProfiles.count { p ->
                sanitizeTag(p.remarks.ifEmpty { p.id }, "node") == base
            }
            return if (sameCount <= 1) base else ""
        }

        /**
         * Returns true when switching active profile can happen live via Control API
         * (`PUT /v1/groups/<selectorTag>`) without tearing down VPN TUN or restarting core.
         */
        fun canHotSwitchViaSelector(
            running: Boolean,
            targetTag: String,
            selectorTag: String,
            selectorMembers: List<String>,
        ): Boolean {
            if (!running) return false
            if (targetTag.isBlank() || selectorTag.isBlank()) return false
            return targetTag in selectorMembers
        }

        private fun quoteKdl(s: String): String = buildString(s.length + 2) {
            append('"')
            for (ch in s) {
                if (ch == '\\' || ch == '"') append('\\')
                append(ch)
            }
            append('"')
        }

        /**
         * Synthesizes/overlays the `inbounds { ... }` section for Android so any combination of
         * `Mixed`, `HTTP`, and `SOCKS5` local listeners (plus `allowLan` `0.0.0.0` binding) works
         * deterministically across both VPN and Proxy-Only modes.
         */
        fun applyAndroidInboundsOverlay(kdl: String, host: AndroidHostSection): String {
            val nlPos = kdl.indexOf("\ninbounds {\n")
            val blkStart = when {
                nlPos >= 0 -> nlPos + 1
                kdl.startsWith("inbounds {\n") -> 0
                else -> return kdl
            }
            var depth = 0
            var inStr = false
            var blkEnd = -1
            for (i in blkStart until kdl.length) {
                val c = kdl[i]
                if (c == '"' && (i == 0 || kdl[i - 1] != '\\')) inStr = !inStr
                if (inStr) continue
                if (c == '{') depth++
                else if (c == '}') {
                    depth--
                    if (depth == 0) {
                        blkEnd = if (i + 1 < kdl.length && kdl[i + 1] == '\n') i + 2 else i + 1
                        break
                    }
                }
            }
            if (blkEnd <= blkStart) return kdl

            val body = StringBuilder()
            var count = 0
            if (host.runMode == AndroidRunMode.VPN) {
                val mtu = host.tunMtu.coerceIn(1280, 9000)
                body.append("  inbound \"tun-in\" type=\"tun\" {\n    stack \"system\"\n    mtu ")
                    .append(mtu)
                    .append("\n    endpoint-independent-nat #false\n  }\n")
                count++
            }

            fun appendProxyInbound(name: String, proto: String, listenSpec: String) {
                val hp = AndroidHostConfig.parseHostPort(listenSpec) ?: return
                val effHost = if (host.allowLan) {
                    when (hp.first) {
                        "127.0.0.1" -> "0.0.0.0"
                        "::1" -> "::"
                        else -> hp.first
                    }
                } else {
                    hp.first
                }
                body.append("  inbound ").append(quoteKdl(name)).append(" type=").append(quoteKdl(proto))
                    .append(" {\n    listen host=").append(quoteKdl(effHost)).append(" port=").append(hp.second)
                    .append("\n    authentication \"none\"\n  }\n")
                count++
            }

            val anyLocal = host.enableLocalProxy || host.enableHttp || host.enableSocks
            if (host.enableLocalProxy || (host.runMode == AndroidRunMode.PROXY_ONLY && !anyLocal)) {
                appendProxyInbound("local-mixed", "mixed", host.localListen.ifBlank { "127.0.0.1:10808" })
            }
            if (host.enableHttp && host.httpListen.isNotBlank()) {
                appendProxyInbound("local-http", "http", host.httpListen)
            }
            if (host.enableSocks && host.socksListen.isNotBlank()) {
                appendProxyInbound("local-socks", "socks5", host.socksListen)
            }
            if (count == 0) return kdl

            return buildString(kdl.length + 192) {
                append(kdl, 0, blkStart)
                append("inbounds {\n")
                append(body)
                append("}\n")
                append(kdl, blkEnd, kdl.length)
            }
        }
    }
}
