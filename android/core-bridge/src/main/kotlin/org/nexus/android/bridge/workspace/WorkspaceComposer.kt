package org.nexus.android.bridge.workspace

import org.json.JSONObject
import org.nexus.android.bridge.core.CoreProcessSupervisor
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
        val raw = supervisor.composeWorkspace(
            workspaceFile = workspaceFile,
            hostFile = hostFile,
            secretsDir = secretsDir,
            activeProfileId = activeProfileId,
            emitKdlFile = emitKdlFile,
        )
        val parsed = parseComposeResultJson(raw.output, fallbackOk = raw.ok)
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
    }
}
