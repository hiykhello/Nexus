package org.nexus.android.bridge.workspace

import org.json.JSONObject
import org.nexus.android.bridge.core.CoreProcessSupervisor
import org.nexus.android.bridge.profile.ProfileRepository
import java.io.File
import java.io.RandomAccessFile
import java.util.UUID

data class ExportShareResult(
    val ok: Boolean,
    val uri: String = "",
    val exportedCount: Int = 0,
    val warnings: List<String> = emptyList(),
    val errors: List<String> = emptyList(),
)

data class ImportShareResult(
    val ok: Boolean,
    val importedIds: List<String> = emptyList(),
    val warnings: List<String> = emptyList(),
    val errors: List<String> = emptyList(),
    val workspaceJson: String = "",
)

data class SealSyncResult(
    val ok: Boolean,
    val revision: Long = 0L,
    val updatedAtMs: Long = 0L,
    val envelopeSha256: String = "",
    val warnings: List<String> = emptyList(),
    val errors: List<String> = emptyList(),
    val envelopeJson: String = "",
)

data class OpenSyncResult(
    val ok: Boolean,
    val revision: Long = 0L,
    val updatedAtMs: Long = 0L,
    val deviceLabel: String = "",
    val warnings: List<String> = emptyList(),
    val errors: List<String> = emptyList(),
    val workspaceJson: String = "",
)

/**
 * Core CLI bridge for `nexus://share/v1/...` portable share bundles and `nexus-sync-v1` E2EE
 * sync envelope sealing/opening. Never passes passphrases on argv — always uses transient `0600`
 * files under [tempDir] (`noBackupFilesDir`) zeroed and deleted in `finally`.
 */
class WorkspaceSyncBridge(
    private val supervisor: CoreProcessSupervisor,
    private val tempDir: File,
) {
    suspend fun exportShare(
        workspaceFile: File,
        profileIds: List<String>,
    ): ExportShareResult {
        val cleanIds = profileIds.map { it.trim() }.filter { it.isNotEmpty() }
        if (cleanIds.isEmpty()) {
            return ExportShareResult(ok = false, errors = listOf("请选择至少一个要分享的档案"))
        }
        val args = buildList {
            add("workspace")
            add("export-share")
            add("--workspace")
            add(workspaceFile.absolutePath)
            cleanIds.forEach { id ->
                add("--id")
                add(id)
            }
            add("--json-result")
        }
        val raw = supervisor.runCoreCommand(args, timeoutSeconds = 10L)
        return parseExportShareJson(raw.output, fallbackOk = raw.ok)
    }

    suspend fun importShare(
        workspaceFile: File,
        uri: String,
        subscriptionId: String = "",
        outWorkspaceFile: File? = null,
    ): ImportShareResult {
        val cleanUri = uri.trim()
        if (!cleanUri.startsWith(SHARE_URI_PREFIX)) {
            return ImportShareResult(ok = false, errors = listOf("无效的 nexus:// 分享链接"))
        }
        val args = buildList {
            add("workspace")
            add("import-share")
            add("--workspace")
            add(workspaceFile.absolutePath)
            add("--uri")
            add(cleanUri)
            if (subscriptionId.isNotBlank()) {
                add("--subscription-id")
                add(subscriptionId.trim())
            }
            if (outWorkspaceFile != null) {
                add("--out-workspace")
                add(outWorkspaceFile.absolutePath)
            }
            add("--json-result")
        }
        val raw = supervisor.runCoreCommand(args, timeoutSeconds = 10L)
        return parseImportShareJson(raw.output, fallbackOk = raw.ok)
    }

    suspend fun sealSync(
        workspaceFile: File,
        passphrase: String,
        deviceLabel: String = "Android",
        outEnvelopeFile: File? = null,
    ): SealSyncResult {
        if (passphrase.isEmpty()) {
            return SealSyncResult(ok = false, errors = listOf("请先设置端到端同步口令"))
        }
        return withTransientPassphraseFile(tempDir, passphrase) { passFile ->
            val args = buildList {
                add("workspace")
                add("seal-sync")
                add("--workspace")
                add(workspaceFile.absolutePath)
                add("--passphrase-file")
                add(passFile.absolutePath)
                if (deviceLabel.isNotBlank()) {
                    add("--device-label")
                    add(deviceLabel.trim().take(64))
                }
                if (outEnvelopeFile != null) {
                    outEnvelopeFile.parentFile?.mkdirs()
                    add("--out")
                    add(outEnvelopeFile.absolutePath)
                }
                add("--json-result")
            }
            val raw = supervisor.runCoreCommand(args, timeoutSeconds = 15L)
            parseSealSyncJson(raw.output, fallbackOk = raw.ok)
        }
    }

    suspend fun openSync(
        envelopeFile: File,
        passphrase: String,
        outWorkspaceFile: File? = null,
    ): OpenSyncResult {
        if (passphrase.isEmpty()) {
            return OpenSyncResult(ok = false, errors = listOf("请输入端到端同步口令"))
        }
        return withTransientPassphraseFile(tempDir, passphrase) { passFile ->
            val args = buildList {
                add("workspace")
                add("open-sync")
                add("--envelope")
                add(envelopeFile.absolutePath)
                add("--passphrase-file")
                add(passFile.absolutePath)
                if (outWorkspaceFile != null) {
                    outWorkspaceFile.parentFile?.mkdirs()
                    add("--out-workspace")
                    add(outWorkspaceFile.absolutePath)
                }
                add("--json-result")
            }
            val raw = supervisor.runCoreCommand(args, timeoutSeconds = 15L)
            parseOpenSyncJson(raw.output, fallbackOk = raw.ok)
        }
    }

    companion object {
        const val SHARE_URI_PREFIX = "nexus://share/v1/"

        suspend fun <T> withTransientPassphraseFile(
            dir: File,
            passphrase: String,
            block: suspend (File) -> T,
        ): T {
            dir.mkdirs()
            val file = File(dir, ".nexus-pass-${UUID.randomUUID()}.secret")
            ProfileRepository.atomicWriteSecret0600(file, passphrase)
            return try {
                block(file)
            } finally {
                wipeAndDelete(file)
            }
        }

        fun wipeAndDelete(file: File) {
            runCatching {
                if (file.isFile) {
                    val len = file.length().coerceIn(0L, 64 * 1024L).toInt()
                    if (len > 0) {
                        RandomAccessFile(file, "rw").use { raf ->
                            raf.seek(0L)
                            raf.write(ByteArray(len))
                            raf.fd.sync()
                        }
                    }
                }
            }
            runCatching { file.delete() }
        }

        fun parseExportShareJson(rawOutput: String, fallbackOk: Boolean = true): ExportShareResult {
            val obj = extractJsonObject(rawOutput)
                ?: return ExportShareResult(ok = false, errors = listOf(rawOutput.trim().ifEmpty { "Empty export-share response" }))
            val ok = fallbackOk && obj.optBoolean("ok", false)
            val errors = WorkspaceJsonCodec.readStringList(obj.optJSONArray("errors"))
            return ExportShareResult(
                ok = ok && errors.isEmpty(),
                uri = obj.optString("uri", ""),
                exportedCount = obj.optInt("exported_count", 0),
                warnings = WorkspaceJsonCodec.readStringList(obj.optJSONArray("warnings")),
                errors = if (!ok && errors.isEmpty()) listOf("导出分享链接失败") else errors,
            )
        }

        fun parseImportShareJson(rawOutput: String, fallbackOk: Boolean = true): ImportShareResult {
            val obj = extractJsonObject(rawOutput)
                ?: return ImportShareResult(ok = false, errors = listOf(rawOutput.trim().ifEmpty { "Empty import-share response" }))
            val ok = fallbackOk && obj.optBoolean("ok", false)
            val errors = WorkspaceJsonCodec.readStringList(obj.optJSONArray("errors"))
            return ImportShareResult(
                ok = ok && errors.isEmpty(),
                importedIds = WorkspaceJsonCodec.readStringList(obj.optJSONArray("imported_ids")),
                warnings = WorkspaceJsonCodec.readStringList(obj.optJSONArray("warnings")),
                errors = if (!ok && errors.isEmpty()) listOf("导入分享链接失败") else errors,
                workspaceJson = obj.optString("workspace_json", ""),
            )
        }

        fun parseSealSyncJson(rawOutput: String, fallbackOk: Boolean = true): SealSyncResult {
            val obj = extractJsonObject(rawOutput)
                ?: return SealSyncResult(ok = false, errors = listOf(rawOutput.trim().ifEmpty { "Empty seal-sync response" }))
            val ok = fallbackOk && obj.optBoolean("ok", false)
            val errors = WorkspaceJsonCodec.readStringList(obj.optJSONArray("errors"))
            return SealSyncResult(
                ok = ok && errors.isEmpty(),
                revision = obj.optLong("revision", 0L),
                updatedAtMs = obj.optLong("updated_at_ms", 0L),
                envelopeSha256 = obj.optString("envelope_sha256", ""),
                warnings = WorkspaceJsonCodec.readStringList(obj.optJSONArray("warnings")),
                errors = if (!ok && errors.isEmpty()) listOf("加密同步快照失败") else errors,
                envelopeJson = obj.optString("envelope_json", ""),
            )
        }

        fun parseOpenSyncJson(rawOutput: String, fallbackOk: Boolean = true): OpenSyncResult {
            val obj = extractJsonObject(rawOutput)
                ?: return OpenSyncResult(ok = false, errors = listOf(rawOutput.trim().ifEmpty { "Empty open-sync response" }))
            val ok = fallbackOk && obj.optBoolean("ok", false)
            val errors = WorkspaceJsonCodec.readStringList(obj.optJSONArray("errors"))
            return OpenSyncResult(
                ok = ok && errors.isEmpty(),
                revision = obj.optLong("revision", 0L),
                updatedAtMs = obj.optLong("updated_at_ms", 0L),
                deviceLabel = obj.optString("device_label", ""),
                warnings = WorkspaceJsonCodec.readStringList(obj.optJSONArray("warnings")),
                errors = if (!ok && errors.isEmpty()) listOf("解密同步快照失败（请检查同步口令）") else errors,
                workspaceJson = obj.optString("workspace_json", ""),
            )
        }

        internal fun extractJsonObject(rawOutput: String): JSONObject? {
            val trimmed = rawOutput.trim()
            val start = trimmed.indexOf('{')
            val end = trimmed.lastIndexOf('}')
            if (start < 0 || end <= start) return null
            return runCatching { JSONObject(trimmed.substring(start, end + 1)) }.getOrNull()
        }
    }
}
