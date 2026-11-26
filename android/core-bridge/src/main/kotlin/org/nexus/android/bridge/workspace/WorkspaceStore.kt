package org.nexus.android.bridge.workspace

import org.nexus.android.bridge.profile.SecretFileIO
import java.io.File
import java.util.UUID

/**
 * Unified SQLite 3 (WAL)-backed store for Layer 1 portable workspace documents,
 * with race-free first-launch default initialization and on-demand `0600` JSON
 * materialization for Core CLI invocations and E2EE sync.
 */
class WorkspaceStore(
    val rootDir: File,
    val db: NexusClientDatabase = NexusClientDatabase.inMemory(),
) {
    fun loadOrInit(): WorkspaceDocument {
        db.loadWorkspace()?.let { return it }
        val initial = WorkspaceDocument(
            schemaVersion = WorkspaceDocument.SCHEMA_VERSION,
            revision = 1L,
            updatedAtMs = System.currentTimeMillis(),
            routingProfiles = WorkspaceDefaults.defaultRoutingProfiles(),
        )
        db.saveWorkspaceIfEmpty(initial)
        return db.loadWorkspace() ?: initial
    }

    fun save(doc: WorkspaceDocument, bumpRevision: Boolean = true): WorkspaceDocument {
        val persisted = doc.copy(
            schemaVersion = WorkspaceDocument.SCHEMA_VERSION,
            revision = if (bumpRevision) (doc.revision + 1L).coerceAtLeast(1L) else doc.revision.coerceAtLeast(1L),
            updatedAtMs = System.currentTimeMillis(),
        )
        db.saveWorkspace(persisted)
        return persisted
    }

    fun listProfileSummaries(): List<ProfileSummary> {
        if (!db.hasWorkspaceData()) loadOrInit()
        return db.listProfileSummaries()
    }

    fun writeCoreInputFile(targetFile: File, doc: WorkspaceDocument = loadOrInit()): File {
        val encoded = WorkspaceJsonCodec.encode(doc, indentSpaces = 2)
        SecretFileIO.atomicWriteSecret0600(targetFile, encoded)
        return targetFile
    }

    fun exportPortableJson(doc: WorkspaceDocument = loadOrInit()): String =
        WorkspaceJsonCodec.encode(doc, indentSpaces = 2)

    fun importPortableJson(rawJson: String, bumpRevision: Boolean = true): WorkspaceDocument {
        val decoded = WorkspaceJsonCodec.decode(rawJson)
        return save(decoded, bumpRevision = bumpRevision)
    }

    companion object {
        fun newProfileId(prefix: String = "prof"): String =
            "${SecretFileIO.sanitizeId(prefix)}-${UUID.randomUUID().toString().take(8)}"

        fun makeUniqueId(base: String, existing: Set<String>): String {
            var candidate = SecretFileIO.sanitizeId(base)
            var suffix = 2
            while (candidate in existing) {
                candidate = "${SecretFileIO.sanitizeId(base)}-$suffix"
                suffix++
            }
            return candidate
        }
    }
}
