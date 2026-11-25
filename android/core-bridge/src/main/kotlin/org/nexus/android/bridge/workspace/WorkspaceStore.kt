package org.nexus.android.bridge.workspace

import org.nexus.android.bridge.profile.ProfileRepository
import java.io.File
import java.util.UUID

data class LegacyMigrationReport(
    val migratedProfileIds: List<String>,
    val skippedAlreadyMigrated: Boolean,
)

/**
 * Atomic 0600 storage for Layer 1 portable `workspace.json` + one-shot migration of legacy
 * profile KDL files under `profiles/` into `full_custom_kdl` entries.
 */
class WorkspaceStore(
    val rootDir: File,
    val workspaceFile: File = File(rootDir, "workspace.json"),
) {
    private val migrationSentinel = File(rootDir, ".workspace_migrated_v1")

    fun loadOrInit(): WorkspaceDocument {
        if (!workspaceFile.isFile) {
            val initial = WorkspaceDocument(
                schemaVersion = WorkspaceDocument.SCHEMA_VERSION,
                revision = 1L,
                updatedAtMs = System.currentTimeMillis(),
                routingProfiles = WorkspaceDefaults.defaultRoutingProfiles(),
            )
            save(initial, bumpRevision = false)
            return initial
        }
        return WorkspaceJsonCodec.decode(workspaceFile.readText(Charsets.UTF_8))
    }

    fun save(doc: WorkspaceDocument, bumpRevision: Boolean = true): WorkspaceDocument {
        rootDir.mkdirs()
        val persisted = doc.copy(
            schemaVersion = WorkspaceDocument.SCHEMA_VERSION,
            revision = if (bumpRevision) (doc.revision + 1L).coerceAtLeast(1L) else doc.revision.coerceAtLeast(1L),
            updatedAtMs = System.currentTimeMillis(),
        )
        val encoded = WorkspaceJsonCodec.encode(persisted, indentSpaces = 2)
        // Strict 0600 write because workspace.json stores node credentials.
        ProfileRepository.atomicWriteSecret0600(workspaceFile, encoded)
        return persisted
    }

    /**
     * One-shot migration of legacy KDL files in `profiles/` into `full_custom_kdl` profiles
     * without mutating or deleting original files and without duplicating on subsequent boots.
     */
    fun migrateLegacyProfilesIfNeeded(legacyRootDir: File = rootDir): LegacyMigrationReport {
        if (migrationSentinel.isFile) {
            return LegacyMigrationReport(emptyList(), skippedAlreadyMigrated = true)
        }
        val legacyDir = File(legacyRootDir, "profiles")
        val kdlFiles = legacyDir.listFiles { f -> f.isFile && f.extension.equals("kdl", ignoreCase = true) }
            .orEmpty()
            .sortedBy { it.name }

        var doc = loadOrInit()
        val existingIds = doc.profiles.map { it.id }.toMutableSet()
        val migrated = mutableListOf<String>()
        val nextProfiles = doc.profiles.toMutableList()

        for (file in kdlFiles) {
            val rawKdl = runCatching { file.readText(Charsets.UTF_8) }.getOrNull()?.trim().orEmpty()
            if (rawKdl.isEmpty()) continue
            val baseName = file.nameWithoutExtension
            val id = makeUniqueId("legacy-${ProfileRepository.sanitizeId(baseName)}", existingIds)
            existingIds.add(id)
            nextProfiles.add(
                ProfileItem(
                    id = id,
                    remarks = baseName,
                    subscriptionId = "",
                    isFromSub = false,
                    kind = ProfileKind.FULL_CUSTOM_KDL,
                    fullCustomKdl = rawKdl + "\n",
                ),
            )
            migrated.add(id)
        }

        if (migrated.isNotEmpty()) {
            doc = save(doc.copy(profiles = nextProfiles))
        }
        rootDir.mkdirs()
        runCatching { ProfileRepository.atomicWriteSecret0600(migrationSentinel, "v1\n") }
        return LegacyMigrationReport(migrated, skippedAlreadyMigrated = false)
    }

    fun exportPortableJson(doc: WorkspaceDocument = loadOrInit()): String =
        WorkspaceJsonCodec.encode(doc, indentSpaces = 2)

    fun importPortableJson(rawJson: String, bumpRevision: Boolean = true): WorkspaceDocument {
        val decoded = WorkspaceJsonCodec.decode(rawJson)
        return save(decoded, bumpRevision = bumpRevision)
    }

    companion object {
        fun newProfileId(prefix: String = "prof"): String =
            "${ProfileRepository.sanitizeId(prefix)}-${UUID.randomUUID().toString().take(8)}"

        fun makeUniqueId(base: String, existing: Set<String>): String {
            var candidate = ProfileRepository.sanitizeId(base)
            var suffix = 2
            while (candidate in existing) {
                candidate = "${ProfileRepository.sanitizeId(base)}-$suffix"
                suffix++
            }
            return candidate
        }
    }
}
