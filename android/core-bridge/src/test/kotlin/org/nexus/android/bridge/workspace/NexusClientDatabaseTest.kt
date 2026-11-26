package org.nexus.android.bridge.workspace

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions

class NexusClientDatabaseTest {
    @Test
    fun schemaV1DefinesExactSharedPragmasEightTablesAndFourIndexes() {
        assertEquals(1, NexusClientSchema.SCHEMA_VERSION)
        val pragmas = NexusClientSchema.PRAGMA_STATEMENTS.joinToString("\n")
        assertTrue(pragmas.contains("PRAGMA journal_mode=WAL"))
        assertTrue(pragmas.contains("PRAGMA synchronous=NORMAL"))
        assertTrue(pragmas.contains("PRAGMA foreign_keys=ON"))
        assertTrue(pragmas.contains("PRAGMA busy_timeout=5000"))
        assertTrue(pragmas.contains("PRAGMA temp_store=MEMORY"))
        assertTrue(pragmas.contains("PRAGMA mmap_size=0"))
        assertTrue(pragmas.contains("PRAGMA cache_size=-2000"))

        val ddl = NexusClientSchema.DDL_STATEMENTS.joinToString("\n")
        listOf(
            "CREATE TABLE IF NOT EXISTS subscriptions",
            "CREATE TABLE IF NOT EXISTS profiles",
            "CREATE TABLE IF NOT EXISTS profile_payloads",
            "REFERENCES profiles(id) ON DELETE CASCADE",
            "CREATE TABLE IF NOT EXISTS routing_profiles",
            "CREATE TABLE IF NOT EXISTS workspace_meta",
            "CREATE TABLE IF NOT EXISTS node_telemetry",
            "CREATE TABLE IF NOT EXISTS traffic_ledger",
            "CREATE TABLE IF NOT EXISTS host_kv",
            "ON profiles(subscription_id, sort_order)",
            "ON profiles(kind)",
            "ON profiles(protocol)",
            "ON profiles(pinned)",
        ).forEach { expected ->
            assertTrue("Missing schema fragment: $expected", ddl.contains(expected))
        }
        assertEquals(listOf("PRAGMA shrink_memory", "PRAGMA wal_checkpoint(PASSIVE)"), NexusClientSchema.SHRINK_STATEMENTS)
    }

    @Test
    fun losslessWorkspaceRoundTripVerticalSplitCascadeAndPinnedPreservation() {
        val dir = Files.createTempDirectory("nexus-db-ws").toFile()
        try {
            val dbFile = File(dir, NexusClientSchema.DEFAULT_DB_NAME)
            val exec = InMemorySqlExecutor(dbFile)
            val db = NexusClientDatabase(exec)
            assertNull(db.loadWorkspace())
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(dbFile.toPath()))

            val doc = WorkspaceDocument(
                schemaVersion = 1,
                revision = 9L,
                updatedAtMs = 1_750_000_000_000L,
                profiles = listOf(
                    ProfileItem(
                        id = "n-hk",
                        remarks = "HK-01",
                        subscriptionId = "sub-main",
                        isFromSub = true,
                        kind = ProfileKind.NODE,
                        node = NodeConfig(protocol = "vless", server = "hk.example.com", port = 443, password = "secret-uuid"),
                    ),
                    ProfileItem(
                        id = "g-auto",
                        remarks = "Auto",
                        kind = ProfileKind.POLICY_GROUP,
                        policyGroup = PolicyGroupConfig(strategy = "url-test", memberIds = listOf("n-hk")),
                    ),
                    ProfileItem(
                        id = "ch-1",
                        remarks = "Relay",
                        kind = ProfileKind.PROXY_CHAIN,
                        proxyChain = ProxyChainConfig(hopIds = listOf("n-hk", "g-auto")),
                    ),
                ),
                subscriptions = listOf(
                    SubscriptionItem(id = "sub-main", remarks = "Main", url = "https://sub.example.com/feed", enabled = true, updatedAtMs = 1234L),
                ),
                routingProfiles = WorkspaceDefaults.defaultRoutingProfiles().map { it.copy(isActive = it.id == "global") },
                dns = DnsConfig(mode = "simple", simple = SimpleDnsConfig(fakeIpEnabled = true, hosts = mapOf("lan.home" to "192.168.1.2"))),
                ruleSetAssets = listOf(RuleSetAsset(tag = "cn", path = "cn.nxmm")),
                fullTemplate = FullTemplateConfig(enabled = true, templateKdl = "// tpl", appendProxiesOnly = true),
            )
            db.saveWorkspace(doc)
            db.setProfilePinned("n-hk", true)

            // Fast index-only listing via WorkspaceStore MUST NOT touch profile_payloads
            val store = WorkspaceStore(dir, db)
            val beforeReads = exec.payloadReads.get()
            val summaries = store.listProfileSummaries()
            assertEquals(beforeReads, exec.payloadReads.get())
            assertEquals(3, summaries.size)
            assertEquals("n-hk", summaries[0].id)
            assertEquals("vless", summaries[0].protocol)
            assertEquals("hk.example.com", summaries[0].server)
            assertEquals(443, summaries[0].port)
            assertTrue(summaries[0].pinned)
            assertEquals(ProfileKind.POLICY_GROUP, summaries[1].kind)

            // Full load runs inside a read transaction and hydrates profile_payloads losslessly
            val readTxBefore = exec.readTransactions.get()
            val loaded = db.loadWorkspace()
            assertEquals(doc, loaded)
            assertEquals(beforeReads + 1, exec.payloadReads.get())
            assertEquals(readTxBefore + 1, exec.readTransactions.get())

            // Conditional saveWorkspaceIfEmpty is atomic no-op once DB is populated
            assertFalse(db.saveWorkspaceIfEmpty(WorkspaceDocument(revision = 99L)))
            assertEquals(9L, db.loadWorkspace()?.revision)

            // Removing "ch-1" cascades to profile_payloads and preserves pinned state on "n-hk"
            db.saveWorkspace(doc.copy(revision = 10L, profiles = doc.profiles.dropLast(1)))
            assertFalse("ON DELETE CASCADE must remove orphan payload row", exec.hasPayloadRow("ch-1"))
            assertTrue(exec.hasPayloadRow("n-hk"))
            assertTrue(db.listProfileSummaries().first { it.id == "n-hk" }.pinned)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun transactionRollbackPreservesPreviousCommittedState() {
        val db = NexusClientDatabase.inMemory()
        val initial = WorkspaceDocument(revision = 2L, profiles = listOf(ProfileItem(id = "p1", remarks = "Keep")))
        db.saveWorkspace(initial)

        val failed = runCatching {
            db.executor.inTransaction {
                db.executor.setHostKv("temp_key", "\"v\"")
                db.executor.replaceProfiles(emptyList(), emptyMap())
                error("simulated failure mid-transaction")
            }
        }
        assertTrue(failed.isFailure)
        assertNull(db.getHostKv("temp_key"))
        assertEquals(1, db.listProfileSummaries().size)
        assertEquals("p1", db.listProfileSummaries().first().id)
    }

    @Test
    fun nodeTelemetryTrafficLedgerHostKvSecretGuardAndShrinkMemory() {
        val dir = Files.createTempDirectory("nexus-db-tel").toFile()
        try {
            val dbFile = File(dir, NexusClientSchema.DEFAULT_DB_NAME)
            val exec = InMemorySqlExecutor(dbFile)
            val db = NexusClientDatabase(exec)

            db.upsertNodeTelemetry(NodeTelemetryRecord(profileId = "n1", latencyMs = 42L, ewmaMs = 45L, statusCode = 204, state = "healthy", testedAtMs = 9000L))
            db.recordTrafficDelta(bucketHour = 100L, profileId = "n1", uploadBytes = 1000L, downloadBytes = 2000L)
            db.recordTrafficDelta(bucketHour = 100L, profileId = "n1", uploadBytes = 500L, downloadBytes = 800L)
            db.recordTrafficDelta(bucketHour = 101L, profileId = "n1", uploadBytes = 200L, downloadBytes = 300L)

            val allLedger = db.queryTrafficLedger(0L)
            assertEquals(2, allLedger.size)
            assertEquals(1500L, allLedger[0].uploadBytes)
            assertEquals(2800L, allLedger[0].downloadBytes)
            assertEquals(1, db.queryTrafficLedger(101L).size)

            val tel = db.loadTelemetry()
            assertEquals(42L, tel.profiles["n1"]?.latencyMs)
            assertEquals(1700L, tel.profiles["n1"]?.uploadBytes)
            assertEquals(3100L, tel.profiles["n1"]?.downloadBytes)

            // Updating top-level telemetry metadata preserves rich ewmaMs/statusCode/state rows
            db.saveTelemetry(tel.copy(activeProfileId = "n1", outboundMode = "global"))
            val rich = db.listNodeTelemetry().first { it.profileId == "n1" }
            assertEquals(45L, rich.ewmaMs)
            assertEquals(204, rich.statusCode)
            assertEquals("healthy", rich.state)

            // Updating latency via TelemetryStore.updateLatency preserves rich ewmaMs/statusCode/state
            val telStore = TelemetryStore(File(dir, "telemetry.json"), db)
            telStore.updateLatency("n1", 31L)
            val updatedRich = db.listNodeTelemetry().first { it.profileId == "n1" }
            assertEquals(31L, updatedRich.latencyMs)
            assertEquals(45L, updatedRich.ewmaMs)
            assertEquals(204, updatedRich.statusCode)
            assertEquals("healthy", updatedRich.state)

            // Guardrail: SQLite host_kv rejects WebDAV password or E2EE sync passphrase on ANY key (nested or top-level)
            assertThrows(IllegalArgumentException::class.java) {
                db.setHostKv(
                    NexusClientDatabase.KV_ANDROID_HOST_CONFIG,
                    """{"android":{"webdav_password":"leaked","sync_passphrase":"secret"}}""",
                )
            }
            assertThrows(IllegalArgumentException::class.java) {
                db.setHostKv("any_other_key", """{"sync_passphrase":"top-level-secret"}""")
            }
            assertThrows(IllegalArgumentException::class.java) {
                db.setHostKvIfAbsent("another_key", """{"nested":{"webdav_password":"pw"}}""")
            }
            assertTrue(db.setHostKvIfAbsent("custom_key", """{"ok":true}"""))
            assertFalse(db.setHostKvIfAbsent("custom_key", """{"ok":false}"""))
            assertEquals("""{"ok":true}""", db.getHostKv("custom_key"))
            db.deleteHostKv("custom_key")
            assertNull(db.getHostKv("custom_key"))

            // Forward schema version (> 1) fails closed refusing downgrade
            assertThrows(IllegalStateException::class.java) {
                NexusClientDatabase.inMemory(userVersion = 99)
            }

            db.shrinkMemory()
            assertEquals(1, exec.shrinkCalls.get())
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(dbFile.toPath()))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun trafficOnlyDbSkipsStaleLegacyTelemetryReimport() {
        val dir = Files.createTempDirectory("nexus-db-traffic-only").toFile()
        try {
            val db = NexusClientDatabase.inMemory()
            db.recordTrafficDelta(bucketHour = 200L, profileId = "n-live", uploadBytes = 50L, downloadBytes = 90L)
            assertTrue(db.hasTelemetryState())

            val staleLegacy = File(dir, "telemetry.json")
            staleLegacy.writeText(
                TelemetryStore.encode(TelemetryDocument(activeProfileId = "stale-id", outboundMode = "direct")),
                Charsets.UTF_8,
            )
            val telStore = TelemetryStore(staleLegacy, db)
            val loaded = telStore.load()
            assertEquals("", loaded.activeProfileId)
            assertEquals("rule", loaded.outboundMode)
            assertEquals(50L, loaded.profiles["n-live"]?.uploadBytes)
            assertFalse(db.importLegacyTelemetryIfEmpty(TelemetryDocument(activeProfileId = "other")))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun oneShotLegacyMigrationImportsHostSecretsOutOfHostJsonAndTelemetryJson() {
        val dir = Files.createTempDirectory("nexus-db-mig").toFile()
        try {
            val db = NexusClientDatabase.inMemory(File(dir, NexusClientSchema.DEFAULT_DB_NAME))
            val legacyHostFile = File(dir, "host.json")
            val legacyCfg = AndroidHostConfig(
                android = AndroidHostSection(
                    runMode = AndroidRunMode.PROXY_ONLY,
                    webdavUrl = "https://dav.example.com/nexus/",
                    webdavPassword = "legacy-dav-password",
                    syncPassphrase = "legacy-sync-passphrase",
                    autoStartOnBoot = true,
                ),
            )
            legacyHostFile.writeText(legacyCfg.toJson(indentSpaces = 2, includeSecrets = true), Charsets.UTF_8)

            val hostStore = AndroidHostConfigStore(legacyHostFile, db)
            val migratedHost = hostStore.load()
            assertEquals(AndroidRunMode.PROXY_ONLY, migratedHost.android.runMode)
            assertTrue(migratedHost.android.autoStartOnBoot)
            assertEquals("legacy-dav-password", migratedHost.android.webdavPassword)
            assertEquals("legacy-sync-passphrase", migratedHost.android.syncPassphrase)

            // Migrated secrets are in 0600 secretFile, NOT in SQLite host_kv, and scrubbed from legacy host.json
            val storedKv = db.getHostKv(NexusClientDatabase.KV_ANDROID_HOST_CONFIG).orEmpty()
            assertFalse(storedKv.contains("legacy-dav-password"))
            assertFalse(storedKv.contains("legacy-sync-passphrase"))
            assertFalse(legacyHostFile.readText(Charsets.UTF_8).contains("legacy-dav-password"))
            assertFalse(legacyHostFile.readText(Charsets.UTF_8).contains("legacy-sync-passphrase"))
            assertTrue(hostStore.secretFile.isFile)
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(hostStore.secretFile.toPath()))

            // Legacy telemetry.json one-shot migration
            val legacyTelFile = File(dir, "telemetry.json")
            legacyTelFile.writeText(
                TelemetryStore.encode(
                    TelemetryDocument(
                        activeProfileId = "hk-01",
                        outboundMode = "global",
                        unreadUnexpectedCrash = true,
                        lastCrashReason = "exit=139",
                        profiles = mapOf("hk-01" to ProfileTelemetryEntry(latencyMs = 55L, lastTestedMs = 1000L, uploadBytes = 100L, downloadBytes = 200L)),
                    ),
                ),
                Charsets.UTF_8,
            )
            val telStore = TelemetryStore(legacyTelFile, db)
            val migratedTel = telStore.load()
            assertEquals("hk-01", migratedTel.activeProfileId)
            assertEquals("global", migratedTel.outboundMode)
            assertTrue(migratedTel.unreadUnexpectedCrash)
            assertEquals(55L, migratedTel.profiles["hk-01"]?.latencyMs)
            assertNotNull(db.getHostKv(NexusClientDatabase.KV_TELEMETRY_STATE))
        } finally {
            dir.deleteRecursively()
        }
    }
}
