package org.nexus.android.bridge.workspace

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.BufferedInputStream
import java.io.File
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class WorkspaceSyncAndProbeTest {
    private fun sampleEnvelope(revision: Long, device: String): String = """
        {
          "format": "nexus-sync-v1",
          "kdf": "scrypt",
          "kdf_n": 32768,
          "kdf_r": 8,
          "kdf_p": 1,
          "aead": "xchacha20-poly1305",
          "salt_b64": "AAAAAAAAAAAAAAAAAAAAAA==",
          "nonce_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          "revision": $revision,
          "updated_at_ms": 1700000000000,
          "device_label": "$device",
          "plaintext_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "ciphertext_b64": "AAAA"
        }
    """.trimIndent()

    @Test
    fun webDavPushConflictPullAndBackupAgainstLoopbackServer() = runBlocking {
        val dir = Files.createTempDirectory("nexus-dav-test").toFile()
        val server = MockWebDavServer()
        try {
            server.start()
            val cfg = WebDavConfig(
                baseUrl = "http://127.0.0.1:${server.port}/nexus/",
                username = "alice",
                password = "secret-dav-password",
                timeoutMs = 5_000,
            )
            val client = WebDavSyncClient()

            // 1. Initial push succeeds (MKCOL + GET 404 + PUT 201 with If-None-Match: *)
            val first = client.pushEnvelope(cfg, sampleEnvelope(1L, "Android"), localRevision = 1L)
            assertTrue("Expected Success, got $first", first is SyncOutcome.Success)
            val okFirst = first as SyncOutcome.Success
            assertEquals("\"etag-1\"", okFirst.etag)
            assertEquals("*", server.lastPutIfNoneMatch)
            assertTrue(server.mkcolSeen.get())
            assertTrue(server.authSeen.get())

            // 1b. Concurrent initial push race: GET sees 404, another device uploads before PUT -> If-None-Match: * triggers 412 Conflict
            server.setStored("", "")
            server.injectOnNextPutBody = sampleEnvelope(1L, "Concurrent-Mac")
            server.injectOnNextPutEtag = "\"etag-race\""
            val initialRace = client.pushEnvelope(cfg, sampleEnvelope(1L, "Android"), localRevision = 1L, expectedEtag = "", forceOverwrite = false)
            assertTrue("Expected initial race Conflict, got $initialRace", initialRace is SyncOutcome.Conflict)
            assertTrue(server.storedBody.contains("Concurrent-Mac"))

            // 2. Simulate another device pushing rev 3 ("etag-2") -> stale push must Conflict (NOT overwrite!)
            server.setStored(sampleEnvelope(3L, "Desktop-Linux"), "\"etag-2\"")
            val conflict = client.pushEnvelope(
                cfg,
                sampleEnvelope(2L, "Android"),
                localRevision = 2L,
                expectedEtag = "\"etag-1\"",
                forceOverwrite = false,
            )
            assertTrue("Expected Conflict, got $conflict", conflict is SyncOutcome.Conflict)
            val c = conflict as SyncOutcome.Conflict
            assertEquals(3L, c.remoteRevision)
            assertEquals("Desktop-Linux", c.remoteDevice)
            assertEquals("\"etag-2\"", c.remoteEtag)
            assertTrue(server.storedBody.contains("Desktop-Linux"))

            // 3. Server-enforced HTTP 412 Precondition Failed -> returns Conflict
            server.force412Once.set(true)
            val precond = client.pushEnvelope(
                cfg,
                sampleEnvelope(4L, "Android"),
                localRevision = 4L,
                expectedEtag = "\"etag-2\"",
                forceOverwrite = false,
            )
            assertTrue("Expected 412 Conflict, got $precond", precond is SyncOutcome.Conflict)

            // 4. Force push overwrites remote cleanly
            val forced = client.pushEnvelope(
                cfg,
                sampleEnvelope(4L, "Android"),
                localRevision = 4L,
                expectedEtag = "\"etag-1\"",
                forceOverwrite = true,
            )
            assertTrue("Expected forced Success, got $forced", forced is SyncOutcome.Success)

            // 5. Equal-revision divergence after prior sync: synced at rev 5 ("etag-5"), local edited to 6, remote pushed 6 ("etag-6") -> Conflict!
            server.setStored(sampleEnvelope(6L, "Desktop-Linux"), "\"etag-6\"")
            val equalDiv = client.pullEnvelope(
                cfg,
                localRevision = 6L,
                lastSyncedRevision = 5L,
                lastSyncedEtag = "\"etag-5\"",
                forceOverwrite = false,
            )
            assertTrue("Expected equal-revision divergence Conflict, got $equalDiv", equalDiv is SyncOutcome.Conflict)

            // 5b. Clean fast-forward pull when local has no edits since last sync (localRevision == lastSyncedRevision == 5)
            val fastForward = client.pullEnvelope(
                cfg,
                localRevision = 5L,
                lastSyncedRevision = 5L,
                lastSyncedEtag = "\"etag-5\"",
                forceOverwrite = false,
            )
            assertTrue("Expected fast-forward Success, got $fastForward", fastForward is SyncOutcome.Success)

            // 5c. Pull when localRevision > remoteRevision returns Conflict unless forced
            val pullConflict = client.pullEnvelope(cfg, localRevision = 9L, forceOverwrite = false)
            assertTrue("Expected pull Conflict, got $pullConflict", pullConflict is SyncOutcome.Conflict)

            // 6. Forced pull creates 0600 timestamped local backup before returning envelope
            val localWs = File(dir, "workspace.json").apply { writeText("{\"schema_version\":1}\n") }
            val backups = File(dir, "backups")
            val pulled = client.pullEnvelope(cfg, localRevision = 9L, localWorkspaceFile = localWs, backupDir = backups, forceOverwrite = true)
            assertTrue("Expected pulled Success, got $pulled", pulled is SyncOutcome.Success)
            val okPull = pulled as SyncOutcome.Success
            val backupFile = okPull.backupFile
            assertNotNull(backupFile)
            assertTrue(backupFile!!.isFile)
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(backupFile.toPath()))
            assertTrue(okPull.envelopeJson.contains("nexus-sync-v1"))
        } finally {
            server.close()
            dir.deleteRecursively()
        }
    }

    @Test
    fun webDavRejectsNonHttpsCrlfAndResolvesQueryPathsSafely() = runBlocking {
        val client = WebDavSyncClient()
        assertNull(WebDavSyncClient.validateWebDavUrl("http://dav.example.com/nexus/"))
        assertNull(WebDavSyncClient.validateWebDavUrl("https://dav.example.com/nexus/\r\nX-Injected: 1"))
        assertNull(WebDavSyncClient.validateWebDavUrl("https://dav.example.com/nexus/\nfoo"))
        assertNull(WebDavSyncClient.validateWebDavUrl("https://dav.example.com/nexus/ has space"))
        assertNull(WebDavSyncClient.validateWebDavUrl("https:///missing-host/"))
        assertNotNull(WebDavSyncClient.validateWebDavUrl("https://dav.example.com/nexus/"))
        assertNotNull(WebDavSyncClient.validateWebDavUrl("http://127.0.0.1:8080/nexus/"))

        val colWithQuerySlash = WebDavSyncClient.resolveCollectionUrl("https://dav.example.com/nexus/nexus-workspace-v1.enc?next=/a/b/c")
        assertEquals("https://dav.example.com/nexus/", colWithQuerySlash?.toExternalForm())
        val envWithQuery = WebDavSyncClient.resolveEnvelopeUrl("https://dav.example.com/nexus/?token=a/b")
        assertEquals("https://dav.example.com/nexus/nexus-workspace-v1.enc?token=a/b", envWithQuery?.toExternalForm())

        val res = client.pushEnvelope(WebDavConfig("http://dav.example.com/nexus/"), sampleEnvelope(1L, "A"), 1L)
        assertTrue(res is SyncOutcome.Error)
    }

    @Test
    fun pullImportPreservesRevisionAndBackupPrunesOldest() {
        val dir = Files.createTempDirectory("nexus-pull-rev-test").toFile()
        try {
            val store = WorkspaceStore(dir)
            val remoteJson = WorkspaceJsonCodec.encode(WorkspaceDocument(revision = 7L))
            val importedNoBump = store.importPortableJson(remoteJson, bumpRevision = false)
            assertEquals(7L, importedNoBump.revision)
            assertEquals(7L, store.loadOrInit().revision)

            val importedBumped = store.importPortableJson(remoteJson, bumpRevision = true)
            assertEquals(8L, importedBumped.revision)

            val backups = File(dir, "backups")
            val created = (1..8).mapNotNull {
                WebDavSyncClient.createPrePullBackupJson(store.exportPortableJson(), backups, maxBackups = 5)
            }
            assertEquals(8, created.size)
            val remaining = backups.listFiles { f -> f.isFile && f.name.startsWith("workspace.backup-") }.orEmpty().sortedBy { it.name }
            assertEquals(5, remaining.size)
            assertEquals(created.takeLast(5).map { it.name }, remaining.map { it.name })
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(remaining.last().toPath()))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun passphraseAndWebDavCredsStayIn0600HostJsonAndNeverLeakToWorkspace() = runBlocking {
        val dir = Files.createTempDirectory("nexus-iso-test").toFile()
        try {
            val db = NexusClientDatabase.inMemory(File(dir, NexusClientSchema.DEFAULT_DB_NAME))
            val hostStore = AndroidHostConfigStore(File(dir, "host.json"), db)
            val secretPass = "super-secret-sync-passphrase-99"
            val secretDavPw = "dav-app-password-88"
            hostStore.save(
                AndroidHostConfig(
                    android = AndroidHostSection(
                        webdavUrl = "https://dav.example.com/nexus/",
                        webdavUsername = "alice",
                        webdavPassword = secretDavPw,
                        syncPassphrase = secretPass,
                        syncDeviceLabel = "Pixel-9",
                        lastSyncedEtag = "\"e1\"",
                        lastSyncedRevision = 5L,
                    ),
                ),
            )
            // Secrets live strictly in 0600 secretFile, NEVER in SQLite host_kv and NEVER in workspace.json
            assertTrue(hostStore.secretFile.isFile)
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(hostStore.secretFile.toPath()))
            val rawHostKv = db.getHostKv(NexusClientDatabase.KV_ANDROID_HOST_CONFIG).orEmpty()
            assertFalse("SQLite host_kv must NEVER contain sync passphrase", rawHostKv.contains(secretPass))
            assertFalse("SQLite host_kv must NEVER contain WebDAV password", rawHostKv.contains(secretDavPw))

            val loadedHost = hostStore.load()
            assertEquals(secretPass, loadedHost.android.syncPassphrase)
            assertEquals(secretDavPw, loadedHost.android.webdavPassword)
            assertEquals("Pixel-9", loadedHost.android.syncDeviceLabel)

            // Workspace JSON MUST NEVER contain WebDAV credentials or sync passphrase
            val wsJson = WorkspaceJsonCodec.encode(WorkspaceDocument())
            assertFalse(wsJson.contains(secretPass))
            assertFalse(wsJson.contains(secretDavPw))
            assertFalse(wsJson.contains("webdav_url"))
            assertFalse(wsJson.contains("sync_passphrase"))

            // Transient passphrase file is 0600 while in use and deleted even on failure
            var observedFile: File? = null
            val caught = runCatching {
                WorkspaceSyncBridge.withTransientPassphraseFile(dir, secretPass) { pf ->
                    observedFile = pf
                    assertTrue(pf.isFile)
                    assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(pf.toPath()))
                    assertEquals(secretPass, pf.readText(Charsets.UTF_8))
                    error("simulated failure")
                }
            }
            assertTrue(caught.isFailure)
            assertNotNull(observedFile)
            assertFalse("Transient passphrase file must be deleted in finally", observedFile!!.exists())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun shareSyncAndUdpProbeJsonParsersMatchFrozenContract() {
        val exp = WorkspaceSyncBridge.parseExportShareJson(
            """{"ok":true,"uri":"nexus://share/v1/eyJzY2hlbWFfdmVyc2lvbiI6MX0","exported_count":2,"warnings":[],"errors":[]}""",
        )
        assertTrue(exp.ok)
        assertEquals(2, exp.exportedCount)
        assertTrue(exp.uri.startsWith(WorkspaceSyncBridge.SHARE_URI_PREFIX))

        val imp = WorkspaceSyncBridge.parseImportShareJson(
            """{"ok":true,"imported_ids":["p-new-1","p-new-2"],"warnings":["remapped"],"errors":[],"workspace_json":"{}"}""",
        )
        assertTrue(imp.ok)
        assertEquals(listOf("p-new-1", "p-new-2"), imp.importedIds)
        assertEquals(listOf("remapped"), imp.warnings)

        val sealed = WorkspaceSyncBridge.parseSealSyncJson(
            """{"ok":true,"revision":12,"updated_at_ms":1700000000123,"envelope_sha256":"abcd","warnings":[],"errors":[],"envelope_json":"{}"}""",
        )
        assertTrue(sealed.ok)
        assertEquals(12L, sealed.revision)
        assertEquals("abcd", sealed.envelopeSha256)

        val opened = WorkspaceSyncBridge.parseOpenSyncJson(
            """{"ok":true,"revision":12,"updated_at_ms":1700000000123,"device_label":"Desktop","warnings":[],"errors":[],"workspace_json":"{\"schema_version\":1}"}""",
        )
        assertTrue(opened.ok)
        assertEquals("Desktop", opened.deviceLabel)

        val stun = UdpProbeClient.parseProbeResultJson(
            """{"ok":true,"kind":"stun","via_socks5":true,"rtt_ms":38,"attempts":1,"detail":"mapped 203.0.113.5:54321","error":""}""",
        )
        assertTrue(stun.ok)
        assertEquals("stun", stun.kind)
        assertTrue(stun.viaSocks5)
        assertEquals(38L, stun.rttMs)
        assertEquals("mapped 203.0.113.5:54321", stun.detail)

        val bad = UdpProbeClient.parseProbeResultJson("timeout waiting for UDP reply", fallbackKind = "ntp")
        assertFalse(bad.ok)
        assertEquals("ntp", bad.kind)
        assertTrue(bad.error.contains("timeout"))

        // Non-zero Core exit (fallbackOk = false) MUST NEVER report ok = true
        assertFalse(WorkspaceSyncBridge.parseExportShareJson("""{"ok":true,"uri":"nexus://share/v1/x"}""", fallbackOk = false).ok)
        assertFalse(WorkspaceSyncBridge.parseImportShareJson("""{"ok":true,"imported_ids":["a"]}""", fallbackOk = false).ok)
        assertFalse(WorkspaceSyncBridge.parseSealSyncJson("""{"ok":true,"revision":2}""", fallbackOk = false).ok)
        assertFalse(WorkspaceSyncBridge.parseOpenSyncJson("""{"ok":true,"revision":2}""", fallbackOk = false).ok)
    }

    private class MockWebDavServer {
        private val socket = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))
        val port: Int get() = socket.localPort
        val mkcolSeen = AtomicBoolean(false)
        val authSeen = AtomicBoolean(false)
        val force412Once = AtomicBoolean(false)
        private val etagSeq = AtomicInteger(0)

        @Volatile var storedBody: String = ""
        @Volatile var storedEtag: String = ""
        @Volatile var lastPutIfNoneMatch: String? = null
        @Volatile var injectOnNextPutBody: String? = null
        @Volatile var injectOnNextPutEtag: String = ""
        @Volatile private var running = true
        private var thread: Thread? = null

        fun setStored(body: String, etag: String) {
            storedBody = body
            storedEtag = etag
        }

        fun start() {
            thread = Thread({
                while (running) {
                    val client = runCatching { socket.accept() }.getOrNull() ?: break
                    runCatching { handle(client) }
                }
            }, "mock-webdav").apply { isDaemon = true; start() }
        }

        private fun handle(client: java.net.Socket) {
            client.use { s ->
                val input = BufferedInputStream(s.getInputStream())
                val reqLine = readAsciiLine(input) ?: return
                val parts = reqLine.split(' ')
                if (parts.size < 2) return
                val method = parts[0].uppercase()
                val headers = linkedMapOf<String, String>()
                while (true) {
                    val line = readAsciiLine(input) ?: break
                    if (line.isEmpty()) break
                    val colon = line.indexOf(':')
                    if (colon > 0) headers[line.substring(0, colon).trim().lowercase()] = line.substring(colon + 1).trim()
                }
                if (headers["authorization"]?.startsWith("Basic ") == true) authSeen.set(true)
                val contentLen = headers["content-length"]?.toIntOrNull() ?: 0
                val bodyBytes = if (contentLen > 0) input.readNBytes(contentLen) else ByteArray(0)

                val out = s.getOutputStream()
                when (method) {
                    "MKCOL" -> {
                        mkcolSeen.set(true)
                        writeResp(out, "201 Created", emptyMap(), "")
                    }
                    "HEAD" -> {
                        if (storedBody.isEmpty()) writeResp(out, "404 Not Found", emptyMap(), "")
                        else writeResp(out, "200 OK", mapOf("ETag" to storedEtag, "Content-Length" to storedBody.toByteArray().size.toString()), "")
                    }
                    "GET" -> {
                        if (storedBody.isEmpty()) writeResp(out, "404 Not Found", emptyMap(), "")
                        else writeResp(out, "200 OK", mapOf("ETag" to storedEtag, "Content-Type" to "application/json"), storedBody)
                    }
                    "PUT" -> {
                        injectOnNextPutBody?.let { injected ->
                            storedBody = injected
                            storedEtag = injectOnNextPutEtag
                            injectOnNextPutBody = null
                        }
                        val ifMatch = headers["if-match"]
                        val ifNoneMatch = headers["if-none-match"]
                        lastPutIfNoneMatch = ifNoneMatch
                        val ifNoneMatchFailed = ifNoneMatch == "*" && storedBody.isNotEmpty()
                        val ifMatchFailed = ifMatch != null && storedEtag.isNotEmpty() && ifMatch != storedEtag
                        if (force412Once.getAndSet(false) || ifNoneMatchFailed || ifMatchFailed) {
                            writeResp(out, "412 Precondition Failed", emptyMap(), "")
                        } else {
                            storedBody = String(bodyBytes, Charsets.UTF_8)
                            storedEtag = "\"etag-${etagSeq.incrementAndGet()}\""
                            writeResp(out, "201 Created", mapOf("ETag" to storedEtag), "")
                        }
                    }
                    else -> writeResp(out, "405 Method Not Allowed", emptyMap(), "")
                }
            }
        }

        private fun readAsciiLine(input: BufferedInputStream): String? {
            val sb = StringBuilder()
            while (true) {
                val b = input.read()
                if (b < 0) return if (sb.isEmpty()) null else sb.toString()
                if (b == '\n'.code) break
                if (b != '\r'.code) sb.append(b.toChar())
            }
            return sb.toString()
        }

        private fun writeResp(out: java.io.OutputStream, status: String, headers: Map<String, String>, body: String) {
            val bytes = body.toByteArray(Charsets.UTF_8)
            val sb = StringBuilder("HTTP/1.1 $status\r\n")
            headers.forEach { (k, v) -> sb.append("$k: $v\r\n") }
            if ("Content-Length" !in headers) sb.append("Content-Length: ${bytes.size}\r\n")
            sb.append("Connection: close\r\n\r\n")
            out.write(sb.toString().toByteArray(Charsets.US_ASCII))
            if (bytes.isNotEmpty()) out.write(bytes)
            out.flush()
        }

        fun close() {
            running = false
            runCatching { socket.close() }
        }
    }
}
