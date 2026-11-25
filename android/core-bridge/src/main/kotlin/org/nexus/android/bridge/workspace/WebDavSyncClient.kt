package org.nexus.android.bridge.workspace

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.nexus.android.bridge.profile.ProfileRepository
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.util.Base64
import java.util.Locale
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

data class WebDavConfig(
    val baseUrl: String,
    val username: String = "",
    val password: String = "",
    val timeoutMs: Int = 10_000,
)

data class RemoteEnvelopeMeta(
    val format: String = "",
    val revision: Long = 0L,
    val updatedAtMs: Long = 0L,
    val deviceLabel: String = "",
    val etag: String = "",
    val body: String = "",
)

sealed interface SyncOutcome {
    data class Success(
        val revision: Long,
        val updatedAtMs: Long,
        val etag: String,
        val deviceLabel: String = "",
        val envelopeJson: String = "",
        val backupFile: File? = null,
    ) : SyncOutcome

    data class Conflict(
        val remoteRevision: Long,
        val remoteDevice: String,
        val remoteEtag: String,
        val remoteUpdatedAtMs: Long = 0L,
        val message: String,
    ) : SyncOutcome

    data class NotFound(val message: String) : SyncOutcome
    data class Error(val message: String) : SyncOutcome
}

/**
 * E2EE WebDAV Sync HTTP client (`MKCOL`/`HEAD`/`GET`/`PUT`, Basic Auth, strict HTTPS except
 * loopback HTTP for tests, ETag + revision conflict detection, `If-Match` conditional upload,
 * and pre-pull `0600` timestamped local backup).
 */
class WebDavSyncClient {
    suspend fun pushEnvelope(
        config: WebDavConfig,
        envelopeJson: String,
        localRevision: Long,
        expectedEtag: String = "",
        forceOverwrite: Boolean = false,
    ): SyncOutcome = withContext(Dispatchers.IO) {
        val target = resolveEnvelopeUrl(config.baseUrl)
            ?: return@withContext SyncOutcome.Error("仅支持 HTTPS WebDAV 地址（或本机回环调试地址）")
        val auth = buildBasicAuth(config.username, config.password)

        // Ensure parent collection exists before upload; abort fast on TLS errors.
        resolveCollectionUrl(config.baseUrl)?.let { colUrl ->
            val mkErr = runCatching { sendMkcol(colUrl, auth, config.timeoutMs) }.exceptionOrNull()
            if (mkErr is SSLException) {
                return@withContext SyncOutcome.Error("WebDAV TLS 校验失败: ${mkErr.message ?: mkErr.javaClass.simpleName}")
            }
        }

        if (!forceOverwrite) {
            when (val probe = fetchRemoteMeta(target, auth, config.timeoutMs, fetchBody = true)) {
                is ProbeResult.Found -> {
                    val m = probe.meta
                    val etagMismatch = expectedEtag.isNotBlank() && m.etag.isNotBlank() && m.etag != expectedEtag
                    val remoteAhead = m.revision > localRevision
                    val unseenRemote = expectedEtag.isBlank() && m.revision > 0L
                    if (etagMismatch || remoteAhead || unseenRemote) {
                        return@withContext SyncOutcome.Conflict(
                            remoteRevision = m.revision,
                            remoteDevice = m.deviceLabel,
                            remoteEtag = m.etag,
                            remoteUpdatedAtMs = m.updatedAtMs,
                            message = "远端快照已更新（rev ${m.revision}，设备 ${m.deviceLabel.ifBlank { "未知" }}）",
                        )
                    }
                }
                is ProbeResult.NotFound -> Unit
                is ProbeResult.Failed -> return@withContext SyncOutcome.Error(probe.message)
            }
        }

        val payloadBytes = envelopeJson.toByteArray(Charsets.UTF_8)
        runCatching {
            val conn = openConn(target, "PUT", auth, config.timeoutMs).apply {
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
                if (!forceOverwrite) {
                    if (expectedEtag.isNotBlank()) {
                        setRequestProperty("If-Match", expectedEtag)
                    } else {
                        setRequestProperty("If-None-Match", "*")
                    }
                }
                outputStream.use { it.write(payloadBytes) }
            }
            try {
                val code = conn.responseCode
                val respEtag = conn.getHeaderField("ETag")?.trim().orEmpty()
                when {
                    code in 200..299 -> {
                        val finalEtag = respEtag.ifBlank {
                            (fetchRemoteMeta(target, auth, config.timeoutMs, fetchBody = false) as? ProbeResult.Found)
                                ?.meta?.etag.orEmpty()
                        }
                        val localMeta = parseEnvelopeMeta(envelopeJson, finalEtag)
                        SyncOutcome.Success(
                            revision = localMeta.revision.takeIf { it > 0L } ?: localRevision,
                            updatedAtMs = localMeta.updatedAtMs,
                            etag = finalEtag,
                            deviceLabel = localMeta.deviceLabel,
                            envelopeJson = envelopeJson,
                        )
                    }
                    code == 412 -> {
                        val latest = (fetchRemoteMeta(target, auth, config.timeoutMs, fetchBody = true) as? ProbeResult.Found)?.meta
                        SyncOutcome.Conflict(
                            remoteRevision = latest?.revision ?: 0L,
                            remoteDevice = latest?.deviceLabel.orEmpty(),
                            remoteEtag = latest?.etag.orEmpty(),
                            remoteUpdatedAtMs = latest?.updatedAtMs ?: 0L,
                            message = "远端快照发生并发修改 (HTTP 412)",
                        )
                    }
                    code == 401 || code == 403 -> SyncOutcome.Error("WebDAV 认证失败 (HTTP $code)")
                    else -> SyncOutcome.Error("WebDAV 上传失败 (HTTP $code)")
                }
            } finally {
                conn.disconnect()
            }
        }.getOrElse { err ->
            SyncOutcome.Error("WebDAV 上传异常: ${err.message ?: err.javaClass.simpleName}")
        }
    }

    suspend fun pullEnvelope(
        config: WebDavConfig,
        localRevision: Long,
        lastSyncedRevision: Long = 0L,
        lastSyncedEtag: String = "",
        localWorkspaceFile: File? = null,
        backupDir: File? = null,
        forceOverwrite: Boolean = false,
    ): SyncOutcome = withContext(Dispatchers.IO) {
        val target = resolveEnvelopeUrl(config.baseUrl)
            ?: return@withContext SyncOutcome.Error("仅支持 HTTPS WebDAV 地址（或本机回环调试地址）")
        val auth = buildBasicAuth(config.username, config.password)

        when (val probe = fetchRemoteMeta(target, auth, config.timeoutMs, fetchBody = true)) {
            is ProbeResult.NotFound -> SyncOutcome.NotFound("远端尚无加密同步快照")
            is ProbeResult.Failed -> SyncOutcome.Error(probe.message)
            is ProbeResult.Found -> {
                val m = probe.meta
                if (m.format != ENVELOPE_FORMAT) {
                    return@withContext SyncOutcome.Error("远端快照格式无效: ${m.format.ifBlank { "unknown" }}")
                }
                val localAhead = localRevision > m.revision && localRevision > 0L
                val divergedAfterSync = lastSyncedRevision > 0L &&
                    localRevision > lastSyncedRevision &&
                    (m.revision != lastSyncedRevision || (lastSyncedEtag.isNotBlank() && m.etag != lastSyncedEtag))
                val unsyncedEqualConflict = lastSyncedRevision == 0L && localRevision > 1L && localRevision == m.revision
                if (!forceOverwrite && (localAhead || divergedAfterSync || unsyncedEqualConflict)) {
                    val conflictMsg = when {
                        divergedAfterSync -> "本地 (rev $localRevision) 与远端 (rev ${m.revision}) 均已修改，发生分叉冲突"
                        unsyncedEqualConflict -> "本地与远端均存在独立修改 (rev ${m.revision})"
                        else -> "本地版本 (rev $localRevision) 新于远端版本 (rev ${m.revision})"
                    }
                    return@withContext SyncOutcome.Conflict(
                        remoteRevision = m.revision,
                        remoteDevice = m.deviceLabel,
                        remoteEtag = m.etag,
                        remoteUpdatedAtMs = m.updatedAtMs,
                        message = conflictMsg,
                    )
                }
                val backup = createPrePullBackup(localWorkspaceFile, backupDir)
                SyncOutcome.Success(
                    revision = m.revision,
                    updatedAtMs = m.updatedAtMs,
                    etag = m.etag,
                    deviceLabel = m.deviceLabel,
                    envelopeJson = m.body,
                    backupFile = backup,
                )
            }
        }
    }

    private sealed interface ProbeResult {
        data class Found(val meta: RemoteEnvelopeMeta) : ProbeResult
        data object NotFound : ProbeResult
        data class Failed(val message: String) : ProbeResult
    }

    private fun fetchRemoteMeta(url: URL, auth: String?, timeoutMs: Int, fetchBody: Boolean): ProbeResult =
        runCatching {
            val conn = openConn(url, if (fetchBody) "GET" else "HEAD", auth, timeoutMs)
            try {
                val code = conn.responseCode
                val etag = conn.getHeaderField("ETag")?.trim().orEmpty()
                when {
                    code == 404 -> ProbeResult.NotFound
                    code == 401 || code == 403 -> ProbeResult.Failed("WebDAV 认证失败 (HTTP $code)")
                    code in 200..299 -> {
                        val body = if (fetchBody) {
                            conn.inputStream.use { String(ProfileRepository.readBoundedBytes(it, MAX_ENVELOPE_BYTES), Charsets.UTF_8) }
                        } else ""
                        ProbeResult.Found(parseEnvelopeMeta(body, etag))
                    }
                    else -> ProbeResult.Failed("WebDAV 读取失败 (HTTP $code)")
                }
            } finally {
                conn.disconnect()
            }
        }.getOrElse { err ->
            ProbeResult.Failed("WebDAV 连接失败: ${err.message ?: err.javaClass.simpleName}")
        }

    private fun openConn(url: URL, method: String, auth: String?, timeoutMs: Int): HttpURLConnection =
        (url.openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            instanceFollowRedirects = false
            useCaches = false
            setRequestProperty("User-Agent", "Nexus-Android/1.0")
            if (!auth.isNullOrEmpty()) setRequestProperty("Authorization", auth)
        }

    private fun sendMkcol(url: URL, auth: String?, timeoutMs: Int): Int {
        val port = if (url.port != -1) url.port else url.defaultPort
        require(port in 1..65535) { "Invalid WebDAV port: $port" }
        val path = (url.path.ifEmpty { "/" }) + (url.query?.let { "?$it" } ?: "")
        val hostHeader = if (url.port != -1) "${url.host}:${url.port}" else url.host
        val plain = Socket()
        val sock: Socket = try {
            plain.connect(InetSocketAddress(url.host, port), timeoutMs)
            plain.soTimeout = timeoutMs
            if (url.protocol.equals("https", ignoreCase = true)) {
                val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                    .createSocket(plain, url.host, port, true) as SSLSocket
                ssl.soTimeout = timeoutMs
                ssl.sslParameters = ssl.sslParameters.apply {
                    endpointIdentificationAlgorithm = "HTTPS"
                }
                ssl.startHandshake()
                if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(url.host, ssl.session)) {
                    runCatching { ssl.close() }
                    throw SSLPeerUnverifiedException("HTTPS hostname verification failed for ${url.host}")
                }
                ssl
            } else {
                plain
            }
        } catch (t: Throwable) {
            runCatching { plain.close() }
            throw t
        }
        return sock.use { s ->
            s.soTimeout = timeoutMs
            val req = buildString {
                append("MKCOL ").append(path).append(" HTTP/1.1\r\n")
                append("Host: ").append(hostHeader).append("\r\n")
                append("User-Agent: Nexus-Android/1.0\r\n")
                if (!auth.isNullOrEmpty()) append("Authorization: ").append(auth).append("\r\n")
                append("Content-Length: 0\r\n")
                append("Connection: close\r\n\r\n")
            }
            s.getOutputStream().write(req.toByteArray(Charsets.US_ASCII))
            s.getOutputStream().flush()
            val statusLine = BufferedReader(InputStreamReader(s.getInputStream(), Charsets.US_ASCII)).readLine().orEmpty()
            statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: 0
        }
    }

    companion object {
        const val ENVELOPE_FILENAME = "nexus-workspace-v1.enc"
        const val ENVELOPE_FORMAT = "nexus-sync-v1"
        const val MAX_PRE_PULL_BACKUPS = 5
        private const val MAX_ENVELOPE_BYTES = 4 * 1024 * 1024
        private val backupSeq = AtomicLong(0L)

        fun validateWebDavUrl(raw: String): URL? {
            val trimmed = raw.trim()
            if (trimmed.isEmpty() || trimmed.any { it.isISOControl() || it.isWhitespace() }) return null
            val parsed = runCatching { URL(trimmed) }.getOrNull() ?: return null
            if (parsed.host.isNullOrBlank()) return null
            val proto = parsed.protocol.lowercase()
            val loopback = parsed.host.lowercase() in setOf("127.0.0.1", "localhost", "::1", "[::1]")
            return if (proto == "https" || (proto == "http" && loopback)) parsed else null
        }

        fun resolveEnvelopeUrl(rawBase: String): URL? {
            val base = validateWebDavUrl(rawBase) ?: return null
            val path = base.path.orEmpty()
            if (path.endsWith(".enc", ignoreCase = true)) return base
            val nextPath = path.trimEnd('/') + "/$ENVELOPE_FILENAME"
            val filePart = if (base.query.isNullOrEmpty()) nextPath else "$nextPath?${base.query}"
            val resolved = runCatching { URL(base.protocol, base.host, base.port, filePart) }.getOrNull() ?: return null
            return validateWebDavUrl(resolved.toExternalForm())
        }

        fun resolveCollectionUrl(rawBase: String): URL? {
            val base = validateWebDavUrl(rawBase) ?: return null
            val path = base.path.orEmpty()
            val colPath = if (!path.endsWith(".enc", ignoreCase = true)) {
                if (path.endsWith("/")) path else "$path/"
            } else {
                val slash = path.lastIndexOf('/')
                if (slash <= 0) return null
                path.substring(0, slash + 1)
            }
            val colUrl = runCatching { URL(base.protocol, base.host, base.port, colPath) }.getOrNull() ?: return null
            return validateWebDavUrl(colUrl.toExternalForm())
        }

        internal fun buildBasicAuth(username: String, password: String): String? {
            if (username.isEmpty() && password.isEmpty()) return null
            val raw = "${username.replace("\r", "").replace("\n", "")}:${password.replace("\r", "").replace("\n", "")}"
            return "Basic " + Base64.getEncoder().encodeToString(raw.toByteArray(Charsets.UTF_8))
        }

        fun parseEnvelopeMeta(body: String, etag: String = ""): RemoteEnvelopeMeta {
            val obj = WorkspaceSyncBridge.extractJsonObject(body)
                ?: return RemoteEnvelopeMeta(etag = etag, body = body)
            return RemoteEnvelopeMeta(
                format = obj.optString("format", ""),
                revision = obj.optLong("revision", 0L),
                updatedAtMs = obj.optLong("updated_at_ms", 0L),
                deviceLabel = obj.optString("device_label", ""),
                etag = etag,
                body = body,
            )
        }

        fun createPrePullBackup(
            localWorkspaceFile: File?,
            backupDir: File?,
            maxBackups: Int = MAX_PRE_PULL_BACKUPS,
        ): File? {
            if (localWorkspaceFile == null || !localWorkspaceFile.isFile || backupDir == null) return null
            backupDir.mkdirs()
            val seq = backupSeq.incrementAndGet() % 1_000_000L
            val name = String.format(Locale.US, "workspace.backup-%013d-%06d.json", System.currentTimeMillis(), seq)
            val backup = File(backupDir, name)
            val content = localWorkspaceFile.readText(Charsets.UTF_8)
            ProfileRepository.atomicWriteSecret0600(backup, content)
            val keep = maxBackups.coerceAtLeast(1)
            val existing = backupDir.listFiles { f ->
                f.isFile && f.name.startsWith("workspace.backup-") && f.name.endsWith(".json")
            }.orEmpty().sortedBy { it.name }
            if (existing.size > keep) {
                existing.take(existing.size - keep).forEach { old -> runCatching { old.delete() } }
            }
            return backup
        }
    }
}
