package org.nexus.android.ui

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.nexus.android.bridge.core.CoreProcessSupervisor
import org.nexus.android.bridge.ipc.NexusControlClient
import org.nexus.android.bridge.model.RuntimeSocketPaths
import org.nexus.android.bridge.profile.ProfileRepository
import org.nexus.android.bridge.workspace.SyncOutcome
import org.nexus.android.bridge.workspace.UdpProbeClient
import org.nexus.android.bridge.workspace.UdpProbeKind
import org.nexus.android.bridge.workspace.UdpProbeResult
import org.nexus.android.bridge.workspace.WebDavConfig
import org.nexus.android.bridge.workspace.WebDavSyncClient
import org.nexus.android.bridge.workspace.WorkspaceJsonCodec
import org.nexus.android.bridge.workspace.WorkspaceSyncBridge
import java.io.File

/**
 * Coordinates Wave 23 `nexus://share/v1/...` portable sharing, E2EE WebDAV sync (scrypt +
 * XChaCha20-Poly1305 via Core CLI with transient 0600 passphrase files), and UDP protocol probes.
 */
class WorkspaceSyncCoordinator(
    private val coordinator: WorkspaceCoordinator,
    private val socketPaths: RuntimeSocketPaths,
    supervisor: CoreProcessSupervisor,
    private val controlClient: NexusControlClient,
) {
    private val syncBridge = WorkspaceSyncBridge(supervisor, socketPaths.rootDir)
    private val webDavClient = WebDavSyncClient()
    private val udpProbeClient = UdpProbeClient(supervisor)
    private val backupDir = File(socketPaths.rootDir, "backups")

    suspend fun exportShareUri(profileId: String): Pair<String?, String> {
        val res = syncBridge.exportShare(coordinator.workspaceStore.workspaceFile, listOf(profileId))
        return if (res.ok && res.uri.isNotBlank()) {
            res.uri to "已生成便携分享链接（含 ${res.exportedCount} 个关联档案）"
        } else {
            null to "分享导出失败: ${res.errors.firstOrNull() ?: "不支持完整自定义档案"}"
        }
    }

    suspend fun importShareUri(uri: String, running: Boolean): Pair<WorkspaceUiState, String> {
        val wsFile = coordinator.workspaceStore.workspaceFile
        val tmpOut = File(socketPaths.rootDir, ".import-share-${System.nanoTime()}.json")
        return try {
            val res = syncBridge.importShare(wsFile, uri, outWorkspaceFile = tmpOut)
            if (!res.ok) {
                return coordinator.loadInitialState() to "导入 nexus:// 失败: ${res.errors.firstOrNull() ?: "格式无效"}"
            }
            val importedJson = withContext(Dispatchers.IO) {
                if (tmpOut.isFile) tmpOut.readText(Charsets.UTF_8) else res.workspaceJson
            }
            if (importedJson.isBlank()) {
                return coordinator.loadInitialState() to "导入 nexus:// 返回内容为空"
            }
            runCatching {
                withContext(Dispatchers.IO) {
                    coordinator.workspaceStore.importPortableJson(importedJson)
                    res.importedIds.firstOrNull()?.let { coordinator.telemetryStore.setActiveProfileId(it) }
                }
            }.getOrElse { err ->
                return coordinator.loadInitialState() to "导入 nexus:// 工作区解析失败: ${err.message ?: err.javaClass.simpleName}"
            }
            var reloadWarn = ""
            if (running) {
                val activeId = withContext(Dispatchers.IO) { coordinator.telemetryStore.load().activeProfileId }
                val composed = coordinator.composeForLaunch(activeId)
                if (composed.ok) {
                    controlClient.reload()
                } else {
                    reloadWarn = "（热重载校验失败: ${composed.errors.firstOrNull() ?: "未知错误"}）"
                }
            }
            coordinator.loadInitialState() to "已导入 ${res.importedIds.size} 个 nexus:// 档案$reloadWarn"
        } finally {
            WorkspaceSyncBridge.wipeAndDelete(tmpOut)
        }
    }

    suspend fun pushWebDav(forceOverwrite: Boolean): Triple<WorkspaceUiState, SyncConflictUi?, String> {
        val state = coordinator.loadInitialState()
        val a = state.host.android
        if (a.webdavUrl.isBlank()) return Triple(state, null, "请先填写 HTTPS WebDAV 地址")
        if (a.syncPassphrase.isBlank()) return Triple(state, null, "请先填写端到端同步口令")

        val envFile = File(socketPaths.rootDir, ".seal-env-${System.nanoTime()}.enc")
        return try {
            val sealed = syncBridge.sealSync(
                workspaceFile = coordinator.workspaceStore.workspaceFile,
                passphrase = a.syncPassphrase,
                deviceLabel = a.syncDeviceLabel.ifBlank { "Android" },
                outEnvelopeFile = envFile,
            )
            if (!sealed.ok) {
                return Triple(state, null, "加密工作区失败: ${sealed.errors.firstOrNull() ?: "未知错误"}")
            }
            val envelopeJson = withContext(Dispatchers.IO) {
                if (envFile.isFile) envFile.readText(Charsets.UTF_8) else sealed.envelopeJson
            }
            val outcome = webDavClient.pushEnvelope(
                config = WebDavConfig(a.webdavUrl, a.webdavUsername, a.webdavPassword),
                envelopeJson = envelopeJson,
                localRevision = sealed.revision.takeIf { it > 0L } ?: state.document.revision,
                expectedEtag = a.lastSyncedEtag,
                forceOverwrite = forceOverwrite,
            )
            when (outcome) {
                is SyncOutcome.Success -> {
                    val (nextState, _) = coordinator.mutateHost { cur ->
                        cur.copy(
                            android = cur.android.copy(
                                lastSyncedEtag = outcome.etag,
                                lastSyncedRevision = outcome.revision,
                            ),
                        )
                    }
                    Triple(nextState, null, "已上传端到端加密快照 (rev ${outcome.revision})")
                }
                is SyncOutcome.Conflict -> {
                    val conflict = SyncConflictUi(
                        direction = "push",
                        remoteRevision = outcome.remoteRevision,
                        remoteDevice = outcome.remoteDevice,
                        remoteEtag = outcome.remoteEtag,
                        message = outcome.message,
                    )
                    Triple(state, conflict, "同步冲突：${outcome.message}")
                }
                is SyncOutcome.NotFound -> Triple(state, null, outcome.message)
                is SyncOutcome.Error -> Triple(state, null, outcome.message)
            }
        } finally {
            runCatching { envFile.delete() }
        }
    }

    suspend fun pullWebDav(
        forceOverwrite: Boolean,
        running: Boolean,
    ): Triple<WorkspaceUiState, SyncConflictUi?, String> {
        val state = coordinator.loadInitialState()
        val a = state.host.android
        if (a.webdavUrl.isBlank()) return Triple(state, null, "请先填写 HTTPS WebDAV 地址")
        if (a.syncPassphrase.isBlank()) return Triple(state, null, "请先填写端到端同步口令")

        val outcome = webDavClient.pullEnvelope(
            config = WebDavConfig(a.webdavUrl, a.webdavUsername, a.webdavPassword),
            localRevision = state.document.revision,
            lastSyncedRevision = a.lastSyncedRevision,
            lastSyncedEtag = a.lastSyncedEtag,
            forceOverwrite = forceOverwrite,
        )
        when (outcome) {
            is SyncOutcome.NotFound -> return Triple(state, null, outcome.message)
            is SyncOutcome.Error -> return Triple(state, null, outcome.message)
            is SyncOutcome.Conflict -> {
                val conflict = SyncConflictUi(
                    direction = "pull",
                    remoteRevision = outcome.remoteRevision,
                    remoteDevice = outcome.remoteDevice,
                    remoteEtag = outcome.remoteEtag,
                    message = outcome.message,
                )
                return Triple(state, conflict, "同步冲突：${outcome.message}")
            }
            is SyncOutcome.Success -> {
                val envFile = File(socketPaths.rootDir, ".pull-env-${System.nanoTime()}.enc")
                val wsOut = File(socketPaths.rootDir, ".pull-ws-${System.nanoTime()}.json")
                try {
                    withContext(Dispatchers.IO) {
                        ProfileRepository.atomicWriteSecret0600(envFile, outcome.envelopeJson)
                    }
                    val opened = syncBridge.openSync(envFile, a.syncPassphrase, wsOut)
                    if (!opened.ok) {
                        return Triple(state, null, "解密远端快照失败: ${opened.errors.firstOrNull() ?: "口令错误或数据损坏"}")
                    }
                    val decryptedJson = withContext(Dispatchers.IO) {
                        if (wsOut.isFile) wsOut.readText(Charsets.UTF_8) else opened.workspaceJson
                    }
                    if (decryptedJson.isBlank()) {
                        return Triple(state, null, "解密远端快照失败：工作区内容为空")
                    }
                    val (backupFile, imported) = runCatching {
                        withContext(Dispatchers.IO) {
                            WorkspaceJsonCodec.decode(decryptedJson)
                            val backup = WebDavSyncClient.createPrePullBackup(coordinator.workspaceStore.workspaceFile, backupDir)
                            val saved = coordinator.workspaceStore.importPortableJson(decryptedJson, bumpRevision = false)
                            backup to saved
                        }
                    }.getOrElse { err ->
                        return Triple(state, null, "远端工作区 JSON 无效: ${err.message ?: err.javaClass.simpleName}")
                    }
                    val syncedRev = outcome.revision.takeIf { it > 0L } ?: imported.revision
                    val (nextState, _) = coordinator.mutateHost { cur ->
                        cur.copy(
                            android = cur.android.copy(
                                lastSyncedEtag = outcome.etag,
                                lastSyncedRevision = syncedRev,
                            ),
                        )
                    }
                    var reloadWarn = ""
                    if (running && imported.profiles.isNotEmpty()) {
                        val activeId = withContext(Dispatchers.IO) {
                            coordinator.telemetryStore.load().activeProfileId
                                .takeIf { id -> imported.profiles.any { it.id == id } }
                                ?: imported.profiles.first().id.also { coordinator.telemetryStore.setActiveProfileId(it) }
                        }
                        val composed = coordinator.composeForLaunch(activeId)
                        if (composed.ok) {
                            controlClient.reload()
                        } else {
                            reloadWarn = "（热重载校验失败: ${composed.errors.firstOrNull() ?: "未知错误"}）"
                        }
                    }
                    val backupNote = if (backupFile != null) "，已自动备份本地工作区" else ""
                    return Triple(nextState, null, "已拉取远端快照 (rev $syncedRev · ${imported.profiles.size} 档案$backupNote)$reloadWarn")
                } finally {
                    WorkspaceSyncBridge.wipeAndDelete(envFile)
                    WorkspaceSyncBridge.wipeAndDelete(wsOut)
                }
            }
        }
    }

    suspend fun runUdpProbe(kind: UdpProbeKind, running: Boolean): Pair<UdpProbeResult, String> {
        val host = withContext(Dispatchers.IO) { coordinator.hostStore.load(socketPaths).android }
        val socks = if (running && host.enableLocalProxy) host.localListen else ""
        val res = udpProbeClient.probe(kind = kind, socks5Listen = socks)
        val msg = if (res.ok) {
            "${kind.label} 探测成功 (${res.rttMs} ms${if (res.viaSocks5) " · SOCKS5" else ""})"
        } else {
            "${kind.label} 探测失败: ${res.error}"
        }
        return res to msg
    }
}
