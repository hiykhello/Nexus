package org.nexus.android.ui

import android.net.InetAddresses
import android.os.Build
import android.system.OsConstants
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.nexus.android.bridge.core.CoreProcessSupervisor
import org.nexus.android.bridge.ipc.ActiveConnectionSnapshot
import org.nexus.android.bridge.ipc.NexusControlClient
import org.nexus.android.bridge.model.RuntimeSocketPaths
import org.nexus.android.bridge.owner.ConnectionOwnerResolver
import org.nexus.android.bridge.workspace.AndroidHostConfig
import org.nexus.android.bridge.workspace.AndroidPerAppMode
import java.io.File

/**
 * Coordinates legacy raw-KDL validation/save, connection owner UID/package lookup,
 * and mode-aware per-app bypass mutations outside [MainActivity].
 */
internal class MainTunnelCoordinator(
    private val filesDir: File,
    private val cacheDir: File,
    private val configFile: File,
    private val socketPaths: RuntimeSocketPaths,
    private val supervisor: CoreProcessSupervisor,
    private val controlClient: NexusControlClient,
) {
    fun ensureDefaultConfigExists() {
        if (!configFile.exists()) {
            writeConfigAtomically(defaultAndroidKdl(socketPaths))
        }
    }

    suspend fun validateDraft(text: String): Pair<Boolean, String> = withContext(Dispatchers.IO) {
        val draft = File.createTempFile("draft-", ".kdl", cacheDir)
        try {
            draft.writeText(text, Charsets.UTF_8)
            val res = supervisor.validateConfig(draft)
            res.ok to res.output
        } finally {
            runCatching { draft.delete() }
        }
    }

    fun writeConfigAtomically(text: String) {
        val parent = configFile.parentFile ?: filesDir
        parent.mkdirs()
        val tmp = File.createTempFile(".config-", ".kdl.tmp", parent)
        try {
            tmp.writeText(text, Charsets.UTF_8)
            if (!tmp.renameTo(configFile)) throw java.io.IOException("Atomic rename failed")
        } catch (t: Throwable) {
            runCatching { tmp.delete() }
            throw t
        }
    }

    suspend fun saveAndReload(text: String): Pair<Boolean, String> {
        val (ok, msg) = validateDraft(text)
        if (!ok) return false to "拒绝保存无效配置: $msg"
        val writeErr = withContext(Dispatchers.IO) { runCatching { writeConfigAtomically(text) }.exceptionOrNull() }
        if (writeErr != null) return false to "保存配置失败: ${writeErr.message}"
        val reload = controlClient.reload()
        return true to if (reload.ok) "已校验保存并热重载" else "已保存配置"
    }

    suspend fun resolveOwnerPackage(
        ownerResolver: ConnectionOwnerResolver?,
        conn: ActiveConnectionSnapshot,
    ): String? = withContext(Dispatchers.IO) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return@withContext null
        val resolver = ownerResolver ?: return@withContext null
        val src = AndroidHostConfig.parseHostPort(conn.source) ?: return@withContext null
        val dst = AndroidHostConfig.parseHostPort(conn.target) ?: return@withContext null
        if (!InetAddresses.isNumericAddress(src.first) || !InetAddresses.isNumericAddress(dst.first)) return@withContext null
        val proto = if (conn.protocol.contains("udp", ignoreCase = true)) OsConstants.IPPROTO_UDP else OsConstants.IPPROTO_TCP
        val info = runCatching {
            resolver.resolve(
                proto,
                InetAddresses.parseNumericAddress(src.first),
                src.second,
                InetAddresses.parseNumericAddress(dst.first),
                dst.second,
            )
        }.getOrNull() ?: return@withContext null
        if (info.packageNames.isNotEmpty()) "${info.packageNames.joinToString(", ")} (UID ${info.uid})" else "UID ${info.uid}"
    }

    companion object {
        /**
         * Mode-aware host mutation when user taps the per-app bypass button in Connection Inspector:
         * - `EXCLUDE`: appends `pkg` to `perAppPackages`
         * - `INCLUDE`: removes `pkg` from `perAppPackages`
         * - `OFF`: switches `perAppMode` to `EXCLUDE` and adds `pkg`
         */
        fun applyBypassFromConnection(cur: AndroidHostConfig, pkg: String): AndroidHostConfig {
            val action = computePerAppConnectionAction(
                perAppMode = cur.android.perAppMode,
                packageName = pkg,
                perAppPackages = cur.android.perAppPackages.toSet(),
            )
            if (!action.enabled) return cur
            val nextMode = if (action.switchToExcludeMode) AndroidPerAppMode.EXCLUDE else cur.android.perAppMode
            val nextPackages = if (action.removeFromList) {
                cur.android.perAppPackages.filterNot { it == pkg }
            } else {
                (cur.android.perAppPackages + pkg).distinct()
            }
            return cur.copy(
                android = cur.android.copy(
                    perAppMode = nextMode,
                    perAppPackages = nextPackages,
                ),
            )
        }

        private fun escapeKdlString(raw: String): String = buildString(raw.length) {
            for (ch in raw) when (ch) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                else -> if (ch.code >= 0x20 && ch.code != 0x7F && ch != '\u0085' && ch != '\u2028' && ch != '\u2029') append(ch)
            }
        }

        private fun androidControlDirective(paths: RuntimeSocketPaths): String {
            val ctrlSock = escapeKdlString(paths.controlSocket.absolutePath)
            val tokenFile = escapeKdlString(paths.controlTokenFile.absolutePath)
            return """control socket="$ctrlSock" http-listen="127.0.0.1:9090" bearer-token-file="$tokenFile" metrics=#true"""
        }

        internal fun defaultAndroidKdl(paths: RuntimeSocketPaths): String = """
            schema-version 1
            role "client"
            workers 1
            ${androidControlDirective(paths)}
            inbound "local" type="socks5" {
                listen host="127.0.0.1" port=10808
                authentication "none"
            }
            outbound "direct" type="direct"
            routing { default-outbound "direct"; }
        """.trimIndent() + "\n"
    }
}
