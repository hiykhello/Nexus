package org.nexus.android.ui

import android.net.InetAddresses
import android.os.Build
import android.system.OsConstants
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.nexus.android.bridge.ipc.ActiveConnectionSnapshot
import org.nexus.android.bridge.owner.ConnectionOwnerResolver
import org.nexus.android.bridge.workspace.AndroidHostConfig
import org.nexus.android.bridge.workspace.AndroidPerAppMode

/**
 * Coordinates connection owner UID/package lookup and mode-aware per-app bypass mutations
 * outside [MainActivity]. Runtime configuration is owned strictly by [WorkspaceCoordinator].
 */
internal class MainTunnelCoordinator {
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
    }
}
