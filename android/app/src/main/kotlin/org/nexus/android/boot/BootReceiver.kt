package org.nexus.android.boot

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.UserManager
import org.nexus.android.bridge.model.RuntimeSocketPaths
import org.nexus.android.bridge.vpn.NexusVpnService
import org.nexus.android.bridge.workspace.AndroidHostConfigStore
import org.nexus.android.bridge.workspace.AndroidRunMode
import org.nexus.android.bridge.workspace.NexusClientDatabase
import org.nexus.android.bridge.workspace.TelemetryStore
import java.io.File
import java.util.concurrent.Executors

enum class BootLaunchDecision {
    LAUNCH,
    SKIP_USER_LOCKED,
    SKIP_DISABLED,
    ABORT_CRASH_LOOP,
    SKIP_VPN_NOT_PREPARED,
    SKIP_NO_CONFIG,
}

object BootLaunchPolicy {
    /**
     * Crash-loop-safe boot decision backed by SQLite 3 (WAL) `NexusClientDatabase`:
     * 1. Requires unlocked credential storage (`isUserUnlocked == true`).
     * 2. Requires `autoStartOnBoot` enabled in `AndroidHostConfigStore`.
     * 3. If an unread unexpected-crash sentinel exists in `TelemetryStore`, aborts boot launch,
     *    clears `autoStartOnBoot = false`, and clears the sentinel to prevent boot crash loops.
     * 4. In VPN mode requires prior VPN user consent (`vpnPrepared == true`); Proxy-Only skips consent.
     */
    fun evaluate(
        userUnlocked: Boolean,
        hostStore: AndroidHostConfigStore,
        telemetryStore: TelemetryStore,
        vpnPrepared: Boolean,
        configReady: Boolean,
    ): BootLaunchDecision {
        if (!userUnlocked) return BootLaunchDecision.SKIP_USER_LOCKED
        val host = hostStore.load()
        if (!host.android.autoStartOnBoot) return BootLaunchDecision.SKIP_DISABLED
        if (telemetryStore.hasUnreadUnexpectedCrash()) {
            hostStore.save(host.copy(android = host.android.copy(autoStartOnBoot = false)))
            telemetryStore.clearUnexpectedCrash()
            return BootLaunchDecision.ABORT_CRASH_LOOP
        }
        if (host.android.runMode == AndroidRunMode.VPN && !vpnPrepared) {
            return BootLaunchDecision.SKIP_VPN_NOT_PREPARED
        }
        if (!configReady) return BootLaunchDecision.SKIP_NO_CONFIG
        return BootLaunchDecision.LAUNCH
    }
}

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val appContext = context.applicationContext
        val pendingResult = goAsync()
        bootExecutor.execute {
            try {
                val userManager = appContext.getSystemService(UserManager::class.java)
                val unlocked = userManager?.isUserUnlocked ?: true
                val paths = RuntimeSocketPaths(appContext.noBackupFilesDir)
                val db = NexusClientDatabase.open(appContext)
                val hostStore = AndroidHostConfigStore(File(appContext.filesDir, "host.json"), db)
                val telemetryStore = TelemetryStore(paths.telemetryFile, db)
                val configFile = paths.composedConfigFile.takeIf { it.isFile } ?: File(appContext.filesDir, "config.kdl")

                val decision = BootLaunchPolicy.evaluate(
                    userUnlocked = unlocked,
                    hostStore = hostStore,
                    telemetryStore = telemetryStore,
                    vpnPrepared = VpnService.prepare(appContext) == null,
                    configReady = configFile.isFile,
                )
                if (decision == BootLaunchDecision.LAUNCH) {
                    appContext.startForegroundService(
                        Intent(appContext, NexusVpnService::class.java)
                            .setAction(NexusVpnService.ACTION_START)
                            .putExtra(NexusVpnService.EXTRA_CONFIG_PATH, configFile.absolutePath),
                    )
                }
            } finally {
                pendingResult.finish()
            }
        }
    }

    companion object {
        private val bootExecutor = Executors.newSingleThreadExecutor { r ->
            Thread(r, "nexus-boot-receiver").apply { isDaemon = true }
        }
    }
}
