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
import org.nexus.android.bridge.workspace.TelemetryStore
import java.io.File

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
     * Crash-loop-safe boot decision:
     * 1. Requires unlocked credential storage (`isUserUnlocked == true`).
     * 2. Requires `autoStartOnBoot` enabled in `host.json` (or legacy pref).
     * 3. If an unread unexpected-crash sentinel exists in `telemetry.json`, aborts boot launch,
     *    clears `autoStartOnBoot = false` in `host.json`, and clears the sentinel so the device
     *    never enters a boot crash-loop.
     * 4. In VPN mode requires prior VPN user consent (`vpnPrepared == true`); Proxy-Only skips consent.
     */
    fun evaluate(
        userUnlocked: Boolean,
        hostStore: AndroidHostConfigStore,
        telemetryStore: TelemetryStore,
        legacyAutoStartPref: Boolean,
        vpnPrepared: Boolean,
        configReady: Boolean,
        onClearLegacyAutoStart: () -> Unit = {},
    ): BootLaunchDecision {
        if (!userUnlocked) return BootLaunchDecision.SKIP_USER_LOCKED
        val host = hostStore.load()
        val enabled = host.android.autoStartOnBoot || (!hostStore.file.isFile && legacyAutoStartPref)
        if (!enabled) return BootLaunchDecision.SKIP_DISABLED
        if (telemetryStore.hasUnreadUnexpectedCrash()) {
            hostStore.save(host.copy(android = host.android.copy(autoStartOnBoot = false)))
            onClearLegacyAutoStart()
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
        val userManager = context.getSystemService(UserManager::class.java)
        val unlocked = userManager?.isUserUnlocked ?: true
        val prefs = context.getSharedPreferences("nexus_prefs", Context.MODE_PRIVATE)
        val paths = RuntimeSocketPaths(context.noBackupFilesDir)
        val hostStore = AndroidHostConfigStore(File(context.filesDir, "host.json"))
        val telemetryStore = TelemetryStore(paths.telemetryFile)
        val configFile = paths.composedConfigFile.takeIf { it.isFile } ?: File(context.filesDir, "config.kdl")

        val decision = BootLaunchPolicy.evaluate(
            userUnlocked = unlocked,
            hostStore = hostStore,
            telemetryStore = telemetryStore,
            legacyAutoStartPref = prefs.getBoolean("auto_start_on_boot", false),
            vpnPrepared = VpnService.prepare(context) == null,
            configReady = configFile.isFile,
            onClearLegacyAutoStart = {
                prefs.edit().putBoolean("auto_start_on_boot", false).apply()
            },
        )
        if (decision != BootLaunchDecision.LAUNCH) return

        context.startForegroundService(
            Intent(context, NexusVpnService::class.java)
                .setAction(NexusVpnService.ACTION_START)
                .putExtra(NexusVpnService.EXTRA_CONFIG_PATH, configFile.absolutePath),
        )
    }
}
