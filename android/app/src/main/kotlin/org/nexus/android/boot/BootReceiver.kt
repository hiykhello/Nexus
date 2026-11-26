package org.nexus.android.boot

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.UserManager
import kotlinx.coroutines.runBlocking
import org.nexus.android.bridge.core.CoreProcessSupervisor
import org.nexus.android.bridge.model.RuntimeSocketPaths
import org.nexus.android.bridge.vpn.NexusVpnService
import org.nexus.android.bridge.workspace.AndroidHostConfig
import org.nexus.android.bridge.workspace.AndroidHostConfigStore
import org.nexus.android.bridge.workspace.AndroidRunMode
import org.nexus.android.bridge.workspace.NexusClientDatabase
import org.nexus.android.bridge.workspace.TelemetryStore
import org.nexus.android.bridge.workspace.WorkspaceComposer
import org.nexus.android.bridge.workspace.WorkspaceStore
import org.nexus.android.bridge.workspace.WorkspaceSyncBridge
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
    ): BootLaunchDecision = evaluate(
        userUnlocked = userUnlocked,
        hostStore = hostStore,
        telemetryStore = telemetryStore,
        vpnPrepared = vpnPrepared,
        resolveConfigReady = { configReady },
    )

    fun evaluate(
        userUnlocked: Boolean,
        hostStore: AndroidHostConfigStore,
        telemetryStore: TelemetryStore,
        vpnPrepared: Boolean,
        resolveConfigReady: () -> Boolean,
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
        if (!resolveConfigReady()) return BootLaunchDecision.SKIP_NO_CONFIG
        return BootLaunchDecision.LAUNCH
    }

    /**
     * Resolves boot target config without silently falling back to a stale `config.kdl` when
     * the SQLite workspace owns profiles but `composedConfigFile` is missing.
     */
    fun resolveBootConfigTarget(
        hasWorkspaceProfiles: Boolean,
        composedConfigFile: File,
        legacyConfigFile: File,
        composeOnDemand: () -> Boolean = { false },
    ): File? {
        if (hasWorkspaceProfiles) {
            if (composedConfigFile.isFile) return composedConfigFile
            if (composeOnDemand() && composedConfigFile.isFile) return composedConfigFile
            return null
        }
        return composedConfigFile.takeIf { it.isFile } ?: legacyConfigFile.takeIf { it.isFile }
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
                if (!unlocked) return@execute
                val paths = RuntimeSocketPaths(appContext.noBackupFilesDir)
                val db = NexusClientDatabase.open(appContext)
                val hostStore = AndroidHostConfigStore(File(appContext.filesDir, "host.json"), db)
                val telemetryStore = TelemetryStore(db)
                var workspaceStoreRef: WorkspaceStore? = null
                var resolvedTarget: File? = null

                val decision = BootLaunchPolicy.evaluate(
                    userUnlocked = unlocked,
                    hostStore = hostStore,
                    telemetryStore = telemetryStore,
                    vpnPrepared = VpnService.prepare(appContext) == null,
                    resolveConfigReady = {
                        val wsStore = WorkspaceStore(appContext.filesDir, db).also { workspaceStoreRef = it }
                        val summaries = runCatching { wsStore.listProfileSummaries() }.getOrDefault(emptyList())
                        resolvedTarget = BootLaunchPolicy.resolveBootConfigTarget(
                            hasWorkspaceProfiles = summaries.isNotEmpty(),
                            composedConfigFile = paths.composedConfigFile,
                            legacyConfigFile = File(appContext.filesDir, "config.kdl"),
                            composeOnDemand = { composeWorkspaceOnBoot(appContext, paths, wsStore, hostStore, telemetryStore) },
                        )
                        resolvedTarget?.isFile == true
                    },
                )
                val targetFile = resolvedTarget
                if (decision == BootLaunchDecision.LAUNCH && targetFile != null) {
                    val host = hostStore.load(paths)
                    val wsStore = workspaceStoreRef ?: WorkspaceStore(appContext.filesDir, db)
                    val fakeIpv6 = runCatching {
                        val doc = wsStore.loadOrInit()
                        if (AndroidHostConfig.needsFakeIpv6Route(doc, host.android)) doc.dns.simple.fakeIpV6Pool else ""
                    }.getOrDefault("")
                    appContext.startForegroundService(
                        Intent(appContext, NexusVpnService::class.java)
                            .setAction(NexusVpnService.ACTION_START)
                            .putExtra(NexusVpnService.EXTRA_CONFIG_PATH, targetFile.absolutePath)
                            .putExtra(NexusVpnService.EXTRA_FAKE_IPV6_POOL, fakeIpv6),
                    )
                }
            } finally {
                pendingResult.finish()
            }
        }
    }

    private fun composeWorkspaceOnBoot(
        context: Context,
        paths: RuntimeSocketPaths,
        workspaceStore: WorkspaceStore,
        hostStore: AndroidHostConfigStore,
        telemetryStore: TelemetryStore,
    ): Boolean = runCatching {
        val doc = workspaceStore.loadOrInit()
        val activeId = telemetryStore.load().activeProfileId
            .takeIf { id -> doc.profiles.any { it.id == id } }
            ?: doc.profiles.firstOrNull()?.id.orEmpty()
        if (activeId.isEmpty()) return false
        try {
            workspaceStore.writeCoreInputFile(paths.composeWorkspaceFile, doc)
            hostStore.writeCoreHostFile(paths.composeHostFile, paths)
            val composer = WorkspaceComposer(CoreProcessSupervisor(context))
            val res = runBlocking {
                composer.composeWorkspace(
                    workspaceFile = paths.composeWorkspaceFile,
                    hostFile = paths.composeHostFile,
                    secretsDir = paths.secretsDir,
                    activeProfileId = activeId,
                    emitKdlFile = paths.composedConfigFile,
                )
            }
            res.ok && paths.composedConfigFile.isFile
        } finally {
            WorkspaceSyncBridge.wipeAndDelete(paths.composeWorkspaceFile)
            WorkspaceSyncBridge.wipeAndDelete(paths.composeHostFile)
        }
    }.getOrDefault(false)

    companion object {
        private val bootExecutor = Executors.newSingleThreadExecutor { r ->
            Thread(r, "nexus-boot-receiver").apply { isDaemon = true }
        }
    }
}
