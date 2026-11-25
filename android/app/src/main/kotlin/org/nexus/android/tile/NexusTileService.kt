package org.nexus.android.tile

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.nexus.android.bridge.model.RuntimeSocketPaths
import org.nexus.android.bridge.vpn.NexusVpnService
import org.nexus.android.bridge.vpn.VpnTunnelState
import org.nexus.android.bridge.workspace.AndroidHostConfigStore
import org.nexus.android.bridge.workspace.AndroidRunMode
import org.nexus.android.bridge.workspace.TelemetryStore
import org.nexus.android.ui.MainActivity
import java.io.File

class NexusTileService : TileService() {
    private var listenScope: CoroutineScope? = null
    @Volatile
    private var cachedConfigReady: Boolean = false
    @Volatile
    private var cachedProfileName: String = "默认配置"
    @Volatile
    private var cachedRunMode: AndroidRunMode = AndroidRunMode.VPN

    override fun onStartListening() {
        super.onStartListening()
        listenScope?.cancel()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
        listenScope = scope
        scope.launch {
            combine(
                NexusVpnService.tunnelState,
                NexusVpnService.powerSaveMode,
            ) { tunnelState, powerSave -> tunnelState to powerSave }
                .collect { (tunnelState, powerSave) ->
                    val (configExists, profile, runMode) = withContext(Dispatchers.IO) {
                        readTileDiskMeta()
                    }
                    cachedConfigReady = configExists
                    cachedProfileName = profile
                    cachedRunMode = runMode
                    applyTileState(tunnelState, powerSave, configExists, profile)
                }
        }
    }

    override fun onStopListening() {
        listenScope?.cancel()
        listenScope = null
        super.onStopListening()
    }

    override fun onClick() {
        super.onClick()
        val state = NexusVpnService.tunnelState.value
        val activeOrStarting = state == VpnTunnelState.RUNNING ||
            state == VpnTunnelState.STARTING ||
            NexusVpnService.runningState.value
        if (activeOrStarting) {
            startService(Intent(this, NexusVpnService::class.java).setAction(NexusVpnService.ACTION_STOP))
            applyTileState(VpnTunnelState.STOPPED, powerSave = false, configExists = cachedConfigReady, profile = cachedProfileName)
            return
        }

        val configReady = cachedConfigReady
        val needsConsent = cachedRunMode == AndroidRunMode.VPN && VpnService.prepare(this) != null
        if (needsConsent || !configReady) {
            val launch = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                val pending = PendingIntent.getActivity(
                    this,
                    0,
                    launch,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )
                startActivityAndCollapse(pending)
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(launch)
            }
        } else {
            applyTileState(VpnTunnelState.STARTING, powerSave = false, configExists = true, profile = cachedProfileName)
            startForegroundService(
                Intent(this, NexusVpnService::class.java).setAction(NexusVpnService.ACTION_START),
            )
        }
    }

    private fun readTileDiskMeta(): Triple<Boolean, String, AndroidRunMode> {
        val paths = RuntimeSocketPaths(noBackupFilesDir)
        val configExists = paths.composedConfigFile.isFile || File(filesDir, "config.kdl").isFile
        val runMode = runCatching {
            AndroidHostConfigStore(File(filesDir, "host.json")).load().android.runMode
        }.getOrDefault(AndroidRunMode.VPN)
        val telemetryActive = runCatching { TelemetryStore(paths.telemetryFile).load().activeProfileId }.getOrDefault("")
        val activeFile = File(filesDir, ".active_profile")
        val profile = telemetryActive.ifBlank {
            runCatching {
                activeFile.takeIf { it.isFile }?.readText()?.trim()?.takeIf { it.isNotEmpty() }
            }.getOrNull() ?: "默认配置"
        }
        return Triple(configExists, profile, runMode)
    }

    private fun applyTileState(
        state: VpnTunnelState,
        powerSave: Boolean,
        configExists: Boolean,
        profile: String,
    ) {
        qsTile?.apply {
            this.state = when {
                !configExists && state == VpnTunnelState.STOPPED -> Tile.STATE_UNAVAILABLE
                state == VpnTunnelState.RUNNING || state == VpnTunnelState.STARTING -> Tile.STATE_ACTIVE
                else -> Tile.STATE_INACTIVE
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                subtitle = when {
                    !configExists && state == VpnTunnelState.STOPPED -> "待配置"
                    state == VpnTunnelState.STARTING -> "正在启动…"
                    state == VpnTunnelState.RUNNING && powerSave -> "省电 · $profile"
                    state == VpnTunnelState.RUNNING -> "已连接 · $profile"
                    state == VpnTunnelState.ERROR -> "启动异常"
                    else -> "已断开 · $profile"
                }
            }
            updateTile()
        }
    }
}
