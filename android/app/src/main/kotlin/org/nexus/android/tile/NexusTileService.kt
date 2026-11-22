package org.nexus.android.tile

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import org.nexus.android.bridge.vpn.NexusVpnService
import org.nexus.android.ui.MainActivity

class NexusTileService : TileService() {
    override fun onStartListening() {
        super.onStartListening()
        refreshTile()
    }

    override fun onClick() {
        super.onClick()
        val running = NexusVpnService.runningState.value
        if (running) {
            startService(Intent(this, NexusVpnService::class.java).setAction(NexusVpnService.ACTION_STOP))
        } else {
            if (VpnService.prepare(this) != null) {
                val launch = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    val pending = PendingIntent.getActivity(
                        this, 0, launch, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                    )
                    startActivityAndCollapse(pending)
                } else {
                    @Suppress("DEPRECATION")
                    startActivityAndCollapse(launch)
                }
            } else {
                startForegroundService(
                    Intent(this, NexusVpnService::class.java).setAction(NexusVpnService.ACTION_START),
                )
            }
        }
        refreshTile()
    }

    private fun refreshTile() {
        val running = NexusVpnService.runningState.value
        val powerSave = NexusVpnService.powerSaveMode.value
        qsTile?.apply {
            state = if (running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                subtitle = when {
                    running && powerSave -> "省电待机"
                    running -> "已连接"
                    else -> "已断开"
                }
            }
            updateTile()
        }
    }
}
