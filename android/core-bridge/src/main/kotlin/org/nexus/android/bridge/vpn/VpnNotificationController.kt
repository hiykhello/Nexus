package org.nexus.android.bridge.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import org.nexus.android.bridge.R
import org.nexus.android.bridge.workspace.AndroidRunMode
import java.util.Locale

/**
 * Manages the foreground service notification for [NexusVpnService]:
 * - Crisp monochrome prism icon (`R.drawable.ic_nexus_notification`)
 * - Silent updates (`setOnlyAlertOnce(true)`, `setShowWhen(false)`, `CATEGORY_SERVICE`)
 * - Shows active profile name, run mode, and throttled live speed (paused when `powerSave` is active)
 * - Quick actions: `重连` (`ACTION_RESTART`) and `停止` (`ACTION_STOP`)
 */
internal class VpnNotificationController(private val service: Service) {
    private val nm: NotificationManager by lazy {
        service.getSystemService(NotificationManager::class.java)
    }
    @Volatile
    private var lastUpdateMs: Long = 0L

    fun ensureChannel() {
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Nexus VPN", NotificationManager.IMPORTANCE_LOW).apply {
                    description = "Nexus background proxy tunnel status"
                    setShowBadge(false)
                },
            )
        }
    }

    fun promoteForeground(
        runMode: AndroidRunMode,
        profileName: String = "",
        downloadRateBps: Long = -1L,
        uploadRateBps: Long = -1L,
        powerSave: Boolean = false,
    ) {
        ensureChannel()
        val notification = buildNotification(
            runMode = runMode,
            profileName = profileName,
            downloadRateBps = downloadRateBps,
            uploadRateBps = uploadRateBps,
            powerSave = powerSave,
        )
        lastUpdateMs = System.currentTimeMillis()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            service.startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            service.startForeground(NOTIFICATION_ID, notification)
        }
    }

    fun updateIfDue(
        runMode: AndroidRunMode,
        profileName: String,
        downloadRateBps: Long,
        uploadRateBps: Long,
        powerSave: Boolean,
        force: Boolean = false,
    ) {
        val now = System.currentTimeMillis()
        if (!force && (powerSave || now - lastUpdateMs < MIN_UPDATE_INTERVAL_MS)) return
        ensureChannel()
        lastUpdateMs = now
        val notification = buildNotification(
            runMode = runMode,
            profileName = profileName,
            downloadRateBps = if (powerSave) -1L else downloadRateBps,
            uploadRateBps = if (powerSave) -1L else uploadRateBps,
            powerSave = powerSave,
        )
        runCatching { nm.notify(NOTIFICATION_ID, notification) }
    }

    private fun buildNotification(
        runMode: AndroidRunMode,
        profileName: String,
        downloadRateBps: Long,
        uploadRateBps: Long,
        powerSave: Boolean,
    ): Notification {
        val launchIntent = service.packageManager.getLaunchIntentForPackage(service.packageName)?.apply {
            addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        val contentPending = launchIntent?.let {
            PendingIntent.getActivity(
                service,
                0,
                it,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
        }
        val stopPending = PendingIntent.getService(
            service,
            1,
            Intent(service, NexusVpnService::class.java).setAction(NexusVpnService.ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val restartPending = PendingIntent.getForegroundService(
            service,
            2,
            Intent(service, NexusVpnService::class.java).setAction(NexusVpnService.ACTION_RESTART),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val modeLabel = if (runMode == AndroidRunMode.PROXY_ONLY) "本地代理" else "VPN 隧道"
        val cleanProfile = profileName.trim().ifEmpty { "默认配置" }
        val title = "Nexus · $cleanProfile"
        val subtitle = when {
            powerSave -> "$modeLabel · 省电模式"
            downloadRateBps >= 0L && uploadRateBps >= 0L ->
                "$modeLabel · ↓ ${formatRate(downloadRateBps)}  ↑ ${formatRate(uploadRateBps)}"
            else -> "$modeLabel · 运行中"
        }
        return Notification.Builder(service, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(subtitle)
            .setSmallIcon(R.drawable.ic_nexus_notification)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setCategory(Notification.CATEGORY_SERVICE)
            .apply { if (contentPending != null) setContentIntent(contentPending) }
            .addAction(Notification.Action.Builder(null, "重连", restartPending).build())
            .addAction(Notification.Action.Builder(null, "停止", stopPending).build())
            .build()
    }

    companion object {
        private const val CHANNEL_ID = "nexus_vpn_channel"
        private const val NOTIFICATION_ID = 9001
        private const val MIN_UPDATE_INTERVAL_MS = 2_000L

        internal fun formatRate(bytesPerSec: Long): String {
            val b = bytesPerSec.coerceAtLeast(0L)
            return when {
                b < 1_024L -> "${b} B/s"
                b < 1_024L * 1_024L -> String.format(Locale.US, "%.1f KB/s", b / 1_024.0)
                else -> String.format(Locale.US, "%.1f MB/s", b / (1_024.0 * 1_024.0))
            }
        }
    }
}
