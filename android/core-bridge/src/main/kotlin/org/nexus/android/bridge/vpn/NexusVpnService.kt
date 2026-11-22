package org.nexus.android.bridge.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.service.quicksettings.TileService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.nexus.android.bridge.core.CoreProcessSupervisor
import org.nexus.android.bridge.ipc.NexusControlClient
import org.nexus.android.bridge.net.DefaultNetworkMonitor
import java.io.File
import java.util.concurrent.atomic.AtomicLong

/**
 * Non-root Android VpnService hosted in dedicated :bg process (isolated from UI GC).
 * Owns the TUN interface fd, ProtectSocketServer, physical network observer, and libnexus.so lifecycle.
 */
class NexusVpnService : VpnService() {
    private lateinit var supervisor: CoreProcessSupervisor
    private var tunInterface: ParcelFileDescriptor? = null
    private var protectServer: ProtectSocketServer? = null
    private var networkMonitor: DefaultNetworkMonitor? = null
    private var screenMonitor: ScreenStateMonitor? = null
    private var serviceScope: CoroutineScope? = null
    private val networkGeneration = AtomicLong(0L)

    override fun onCreate() {
        super.onCreate()
        supervisor = CoreProcessSupervisor(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val cfgPath = intent.getStringExtra(EXTRA_CONFIG_PATH)
                    ?: File(filesDir, "config.kdl").absolutePath
                val excluded = intent.getStringArrayListExtra(EXTRA_EXCLUDED_PACKAGES).orEmpty()
                startTunnel(File(cfgPath), excluded)
            }
            ACTION_STOP -> stopTunnel()
            else -> {
                // System Always-On VPN restart with null/default intent
                val defaultCfg = File(filesDir, "config.kdl")
                if (defaultCfg.isFile) startTunnel(defaultCfg, emptyList())
            }
        }
        return START_STICKY
    }

    override fun onRevoke() {
        stopTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    private fun startTunnel(configFile: File, excludedPackages: List<String>) {
        if (supervisor.isRunning()) return
        promoteForeground()

        val protectFile = File(noBackupFilesDir, "protect.sock")
        val protectSrv = ProtectSocketServer(protectFile) { fd -> protect(fd) }
        protectSrv.start()
        protectServer = protectSrv

        val builder = Builder()
            .setSession("Nexus")
            .setMtu(1400)
            .addAddress("172.19.0.1", 30)
            .addAddress("fdfe:dcba:9876::1", 126)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            .addDnsServer("172.19.0.2")
            .setMetered(false)

        // Exclude ourselves, Android captive portal login apps, and user-selected split-tunnel packages.
        val defaultExcluded = listOf(
            packageName,
            "com.android.captiveportallogin",
            "com.google.android.captiveportallogin",
        )
        for (pkg in (defaultExcluded + excludedPackages).distinct()) {
            runCatching { builder.addDisallowedApplication(pkg) }
        }

        val tun = builder.establish()
        if (tun == null) {
            stopTunnel()
            return
        }
        tunInterface = tun

        val started = supervisor.start(configFile, tun.fd) { line ->
            appendLog(line)
        }
        if (!started) {
            stopTunnel()
            return
        }
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        serviceScope = scope
        val controlClient = NexusControlClient(
            unixSocketPath = File(noBackupFilesDir, "control.sock").absolutePath,
            httpBaseUrl = "http://127.0.0.1:9090",
        )
        networkMonitor = DefaultNetworkMonitor(this, scope) { network, _ ->
            // Empty array on network loss (never null) to avoid routing loops.
            runCatching { setUnderlyingNetworks(if (network != null) arrayOf(network) else emptyArray()) }
            val gen = networkGeneration.incrementAndGet()
            scope.launch {
                runCatching { controlClient.notifyNetworkChange(gen) }
            }
        }.also { it.start() }
        screenMonitor = ScreenStateMonitor(this) { interactive ->
            _powerSaveMode.value = !interactive
            requestTileSync()
        }.also { it.start() }
        _powerSaveMode.value = false
        _runningState.value = true
        requestTileSync()
    }

    private fun stopTunnel() {
        runCatching { screenMonitor?.close() }
        screenMonitor = null
        _powerSaveMode.value = false
        runCatching { networkMonitor?.stop() }
        networkMonitor = null
        serviceScope?.cancel()
        serviceScope = null
        supervisor.stop()
        runCatching { tunInterface?.close() }
        tunInterface = null
        runCatching { protectServer?.close() }
        protectServer = null
        _runningState.value = false
        requestTileSync()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun requestTileSync() {
        runCatching {
            TileService.requestListeningState(
                this,
                ComponentName(packageName, "org.nexus.android.tile.NexusTileService"),
            )
        }
    }

    private fun promoteForeground() {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Nexus VPN",
                NotificationManager.IMPORTANCE_LOW,
            ).apply { description = "Nexus background proxy tunnel status" }
            nm.createNotificationChannel(channel)
        }
        val stopIntent = Intent(this, NexusVpnService::class.java).setAction(ACTION_STOP)
        val stopPending = PendingIntent.getService(
            this,
            1,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Nexus 正在运行")
            .setContentText("本地加密隧道已激活")
            .setSmallIcon(android.R.drawable.stat_sys_vp_phone_call)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, "停止", stopPending).build())
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    companion object {
        const val ACTION_START = "org.nexus.android.action.START_VPN"
        const val ACTION_STOP = "org.nexus.android.action.STOP_VPN"
        const val EXTRA_CONFIG_PATH = "org.nexus.android.extra.CONFIG_PATH"
        const val EXTRA_EXCLUDED_PACKAGES = "org.nexus.android.extra.EXCLUDED_PACKAGES"

        private const val CHANNEL_ID = "nexus_vpn_channel"
        private const val NOTIFICATION_ID = 9001

        private val _runningState = MutableStateFlow(false)
        val runningState: StateFlow<Boolean> = _runningState

        private val _powerSaveMode = MutableStateFlow(false)
        val powerSaveMode: StateFlow<Boolean> = _powerSaveMode

        private val _recentLogs = MutableStateFlow<List<String>>(emptyList())
        val recentLogs: StateFlow<List<String>> = _recentLogs

        private fun appendLog(line: String) {
            val current = _recentLogs.value
            val next = if (current.size >= 256) current.drop(1) + line else current + line
            _recentLogs.value = next
        }
    }
}
