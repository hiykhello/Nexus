package org.nexus.android.bridge.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.IpPrefix
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
import org.nexus.android.bridge.dns.AndroidDnsBridge
import org.nexus.android.bridge.ipc.NexusControlClient
import org.nexus.android.bridge.model.RuntimeSocketPaths
import org.nexus.android.bridge.net.CidrRouteCalculator
import org.nexus.android.bridge.net.DefaultNetworkMonitor
import org.nexus.android.bridge.profile.ProfileRepository
import java.io.File
import java.net.InetAddress
import java.security.SecureRandom
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicLong

data class ServiceLogLine(
    val seq: Long,
    val text: String,
)

enum class VpnTunnelState {
    STOPPED,
    STARTING,
    RUNNING,
    ERROR,
}

/**
 * Non-root Android VpnService coordinating the TUN descriptor, ProtectSocketServer,
 * AndroidDnsBridge, physical network observer, and isolated native libnexus.so child process.
 */
class NexusVpnService : VpnService() {
    private lateinit var supervisor: CoreProcessSupervisor
    private lateinit var paths: RuntimeSocketPaths
    private lateinit var lifecycleExecutor: ExecutorService
    private var tunInterface: ParcelFileDescriptor? = null
    private var protectServer: ProtectSocketServer? = null
    private var tunFdServer: TunFdSocketServer? = null
    private var dnsBridge: AndroidDnsBridge? = null
    private var networkMonitor: DefaultNetworkMonitor? = null
    private var screenMonitor: ScreenStateMonitor? = null
    private var serviceScope: CoroutineScope? = null
    private val networkGeneration = AtomicLong(0L)

    override fun onCreate() {
        super.onCreate()
        supervisor = CoreProcessSupervisor(this)
        paths = RuntimeSocketPaths(noBackupFilesDir)
        lifecycleExecutor = Executors.newSingleThreadExecutor { r ->
            Thread(r, "nexus-vpn-lifecycle").apply { isDaemon = true }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                promoteForeground()
                val cfgPath = intent.getStringExtra(EXTRA_CONFIG_PATH)
                    ?: File(filesDir, "config.kdl").absolutePath
                val cfgFile = File(cfgPath)
                if (!cfgFile.isFile) {
                    appendLog("[error] vpn: missing config file ${cfgFile.name}")
                    _lastError.value = "未找到配置文件 ${cfgFile.name}"
                    _tunnelState.value = VpnTunnelState.ERROR
                    requestTileSync()
                    runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
                    stopSelf()
                    return START_NOT_STICKY
                }
                val excluded = intent.getStringArrayListExtra(EXTRA_EXCLUDED_PACKAGES)
                    ?: loadPersistedExcludedPackages()
                submitLifecycle { startTunnelLocked(cfgFile, excluded) }
                return START_STICKY
            }
            ACTION_STOP -> {
                submitLifecycle { stopTunnelLocked(stopSelfAfter = true, preserveError = false) }
                return START_NOT_STICKY
            }
            ACTION_RESTART -> {
                promoteForeground()
                val cfgPath = intent.getStringExtra(EXTRA_CONFIG_PATH)
                    ?: File(filesDir, "config.kdl").absolutePath
                val cfgFile = File(cfgPath)
                if (!cfgFile.isFile) {
                    appendLog("[error] vpn: missing config file ${cfgFile.name}")
                    _lastError.value = "未找到配置文件 ${cfgFile.name}"
                    _tunnelState.value = VpnTunnelState.ERROR
                    requestTileSync()
                    runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
                    stopSelf()
                    return START_NOT_STICKY
                }
                val excluded = intent.getStringArrayListExtra(EXTRA_EXCLUDED_PACKAGES)
                    ?: loadPersistedExcludedPackages()
                submitLifecycle {
                    stopTunnelLocked(stopSelfAfter = false, preserveError = false)
                    startTunnelLocked(cfgFile, excluded)
                }
                return START_STICKY
            }
            else -> {
                // System Always-On VPN restart with null/default intent
                val defaultCfg = File(filesDir, "config.kdl")
                if (!defaultCfg.isFile) {
                    stopSelf()
                    return START_NOT_STICKY
                }
                promoteForeground()
                val excluded = loadPersistedExcludedPackages()
                submitLifecycle { startTunnelLocked(defaultCfg, excluded) }
                return START_STICKY
            }
        }
    }

    override fun onRevoke() {
        submitLifecycle { stopTunnelLocked(stopSelfAfter = true) }
        super.onRevoke()
    }

    override fun onDestroy() {
        try {
            lifecycleExecutor.submit { stopTunnelLocked(stopSelfAfter = false) }
                .get(DESTROY_WAIT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        } catch (_: TimeoutException) {
            // Allow queued teardown to finish on the single background lifecycle thread without blocking main.
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        } catch (_: ExecutionException) {
            // Best-effort cleanup during service teardown.
        } catch (_: RejectedExecutionException) {
            // Executor already shut down.
        } finally {
            lifecycleExecutor.shutdown()
        }
        super.onDestroy()
    }

    private fun submitLifecycle(task: () -> Unit) {
        runCatching {
            lifecycleExecutor.execute(task)
        }.onFailure { err ->
            if (err !is RejectedExecutionException) throw err
        }
    }

    private fun loadPersistedExcludedPackages(): List<String> {
        val prefs = getSharedPreferences("nexus_prefs", Context.MODE_PRIVATE)
        return prefs.getStringSet("excluded_packages", emptySet()).orEmpty().toList()
    }

    private fun writeSessionBearerToken(): String {
        val bytes = ByteArray(24)
        SecureRandom().nextBytes(bytes)
        val token = bytes.joinToString("") { "%02x".format(it) }
        ProfileRepository.atomicWriteSecret0600(paths.controlTokenFile, "$token\n")
        return token
    }

    private fun configureRoutes(builder: Builder) {
        val dns4 = InetAddress.getByName(TUN_DNS_V4)
        val dns6 = InetAddress.getByName(TUN_DNS_V6)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            builder.addRoute("0.0.0.0", 0)
            builder.addRoute("::", 0)
            for (cidr in CidrRouteCalculator.PRIVATE_IPV4_CIDRS) {
                runCatching { builder.excludeRoute(IpPrefix(cidr.address, cidr.prefixLength)) }
            }
            for (cidr in CidrRouteCalculator.PRIVATE_IPV6_CIDRS) {
                runCatching { builder.excludeRoute(IpPrefix(cidr.address, cidr.prefixLength)) }
            }
            // Pin TUN DNS sentinels inside the tunnel despite private CIDR exclusions.
            builder.addRoute(dns4, 32)
            builder.addRoute(dns6, 128)
        } else {
            val v4Routes = CidrRouteCalculator.computeAllowedRoutes(
                ipv6 = false,
                excludePrivate = true,
                extraExcludes = emptyList(),
                mustIncludeAddresses = listOf(dns4),
            )
            for (r in v4Routes) {
                builder.addRoute(r.address, r.prefixLength)
            }
            val v6Routes = CidrRouteCalculator.computeAllowedRoutes(
                ipv6 = true,
                excludePrivate = true,
                extraExcludes = emptyList(),
                mustIncludeAddresses = listOf(dns6),
            )
            for (r in v6Routes) {
                builder.addRoute(r.address, r.prefixLength)
            }
        }
    }

    private fun startTunnelLocked(configFile: File, excludedPackages: List<String>) {
        if (supervisor.isRunning()) return
        _lastError.value = ""
        _tunnelState.value = VpnTunnelState.STARTING
        requestTileSync()
        try {
            paths.validatePaths()
            val sessionToken = writeSessionBearerToken()

            val protectSrv = ProtectSocketServer(paths.protectSocket) { fd -> protect(fd) }
            protectSrv.start()
            protectServer = protectSrv

            val builder = Builder()
                .setSession("Nexus")
                .setMtu(1400)
                .addAddress("172.19.0.1", 30)
                .addAddress("fdfe:dcba:9876::1", 126)
                .addDnsServer(TUN_DNS_V4)
                .addDnsServer(TUN_DNS_V6)
                .setMetered(false)
            configureRoutes(builder)

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
                ?: error("VpnService.Builder.establish() returned null")
            tunInterface = tun

            val fdSrv = TunFdSocketServer(paths.tunFdSocket, tun)
            fdSrv.start()
            tunFdServer = fdSrv

            val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
            serviceScope = scope

            val controlClient = NexusControlClient(
                unixSocketPath = paths.controlSocket.absolutePath,
                httpBaseUrl = "http://127.0.0.1:9090",
                bearerToken = sessionToken,
            )
            val monitor = DefaultNetworkMonitor(this, scope) { network, _ ->
                // Empty array on network loss (never null) to avoid routing loops.
                runCatching { setUnderlyingNetworks(if (network != null) arrayOf(network) else emptyArray()) }
                val gen = networkGeneration.incrementAndGet()
                scope.launch {
                    runCatching { controlClient.notifyNetworkChange(gen) }
                }
            }.also { it.start() }
            networkMonitor = monitor

            val bridge = AndroidDnsBridge(paths.dnsBridgeSocket) { monitor.currentPhysicalNetwork }
            bridge.start()
            dnsBridge = bridge

            val started = supervisor.start(
                configFile = configFile,
                tunFdSocket = paths.tunFdSocket,
                onLogLine = { line -> appendLog(line) },
                onExit = { code ->
                    appendLog("[error] core: sidecar exited unexpectedly (code=$code)")
                    _lastError.value = "内核进程异常退出 (exit=$code)"
                    _tunnelState.value = VpnTunnelState.ERROR
                    submitLifecycle { stopTunnelLocked(stopSelfAfter = true, preserveError = true) }
                },
            )
            if (!started) {
                error("failed to start libnexus.so sidecar")
            }

            val screen = ScreenStateMonitor(this) { interactive ->
                _powerSaveMode.value = !interactive
                requestTileSync()
            }.also { it.start() }
            screenMonitor = screen
            _powerSaveMode.value = !screen.isInteractive
            _startedAtMs.value = System.currentTimeMillis()
            _runningState.value = true
            _tunnelState.value = VpnTunnelState.RUNNING
            requestTileSync()
        } catch (t: Throwable) {
            val msg = t.message ?: t.javaClass.simpleName
            appendLog("[error] vpn: startup failed: $msg")
            _lastError.value = msg
            _tunnelState.value = VpnTunnelState.ERROR
            stopTunnelLocked(stopSelfAfter = true, preserveError = true)
        }
    }

    private fun stopTunnelLocked(stopSelfAfter: Boolean, preserveError: Boolean = false) {
        runCatching { screenMonitor?.close() }
        screenMonitor = null
        _powerSaveMode.value = false
        runCatching { dnsBridge?.close() }
        dnsBridge = null
        runCatching { networkMonitor?.stop() }
        networkMonitor = null
        serviceScope?.cancel()
        serviceScope = null
        supervisor.stop()
        runCatching { tunFdServer?.close() }
        tunFdServer = null
        runCatching { tunInterface?.close() }
        tunInterface = null
        runCatching { protectServer?.close() }
        protectServer = null
        _startedAtMs.value = 0L
        _runningState.value = false
        if (!preserveError) {
            _lastError.value = ""
            _tunnelState.value = VpnTunnelState.STOPPED
        }
        requestTileSync()
        if (stopSelfAfter) {
            runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
            stopSelf()
        }
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
        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)?.apply {
            addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        val contentPending = launchIntent?.let {
            PendingIntent.getActivity(
                this,
                0,
                it,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
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
            .apply { if (contentPending != null) setContentIntent(contentPending) }
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
        const val ACTION_RESTART = "org.nexus.android.action.RESTART_VPN"
        const val EXTRA_CONFIG_PATH = "org.nexus.android.extra.CONFIG_PATH"
        const val EXTRA_EXCLUDED_PACKAGES = "org.nexus.android.extra.EXCLUDED_PACKAGES"

        private const val CHANNEL_ID = "nexus_vpn_channel"
        private const val NOTIFICATION_ID = 9001
        private const val DESTROY_WAIT_TIMEOUT_MS = 250L
        private const val TUN_DNS_V4 = "172.19.0.2"
        private const val TUN_DNS_V6 = "fdfe:dcba:9876::2"

        private val logSeq = AtomicLong(0L)
        private val logLock = Any()

        private val _runningState = MutableStateFlow(false)
        val runningState: StateFlow<Boolean> = _runningState

        private val _tunnelState = MutableStateFlow(VpnTunnelState.STOPPED)
        val tunnelState: StateFlow<VpnTunnelState> = _tunnelState

        private val _startedAtMs = MutableStateFlow(0L)
        val startedAtMs: StateFlow<Long> = _startedAtMs

        private val _lastError = MutableStateFlow("")
        val lastError: StateFlow<String> = _lastError

        private val _powerSaveMode = MutableStateFlow(false)
        val powerSaveMode: StateFlow<Boolean> = _powerSaveMode

        private val _recentLogs = MutableStateFlow<List<ServiceLogLine>>(emptyList())
        val recentLogs: StateFlow<List<ServiceLogLine>> = _recentLogs

        private fun appendLog(line: String) {
            val entry = ServiceLogLine(seq = logSeq.incrementAndGet(), text = line)
            synchronized(logLock) {
                val current = _recentLogs.value
                _recentLogs.value = if (current.size >= 256) current.drop(1) + entry else current + entry
            }
        }
    }
}
