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
import android.net.ProxyInfo
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
import org.nexus.android.bridge.workspace.AndroidHostConfig
import org.nexus.android.bridge.workspace.AndroidHostConfigStore
import org.nexus.android.bridge.workspace.AndroidHostSection
import org.nexus.android.bridge.workspace.AndroidRunMode
import org.nexus.android.bridge.workspace.TelemetryStore
import org.nexus.android.bridge.workspace.WorkspaceStore
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

private data class LaunchRequest(
    val configTarget: File,
    val isConfigDir: Boolean,
    val hostOverrideFile: File?,
    val fakeIpv6Pool: String,
    val legacyExcludedOverride: List<String>?,
)

/**
 * Non-root Android VpnService coordinating the TUN descriptor (with Self-Inside-VPN Protect-FD
 * default & OFF/EXCLUDE/INCLUDE per-app split tunneling), Proxy-Only mode, Doze/Screen-Off power
 * saving, crash-sentinel tracking, and isolated native libnexus.so sidecar lifecycle.
 */
class NexusVpnService : VpnService() {
    private lateinit var supervisor: CoreProcessSupervisor
    private lateinit var paths: RuntimeSocketPaths
    private lateinit var hostStore: AndroidHostConfigStore
    private lateinit var telemetryStore: TelemetryStore
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
        hostStore = AndroidHostConfigStore(File(filesDir, "host.json"))
        telemetryStore = TelemetryStore(paths.telemetryFile)
        lifecycleExecutor = Executors.newSingleThreadExecutor { r ->
            Thread(r, "nexus-vpn-lifecycle").apply { isDaemon = true }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val req = resolveLaunchRequest(intent)
                if (!validateLaunchTarget(req)) return START_NOT_STICKY
                val host = loadEffectiveHost(req.legacyExcludedOverride)
                promoteForeground(host.android.runMode)
                submitLifecycle { startTunnelLocked(req, host) }
                return START_STICKY
            }
            ACTION_STOP -> {
                submitLifecycle { stopTunnelLocked(stopSelfAfter = true, preserveError = false) }
                return START_NOT_STICKY
            }
            ACTION_RESTART -> {
                val req = resolveLaunchRequest(intent)
                if (!validateLaunchTarget(req)) return START_NOT_STICKY
                val host = loadEffectiveHost(req.legacyExcludedOverride)
                promoteForeground(host.android.runMode)
                submitLifecycle {
                    stopTunnelLocked(stopSelfAfter = false, preserveError = false)
                    startTunnelLocked(req, host)
                }
                return START_STICKY
            }
            else -> {
                val req = resolveLaunchRequest(null)
                if (!req.configTarget.exists()) {
                    stopSelf()
                    return START_NOT_STICKY
                }
                val host = loadEffectiveHost(null)
                promoteForeground(host.android.runMode)
                submitLifecycle { startTunnelLocked(req, host) }
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
            // Allow background teardown without blocking main thread.
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

    private fun resolveLaunchRequest(intent: Intent?): LaunchRequest {
        val defaultTarget = paths.composedConfigFile.takeIf { it.isFile } ?: File(filesDir, "config.kdl")
        val cfgPath = intent?.getStringExtra(EXTRA_CONFIG_PATH) ?: defaultTarget.absolutePath
        val isDir = intent?.getBooleanExtra(EXTRA_CONFIG_IS_DIR, false) ?: false
        val ovPath = intent?.getStringExtra(EXTRA_HOST_OVERRIDE_PATH)?.takeIf { it.isNotBlank() }
        val fakeIpv6 = intent?.getStringExtra(EXTRA_FAKE_IPV6_POOL).orEmpty()
        val legacyExcluded = intent?.getStringArrayListExtra(EXTRA_EXCLUDED_PACKAGES)
        return LaunchRequest(
            configTarget = File(cfgPath),
            isConfigDir = isDir,
            hostOverrideFile = ovPath?.let { File(it) },
            fakeIpv6Pool = fakeIpv6,
            legacyExcludedOverride = legacyExcluded,
        )
    }

    private fun validateLaunchTarget(req: LaunchRequest): Boolean {
        val ok = if (req.isConfigDir) req.configTarget.isDirectory else req.configTarget.isFile
        if (ok) return true
        appendLog("[error] vpn: missing config ${req.configTarget.name}")
        _lastError.value = "未找到配置文件 ${req.configTarget.name}"
        _tunnelState.value = VpnTunnelState.ERROR
        requestTileSync()
        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
        stopSelf()
        return false
    }

    private fun loadEffectiveHost(legacyExcludedOverride: List<String>?): AndroidHostConfig {
        val loaded = hostStore.load(paths)
        if (loaded.android.perAppPackages.isNotEmpty() || hostStore.file.isFile) return loaded
        val legacy = legacyExcludedOverride ?: loadPersistedExcludedPackages()
        return if (legacy.isNotEmpty()) {
            loaded.copy(android = loaded.android.copy(perAppPackages = legacy))
        } else {
            loaded
        }
    }

    private fun submitLifecycle(task: () -> Unit) {
        runCatching { lifecycleExecutor.execute(task) }
            .onFailure { err -> if (err !is RejectedExecutionException) throw err }
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

    private fun configureRoutes(builder: Builder, host: AndroidHostSection, fakeIpv6Pool: String) {
        val dns4 = InetAddress.getByName(TUN_DNS_V4)
        val dns6 = InetAddress.getByName(TUN_DNS_V6)
        if (!host.bypassLan) {
            builder.addRoute("0.0.0.0", 0)
            if (host.enableIpv6) builder.addRoute("::", 0)
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            builder.addRoute("0.0.0.0", 0)
            CidrRouteCalculator.PRIVATE_IPV4_CIDRS.forEach { c -> runCatching { builder.excludeRoute(IpPrefix(c.address, c.prefixLength)) } }
            builder.addRoute(dns4, 32)
            if (host.enableIpv6) {
                builder.addRoute("::", 0)
                CidrRouteCalculator.PRIVATE_IPV6_CIDRS.forEach { c -> runCatching { builder.excludeRoute(IpPrefix(c.address, c.prefixLength)) } }
                builder.addRoute(dns6, 128)
                addExplicitIpv6PoolRoute(builder, fakeIpv6Pool)
            }
        } else {
            CidrRouteCalculator.computeAllowedRoutes(false, true, emptyList(), listOf(dns4))
                .forEach { r -> builder.addRoute(r.address, r.prefixLength) }
            if (host.enableIpv6) {
                CidrRouteCalculator.computeAllowedRoutes(true, true, emptyList(), listOf(dns6))
                    .forEach { r -> builder.addRoute(r.address, r.prefixLength) }
                addExplicitIpv6PoolRoute(builder, fakeIpv6Pool)
            }
        }
    }

    private fun addExplicitIpv6PoolRoute(builder: Builder, cidrPool: String) {
        val trimmed = cidrPool.trim()
        if (trimmed.isEmpty()) return
        val slash = trimmed.indexOf('/')
        if (slash <= 0) return
        val addrStr = trimmed.substring(0, slash)
        val prefix = trimmed.substring(slash + 1).toIntOrNull() ?: return
        if (prefix in 1..128) {
            runCatching { builder.addRoute(InetAddress.getByName(addrStr), prefix) }
        }
    }

    private fun startTunnelLocked(req: LaunchRequest, hostConfig: AndroidHostConfig) {
        if (supervisor.isRunning()) return
        val host = hostConfig.android
        _lastError.value = ""
        _tunnelState.value = VpnTunnelState.STARTING
        requestTileSync()
        try {
            paths.validatePaths()
            val sessionToken = writeSessionBearerToken()
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
            serviceScope = scope
            val httpUrl = hostConfig.common.controlHttpListen.takeIf { it.isNotBlank() }?.let { "http://$it" }
                ?: "http://127.0.0.1:9090"
            val controlClient = NexusControlClient(
                unixSocketPath = paths.controlSocket.absolutePath,
                httpBaseUrl = httpUrl,
                bearerToken = sessionToken,
            )

            var tunSockForCore: File? = null
            if (host.runMode == AndroidRunMode.VPN) {
                val protectSrv = ProtectSocketServer(paths.protectSocket) { fd -> protect(fd) }
                protectSrv.start()
                protectServer = protectSrv

                val builder = Builder()
                    .setSession("Nexus")
                    .setMtu(host.tunMtu.coerceIn(1280, 9000))
                    .addAddress("172.19.0.1", 30)
                    .addDnsServer(TUN_DNS_V4)
                    .setMetered(false)
                if (host.enableIpv6) {
                    builder.addAddress("fdfe:dcba:9876::1", 126)
                    builder.addDnsServer(TUN_DNS_V6)
                }
                if (host.allowBypass) {
                    builder.allowBypass()
                }
                if (host.enableLocalProxy && host.appendHttpProxy && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    AndroidHostConfig.parseHostPort(host.localListen)?.let { (h, p) ->
                        runCatching { builder.setHttpProxy(ProxyInfo.buildDirectProxy(h, p)) }
                    }
                }
                val effectiveFakeIpv6 = req.fakeIpv6Pool.ifBlank {
                    runCatching {
                        val ws = WorkspaceStore(filesDir).loadOrInit()
                        if (AndroidHostConfig.needsFakeIpv6Route(ws, host)) ws.dns.simple.fakeIpV6Pool else ""
                    }.getOrDefault("")
                }
                configureRoutes(builder, host, effectiveFakeIpv6)

                val plan = AndroidHostConfig.computePerAppPlan(packageName, host)
                for (pkg in plan.allowedPackages) runCatching { builder.addAllowedApplication(pkg) }
                for (pkg in plan.disallowedPackages) runCatching { builder.addDisallowedApplication(pkg) }

                val tun = builder.establish() ?: error("VpnService.Builder.establish() returned null")
                tunInterface = tun

                val fdSrv = TunFdSocketServer(paths.tunFdSocket, tun)
                fdSrv.start()
                tunFdServer = fdSrv
                tunSockForCore = paths.tunFdSocket

                val monitor = DefaultNetworkMonitor(this, scope) { network, _ ->
                    runCatching { setUnderlyingNetworks(if (network != null) arrayOf(network) else emptyArray()) }
                    val gen = networkGeneration.incrementAndGet()
                    scope.launch { runCatching { controlClient.notifyNetworkChange(gen) } }
                }.also { it.start() }
                networkMonitor = monitor

                val bridge = AndroidDnsBridge(paths.dnsBridgeSocket) { monitor.currentPhysicalNetwork }
                bridge.start()
                dnsBridge = bridge
            }

            val started = supervisor.start(
                configFile = req.configTarget,
                tunFdSocket = tunSockForCore,
                isConfigDir = req.isConfigDir,
                hostOverrideFile = req.hostOverrideFile,
                onLogLine = { line -> appendLog(line) },
                onExit = { code ->
                    appendLog("[error] core: sidecar exited unexpectedly (code=$code)")
                    runCatching { telemetryStore.recordUnexpectedCrash("exit=$code") }
                    _lastError.value = "内核进程异常退出 (exit=$code)"
                    _tunnelState.value = VpnTunnelState.ERROR
                    submitLifecycle { stopTunnelLocked(stopSelfAfter = true, preserveError = true) }
                },
            )
            if (!started) error("failed to start libnexus.so sidecar")

            val screen = ScreenStateMonitor(this) { interactive, idle ->
                _dozeMode.value = idle
                _powerSaveMode.value = ScreenStateMonitor.shouldPausePolling(
                    interactive = interactive,
                    deviceIdle = idle,
                    screenOffPauseStats = host.screenOffPauseStats,
                    dozePauseEnabled = host.dozePauseEnabled,
                )
                requestTileSync()
            }.also { it.start() }
            screenMonitor = screen
            _dozeMode.value = screen.isDeviceIdle
            _powerSaveMode.value = ScreenStateMonitor.shouldPausePolling(
                interactive = screen.isInteractive,
                deviceIdle = screen.isDeviceIdle,
                screenOffPauseStats = host.screenOffPauseStats,
                dozePauseEnabled = host.dozePauseEnabled,
            )
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
        runCatching { screenMonitor?.close() }; screenMonitor = null
        _dozeMode.value = false; _powerSaveMode.value = false
        runCatching { dnsBridge?.close() }; dnsBridge = null
        runCatching { networkMonitor?.stop() }; networkMonitor = null
        serviceScope?.cancel(); serviceScope = null
        supervisor.stop()
        runCatching { tunFdServer?.close() }; tunFdServer = null
        runCatching { tunInterface?.close() }; tunInterface = null
        runCatching { protectServer?.close() }; protectServer = null
        _startedAtMs.value = 0L; _runningState.value = false
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

    private fun promoteForeground(runMode: AndroidRunMode) {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Nexus VPN", NotificationManager.IMPORTANCE_LOW)
                    .apply { description = "Nexus background proxy tunnel status" },
            )
        }
        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)?.apply {
            addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        val contentPending = launchIntent?.let {
            PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        }
        val stopPending = PendingIntent.getService(
            this, 1, Intent(this, NexusVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val subtitle = if (runMode == AndroidRunMode.PROXY_ONLY) "仅本地代理模式已激活" else "本地加密隧道已激活"
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Nexus 正在运行")
            .setContentText(subtitle)
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
        const val EXTRA_CONFIG_IS_DIR = "org.nexus.android.extra.CONFIG_IS_DIR"
        const val EXTRA_HOST_OVERRIDE_PATH = "org.nexus.android.extra.HOST_OVERRIDE_PATH"
        const val EXTRA_FAKE_IPV6_POOL = "org.nexus.android.extra.FAKE_IPV6_POOL"
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

        private val _dozeMode = MutableStateFlow(false)
        val dozeMode: StateFlow<Boolean> = _dozeMode

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
