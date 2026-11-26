package org.nexus.android.bridge.vpn

import android.content.ComponentName
import android.content.Intent
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
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.nexus.android.bridge.core.CoreProcessSupervisor
import org.nexus.android.bridge.dns.AndroidDnsBridge
import org.nexus.android.bridge.ipc.NexusControlClient
import org.nexus.android.bridge.model.RuntimeSocketPaths
import org.nexus.android.bridge.net.CidrRouteCalculator
import org.nexus.android.bridge.net.DefaultNetworkMonitor
import org.nexus.android.bridge.profile.SecretFileIO
import org.nexus.android.bridge.workspace.AndroidHostConfig
import org.nexus.android.bridge.workspace.AndroidHostConfigStore
import org.nexus.android.bridge.workspace.AndroidHostSection
import org.nexus.android.bridge.workspace.AndroidRunMode
import org.nexus.android.bridge.workspace.NexusClientDatabase
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
)

/**
 * Non-root Android VpnService coordinating the TUN descriptor (with Self-Inside-VPN Protect-FD
 * default & OFF/EXCLUDE/INCLUDE per-app split tunneling), Proxy-Only mode, Doze/Screen-Off power
 * saving, crash-sentinel tracking, and isolated native libnexus.so sidecar lifecycle.
 */
class NexusVpnService : VpnService() {
    private lateinit var supervisor: CoreProcessSupervisor
    private lateinit var paths: RuntimeSocketPaths
    private lateinit var db: NexusClientDatabase
    private lateinit var workspaceStore: WorkspaceStore
    private lateinit var hostStore: AndroidHostConfigStore
    private lateinit var telemetryStore: TelemetryStore
    private lateinit var notifications: VpnNotificationController
    private lateinit var lifecycleExecutor: ExecutorService
    private var tunInterface: ParcelFileDescriptor? = null
    private var protectServer: ProtectSocketServer? = null
    private var tunFdServer: TunFdSocketServer? = null
    private var dnsBridge: AndroidDnsBridge? = null
    private var networkMonitor: DefaultNetworkMonitor? = null
    private var screenMonitor: ScreenStateMonitor? = null
    private var serviceScope: CoroutineScope? = null
    private val networkGeneration = AtomicLong(0L)
    @Volatile private var lastRunMode: AndroidRunMode = AndroidRunMode.VPN
    @Volatile private var activeProfileLabel: String = ""

    override fun onCreate() {
        super.onCreate()
        supervisor = CoreProcessSupervisor(this)
        paths = RuntimeSocketPaths(noBackupFilesDir)
        db = NexusClientDatabase.open(this)
        workspaceStore = WorkspaceStore(filesDir, db)
        hostStore = AndroidHostConfigStore(File(filesDir, "host.json"), db)
        telemetryStore = TelemetryStore(db)
        notifications = VpnNotificationController(this)
        lifecycleExecutor = Executors.newSingleThreadExecutor { r ->
            Thread(r, "nexus-vpn-lifecycle").apply { isDaemon = true }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = when (intent?.action) {
        ACTION_START -> {
            launchForegroundWithHost(resolveLaunchRequest(intent), stopBeforeStart = false, silentMissing = false)
            START_STICKY
        }
        ACTION_STOP -> {
            submitLifecycle { stopTunnelLocked(stopSelfAfter = true, preserveError = false) }
            START_NOT_STICKY
        }
        ACTION_RESTART -> {
            launchForegroundWithHost(resolveLaunchRequest(intent), stopBeforeStart = true, silentMissing = false)
            START_STICKY
        }
        else -> {
            launchForegroundWithHost(resolveLaunchRequest(null), stopBeforeStart = false, silentMissing = true)
            START_STICKY
        }
    }

    private fun launchForegroundWithHost(req: LaunchRequest, stopBeforeStart: Boolean, silentMissing: Boolean) {
        val initialMode = lastRunMode
        notifications.promoteForeground(runMode = initialMode, profileName = activeProfileLabel)
        submitLifecycle {
            if (silentMissing && !req.configTarget.exists()) {
                runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
                stopSelf()
                return@submitLifecycle
            }
            if (!silentMissing && !validateLaunchTarget(req)) return@submitLifecycle
            val host = hostStore.load(paths)
            lastRunMode = host.android.runMode
            activeProfileLabel = readActiveProfileName()
            notifications.promoteForeground(runMode = host.android.runMode, profileName = activeProfileLabel)
            if (stopBeforeStart) stopTunnelLocked(stopSelfAfter = false, preserveError = false)
            startTunnelLocked(req, host)
        }
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        submitLifecycle { runCatching { db.shrinkMemory() } }
    }

    override fun onRevoke() {
        submitLifecycle { stopTunnelLocked(stopSelfAfter = true) }
        super.onRevoke()
    }

    override fun onDestroy() {
        try {
            lifecycleExecutor.submit { stopTunnelLocked(stopSelfAfter = false) }
                .get(DESTROY_WAIT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        } catch (_: TimeoutException) {
        } catch (_: ExecutionException) {
        } catch (_: RejectedExecutionException) {
        } finally {
            lifecycleExecutor.shutdown()
        }
        super.onDestroy()
    }

    private fun resolveLaunchRequest(intent: Intent?): LaunchRequest {
        val defaultTarget = paths.composedConfigFile
        val cfgPath = intent?.getStringExtra(EXTRA_CONFIG_PATH) ?: defaultTarget.absolutePath
        val isDir = intent?.getBooleanExtra(EXTRA_CONFIG_IS_DIR, false) ?: false
        val ovPath = intent?.getStringExtra(EXTRA_HOST_OVERRIDE_PATH)?.takeIf { it.isNotBlank() }
        val fakeIpv6 = intent?.getStringExtra(EXTRA_FAKE_IPV6_POOL).orEmpty()
        return LaunchRequest(
            configTarget = File(cfgPath),
            isConfigDir = isDir,
            hostOverrideFile = ovPath?.let { File(it) },
            fakeIpv6Pool = fakeIpv6,
        )
    }

    private fun validateLaunchTarget(req: LaunchRequest): Boolean {
        val ok = if (req.isConfigDir) req.configTarget.isDirectory else req.configTarget.isFile
        if (ok) return true
        appendLog("[error] vpn: runtime config is not ready")
        _lastError.value = "运行时配置尚未就绪，请在应用内启动连接"
        _tunnelState.value = VpnTunnelState.ERROR
        requestTileSync()
        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
        stopSelf()
        return false
    }

    private fun submitLifecycle(task: () -> Unit) {
        runCatching { lifecycleExecutor.execute(task) }
            .onFailure { err -> if (err !is RejectedExecutionException) throw err }
    }

    private fun readActiveProfileName(): String = runCatching {
        val activeId = telemetryStore.load().activeProfileId
        val summaries = workspaceStore.listProfileSummaries()
        val matched = summaries.firstOrNull { it.id == activeId } ?: summaries.firstOrNull()
        matched?.name?.ifBlank { matched.id } ?: activeId
    }.getOrDefault("")

    private fun writeSessionBearerToken(): String {
        val bytes = ByteArray(24)
        SecureRandom().nextBytes(bytes)
        val token = bytes.joinToString("") { "%02x".format(it) }
        SecretFileIO.atomicWriteSecret0600(paths.controlTokenFile, "$token\n")
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
            val httpUrl = NexusControlClient.httpUrlFromListen(hostConfig.common.controlHttpListen)
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
                if (host.allowBypass) builder.allowBypass()
                if (host.enableLocalProxy && host.appendHttpProxy && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    AndroidHostConfig.parseHostPort(host.localListen)?.let { (h, p) ->
                        runCatching { builder.setHttpProxy(ProxyInfo.buildDirectProxy(h, p)) }
                    }
                }
                val effectiveFakeIpv6 = req.fakeIpv6Pool.ifBlank {
                    runCatching {
                        val ws = workspaceStore.loadOrInit()
                        if (AndroidHostConfig.needsFakeIpv6Route(ws, host)) ws.dns.simple.fakeIpV6Pool else ""
                    }.getOrDefault("")
                }
                configureRoutes(builder, host, effectiveFakeIpv6)

                val plan = AndroidHostConfig.computePerAppPlan(packageName, host)
                for (pkg in plan.allowedPackages) runCatching { builder.addAllowedApplication(pkg) }
                for (pkg in plan.disallowedPackages) runCatching { builder.addDisallowedApplication(pkg) }

                val tun = builder.establish() ?: error("系统未授予 VPN 接口权限")
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
            if (!started) error("内核引擎启动失败")

            val screen = ScreenStateMonitor(this) { interactive, idle ->
                _dozeMode.value = idle
                val paused = ScreenStateMonitor.shouldPausePolling(
                    interactive = interactive,
                    deviceIdle = idle,
                    screenOffPauseStats = host.screenOffPauseStats,
                    dozePauseEnabled = host.dozePauseEnabled,
                )
                _powerSaveMode.value = paused
                if (paused) {
                    submitLifecycle { runCatching { db.shrinkMemory() } }
                    notifications.updateIfDue(host.runMode, activeProfileLabel, -1L, -1L, powerSave = true, force = true)
                }
                requestTileSync()
            }.also { it.start() }
            screenMonitor = screen
            _dozeMode.value = screen.isDeviceIdle
            val initialPaused = ScreenStateMonitor.shouldPausePolling(
                interactive = screen.isInteractive,
                deviceIdle = screen.isDeviceIdle,
                screenOffPauseStats = host.screenOffPauseStats,
                dozePauseEnabled = host.dozePauseEnabled,
            )
            _powerSaveMode.value = initialPaused
            _startedAtMs.value = System.currentTimeMillis()
            _runningState.value = true
            _tunnelState.value = VpnTunnelState.RUNNING
            notifications.updateIfDue(host.runMode, activeProfileLabel, -1L, -1L, powerSave = initialPaused, force = true)
            launchNotificationSpeedLoop(scope, controlClient, host.runMode)
            requestTileSync()
        } catch (t: Throwable) {
            val msg = t.message ?: t.javaClass.simpleName
            appendLog("[error] vpn: startup failed: $msg")
            _lastError.value = msg
            _tunnelState.value = VpnTunnelState.ERROR
            stopTunnelLocked(stopSelfAfter = true, preserveError = true)
        }
    }

    private fun launchNotificationSpeedLoop(scope: CoroutineScope, controlClient: NexusControlClient, runMode: AndroidRunMode) {
        scope.launch {
            var prevDown = -1L; var prevUp = -1L; var prevTs = 0L; var prevGen = -1L
            var lastProfileSyncMs = System.currentTimeMillis()
            while (isActive && _runningState.value) {
                delay(2_500L)
                if (_powerSaveMode.value) { prevDown = -1L; prevUp = -1L; continue }
                val metrics = runCatching { controlClient.fetchMetrics() }.getOrNull() ?: continue
                val now = System.currentTimeMillis()
                var profileChanged = false
                if (metrics.controlGeneration != prevGen || now - lastProfileSyncMs >= 10_000L) {
                    prevGen = metrics.controlGeneration
                    lastProfileSyncMs = now
                    val latest = readActiveProfileName()
                    if (latest != activeProfileLabel) { activeProfileLabel = latest; profileChanged = true }
                }
                if (prevDown >= 0L && prevTs > 0L) {
                    val elapsedMs = (now - prevTs).coerceAtLeast(500L)
                    val downRate = ((metrics.downloadBytes - prevDown).coerceAtLeast(0L) * 1000L) / elapsedMs
                    val upRate = ((metrics.uploadBytes - prevUp).coerceAtLeast(0L) * 1000L) / elapsedMs
                    notifications.updateIfDue(runMode, activeProfileLabel, downRate, upRate, powerSave = false, force = profileChanged)
                } else if (profileChanged) {
                    notifications.updateIfDue(runMode, activeProfileLabel, -1L, -1L, powerSave = false, force = true)
                }
                prevDown = metrics.downloadBytes; prevUp = metrics.uploadBytes; prevTs = now
            }
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
        runCatching { db.shrinkMemory() }
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

    companion object {
        const val ACTION_START = "org.nexus.android.action.START_VPN"
        const val ACTION_STOP = "org.nexus.android.action.STOP_VPN"
        const val ACTION_RESTART = "org.nexus.android.action.RESTART_VPN"
        const val EXTRA_CONFIG_PATH = "org.nexus.android.extra.CONFIG_PATH"
        const val EXTRA_CONFIG_IS_DIR = "org.nexus.android.extra.CONFIG_IS_DIR"
        const val EXTRA_HOST_OVERRIDE_PATH = "org.nexus.android.extra.HOST_OVERRIDE_PATH"
        const val EXTRA_FAKE_IPV6_POOL = "org.nexus.android.extra.FAKE_IPV6_POOL"

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
