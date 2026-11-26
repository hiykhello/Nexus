package org.nexus.android.bridge.workspace

import org.json.JSONObject
import org.nexus.android.bridge.model.RuntimeSocketPaths
import org.nexus.android.bridge.profile.SecretFileIO
import java.io.File

enum class AndroidRunMode(val wire: String) {
    VPN("vpn"),
    PROXY_ONLY("proxy_only");

    companion object {
        fun fromWire(raw: String?): AndroidRunMode =
            entries.firstOrNull { it.wire == raw?.trim()?.lowercase() } ?: VPN
    }
}

enum class AndroidPerAppMode(val wire: String) {
    OFF("off"),
    EXCLUDE("exclude"),
    INCLUDE("include");

    companion object {
        fun fromWire(raw: String?): AndroidPerAppMode =
            entries.firstOrNull { it.wire == raw?.trim()?.lowercase() } ?: EXCLUDE
    }
}

data class HostCommonConfig(
    val schemaVersion: Int = SCHEMA_VERSION,
    val platform: String = "android",
    val logLevel: String = "info",
    val logFile: String = "",
    val workers: Int = 1,
    val workersSpec: String = "",
    val workersMax: Int = 0,
    val stateDir: String = "",
    val cacheDir: String = "",
    val controlSocket: String = "",
    val controlHttpListen: String = "127.0.0.1:9090",
    val controlBearerFile: String = "",
    val caFile: String = "",
    val includeSiblingNodesInSelector: Boolean = true,
    val maxSelectorMembers: Int = 128,
) {
    companion object {
        const val SCHEMA_VERSION = 1

        fun isValidWorkersSpec(spec: String): Boolean {
            if (spec.isEmpty() || spec == "auto" || spec == "max") return true
            val suffix = when {
                spec.startsWith("max-") -> spec.removePrefix("max-")
                spec.startsWith("auto-") -> spec.removePrefix("auto-")
                else -> return false
            }
            if (suffix.isEmpty() || !suffix.all { it in '0'..'9' }) return false
            val parsed = suffix.toLongOrNull() ?: return false
            return parsed in 0L..Int.MAX_VALUE.toLong()
        }
    }
}

data class AndroidHostSection(
    val runMode: AndroidRunMode = AndroidRunMode.VPN,
    val enableLocalProxy: Boolean = true,
    val localListen: String = "127.0.0.1:10808",
    val dynamicLocalPort: Boolean = false,
    val tunMtu: Int = 1400,
    val tunFdFromEnv: Boolean = true,
    val protectSocketPath: String = "",
    val dnsBridgeSocketPath: String = "",
    val dnsListen: String = "",
    // Android OS keys ignored by Core composer
    val perAppMode: AndroidPerAppMode = AndroidPerAppMode.EXCLUDE,
    val perAppPackages: List<String> = emptyList(),
    val excludeSelfFromVpn: Boolean = false,
    val allowBypass: Boolean = false,
    val bypassLan: Boolean = true,
    val appendHttpProxy: Boolean = false,
    val enableIpv6: Boolean = true,
    val autoStartOnBoot: Boolean = false,
    val dozePauseEnabled: Boolean = true,
    val oomSoftLimitMb: Int = 50,
    val screenOffPauseStats: Boolean = true,
    val dynamicColor: Boolean = false,
    // E2EE WebDAV Sync settings (strictly local Layer 3 0600 host.json; NEVER in workspace.json)
    val webdavUrl: String = "",
    val webdavUsername: String = "",
    val webdavPassword: String = "",
    val syncPassphrase: String = "",
    val syncDeviceLabel: String = "Android",
    val lastSyncedEtag: String = "",
    val lastSyncedRevision: Long = 0L,
)

data class AndroidHostConfig(
    val common: HostCommonConfig = HostCommonConfig(),
    val android: AndroidHostSection = AndroidHostSection(),
) {
    fun boundToPaths(paths: RuntimeSocketPaths): AndroidHostConfig = copy(
        common = common.copy(
            schemaVersion = HostCommonConfig.SCHEMA_VERSION,
            platform = "android",
            stateDir = paths.stateDir.absolutePath,
            cacheDir = paths.cacheDir.absolutePath,
            controlSocket = paths.controlSocket.absolutePath,
            controlBearerFile = paths.controlTokenFile.absolutePath,
        ),
        android = android.copy(
            tunFdFromEnv = true,
            protectSocketPath = paths.protectSocket.absolutePath,
            dnsBridgeSocketPath = paths.dnsBridgeSocket.absolutePath,
        ),
    )

    fun toJson(indentSpaces: Int = 2, includeSecrets: Boolean = false): String {
        val root = JSONObject().apply {
            put("schema_version", HostCommonConfig.SCHEMA_VERSION)
            put("platform", common.platform.ifBlank { "android" })
            put("log_level", common.logLevel)
            put("log_file", common.logFile)
            put("workers", common.workers.coerceAtLeast(1))
            val cleanSpec = common.workersSpec.trim()
            if (cleanSpec.isNotEmpty() && HostCommonConfig.isValidWorkersSpec(cleanSpec)) put("workers_spec", cleanSpec)
            if (common.workersMax > 0) put("workers_max", common.workersMax)
            put("state_dir", common.stateDir)
            put("cache_dir", common.cacheDir)
            put("control_socket", common.controlSocket)
            put("control_http_listen", common.controlHttpListen)
            put("control_bearer_file", common.controlBearerFile)
            put("ca_file", common.caFile)
            put("include_sibling_nodes_in_selector", common.includeSiblingNodesInSelector)
            put("max_selector_members", common.maxSelectorMembers)
            put("android", JSONObject().apply {
                put("run_mode", android.runMode.wire)
                put("enable_local_proxy", android.enableLocalProxy)
                put("local_listen", android.localListen)
                put("dynamic_local_port", android.dynamicLocalPort)
                put("tun_mtu", android.tunMtu.coerceIn(1280, 9000))
                put("tun_fd_from_env", android.tunFdFromEnv)
                put("protect_socket_path", android.protectSocketPath)
                put("dns_bridge_socket_path", android.dnsBridgeSocketPath)
                put("dns_listen", android.dnsListen)
                put("per_app_mode", android.perAppMode.wire)
                put("per_app_packages", WorkspaceJsonCodec.toJsonStringArray(android.perAppPackages.distinct().sorted()))
                put("exclude_self_from_vpn", android.excludeSelfFromVpn)
                put("allow_bypass", android.allowBypass)
                put("bypass_lan", android.bypassLan)
                put("append_http_proxy", android.appendHttpProxy)
                put("enable_ipv6", android.enableIpv6)
                put("auto_start_on_boot", android.autoStartOnBoot)
                put("doze_pause_enabled", android.dozePauseEnabled)
                put("oom_soft_limit_mb", android.oomSoftLimitMb)
                put("screen_off_pause_stats", android.screenOffPauseStats)
                put("dynamic_color", android.dynamicColor)
                put("webdav_url", android.webdavUrl)
                put("webdav_username", android.webdavUsername)
                if (includeSecrets) {
                    put("webdav_password", android.webdavPassword)
                    put("sync_passphrase", android.syncPassphrase)
                }
                put("sync_device_label", android.syncDeviceLabel)
                put("last_synced_etag", android.lastSyncedEtag)
                put("last_synced_revision", android.lastSyncedRevision)
            })
        }
        return if (indentSpaces > 0) root.toString(indentSpaces) + "\n" else root.toString()
    }

    companion object {
        val DEFAULT_CAPTIVE_PORTAL_PACKAGES: List<String> = listOf(
            "com.android.captiveportallogin",
            "com.google.android.captiveportallogin",
        )

        fun fromJson(rawJson: String): AndroidHostConfig {
            val root = JSONObject(rawJson)
            val a = root.optJSONObject("android") ?: JSONObject()
            return AndroidHostConfig(
                common = HostCommonConfig(
                    schemaVersion = root.optInt("schema_version", HostCommonConfig.SCHEMA_VERSION),
                    platform = root.optString("platform", "android").ifBlank { "android" },
                    logLevel = root.optString("log_level", "info"),
                    logFile = root.optString("log_file", ""),
                    workers = root.optInt("workers", 1).coerceAtLeast(1),
                    workersSpec = root.optString("workers_spec", "").trim().takeIf { HostCommonConfig.isValidWorkersSpec(it) }.orEmpty(),
                    workersMax = root.optInt("workers_max", 0).coerceAtLeast(0),
                    stateDir = root.optString("state_dir", ""),
                    cacheDir = root.optString("cache_dir", ""),
                    controlSocket = root.optString("control_socket", ""),
                    controlHttpListen = root.optString("control_http_listen", "127.0.0.1:9090"),
                    controlBearerFile = root.optString("control_bearer_file", ""),
                    caFile = root.optString("ca_file", ""),
                    includeSiblingNodesInSelector = root.optBoolean("include_sibling_nodes_in_selector", true),
                    maxSelectorMembers = root.optInt("max_selector_members", 128).coerceIn(1, 1024),
                ),
                android = AndroidHostSection(
                    runMode = AndroidRunMode.fromWire(a.optString("run_mode", AndroidRunMode.VPN.wire)),
                    enableLocalProxy = a.optBoolean("enable_local_proxy", true),
                    localListen = a.optString("local_listen", "127.0.0.1:10808"),
                    dynamicLocalPort = a.optBoolean("dynamic_local_port", false),
                    tunMtu = a.optInt("tun_mtu", 1400).coerceIn(1280, 9000),
                    tunFdFromEnv = a.optBoolean("tun_fd_from_env", true),
                    protectSocketPath = a.optString("protect_socket_path", ""),
                    dnsBridgeSocketPath = a.optString("dns_bridge_socket_path", ""),
                    dnsListen = a.optString("dns_listen", ""),
                    perAppMode = AndroidPerAppMode.fromWire(a.optString("per_app_mode", AndroidPerAppMode.EXCLUDE.wire)),
                    perAppPackages = WorkspaceJsonCodec.readStringList(a.optJSONArray("per_app_packages")),
                    excludeSelfFromVpn = a.optBoolean("exclude_self_from_vpn", false),
                    allowBypass = a.optBoolean("allow_bypass", false),
                    bypassLan = a.optBoolean("bypass_lan", true),
                    appendHttpProxy = a.optBoolean("append_http_proxy", false),
                    enableIpv6 = a.optBoolean("enable_ipv6", true),
                    autoStartOnBoot = a.optBoolean("auto_start_on_boot", false),
                    dozePauseEnabled = a.optBoolean("doze_pause_enabled", true),
                    oomSoftLimitMb = a.optInt("oom_soft_limit_mb", 50).coerceIn(16, 512),
                    screenOffPauseStats = a.optBoolean("screen_off_pause_stats", true),
                    dynamicColor = a.optBoolean("dynamic_color", false),
                    webdavUrl = a.optString("webdav_url", ""),
                    webdavUsername = a.optString("webdav_username", ""),
                    webdavPassword = a.optString("webdav_password", ""),
                    syncPassphrase = a.optString("sync_passphrase", ""),
                    syncDeviceLabel = a.optString("sync_device_label", "Android").ifBlank { "Android" },
                    lastSyncedEtag = a.optString("last_synced_etag", ""),
                    lastSyncedRevision = a.optLong("last_synced_revision", 0L).coerceAtLeast(0L),
                ),
            )
        }

        /**
         * Computes Android VpnService per-app allow/disallow sets honoring Self-Inside-VPN default:
         * - `excludeSelfFromVpn == false` (default): self stays INSIDE VPN (outbound sockets rely on Protect-FD).
         * - `OFF`: captive portal apps disallowed (+ self only if `excludeSelfFromVpn == true`).
         * - `EXCLUDE`: captive portal apps + `perAppPackages` disallowed (+ self only if `excludeSelfFromVpn == true`).
         * - `INCLUDE`: `perAppPackages` allowed (+ self unless `excludeSelfFromVpn == true`); disallowed is empty.
         */
        fun computePerAppPlan(
            selfPackage: String,
            host: AndroidHostSection,
            captivePortalPackages: List<String> = DEFAULT_CAPTIVE_PORTAL_PACKAGES,
        ): VpnPerAppPlan {
            val userPkgs = host.perAppPackages.map { it.trim() }.filter { it.isNotEmpty() }
            return when (host.perAppMode) {
                AndroidPerAppMode.OFF -> {
                    val disallowed = linkedSetOf<String>()
                    disallowed.addAll(captivePortalPackages)
                    if (host.excludeSelfFromVpn) disallowed.add(selfPackage) else disallowed.remove(selfPackage)
                    VpnPerAppPlan(allowedPackages = emptyList(), disallowedPackages = disallowed.toList())
                }
                AndroidPerAppMode.EXCLUDE -> {
                    val disallowed = linkedSetOf<String>()
                    disallowed.addAll(captivePortalPackages)
                    disallowed.addAll(userPkgs)
                    if (host.excludeSelfFromVpn) disallowed.add(selfPackage) else disallowed.remove(selfPackage)
                    VpnPerAppPlan(allowedPackages = emptyList(), disallowedPackages = disallowed.toList())
                }
                AndroidPerAppMode.INCLUDE -> {
                    val allowed = linkedSetOf<String>()
                    allowed.addAll(userPkgs)
                    if (!host.excludeSelfFromVpn) allowed.add(selfPackage) else allowed.remove(selfPackage)
                    if (allowed.isEmpty()) {
                        val fallbackDisallowed = linkedSetOf<String>()
                        fallbackDisallowed.addAll(captivePortalPackages)
                        if (host.excludeSelfFromVpn) fallbackDisallowed.add(selfPackage)
                        VpnPerAppPlan(allowedPackages = emptyList(), disallowedPackages = fallbackDisallowed.toList())
                    } else {
                        VpnPerAppPlan(allowedPackages = allowed.toList(), disallowedPackages = emptyList())
                    }
                }
            }
        }

        fun needsFakeIpv6Route(workspace: WorkspaceDocument, host: AndroidHostSection): Boolean =
            host.enableIpv6 &&
                workspace.dns.mode == "simple" &&
                workspace.dns.simple.fakeIpEnabled &&
                workspace.dns.simple.fakeIpV6Pool.isNotBlank()

        fun parseHostPort(listen: String): Pair<String, Int>? {
            val trimmed = listen.trim()
            if (trimmed.isEmpty()) return null
            val colon = trimmed.lastIndexOf(':')
            if (colon <= 0 || colon >= trimmed.length - 1) return null
            val host = trimmed.substring(0, colon).removePrefix("[").removeSuffix("]")
            val port = trimmed.substring(colon + 1).toIntOrNull() ?: return null
            return if (host.isNotEmpty() && port in 1..65535) host to port else null
        }
    }
}

data class VpnPerAppPlan(
    val allowedPackages: List<String>,
    val disallowedPackages: List<String>,
)

class AndroidHostConfigStore(
    val file: File,
    val db: NexusClientDatabase = NexusClientDatabase.inMemory(),
    val secretFile: File = File(file.parentFile ?: File("."), ".sync-secrets.json"),
) {
    fun load(paths: RuntimeSocketPaths? = null): AndroidHostConfig {
        var rawKv = db.getHostKv(NexusClientDatabase.KV_ANDROID_HOST_CONFIG)
        if (rawKv == null && file.isFile) {
            val legacy = runCatching { AndroidHostConfig.fromJson(file.readText(Charsets.UTF_8)) }.getOrNull()
            if (legacy != null) {
                val inserted = db.setHostKvIfAbsent(
                    NexusClientDatabase.KV_ANDROID_HOST_CONFIG,
                    legacy.toJson(indentSpaces = 0, includeSecrets = false),
                )
                if (inserted) {
                    val hasSecrets = legacy.android.webdavPassword.isNotEmpty() || legacy.android.syncPassphrase.isNotEmpty()
                    if (hasSecrets && !secretFile.isFile) {
                        writeSyncSecrets(legacy.android.webdavPassword, legacy.android.syncPassphrase)
                    }
                    if (hasSecrets) {
                        runCatching {
                            SecretFileIO.atomicWriteSecret0600(file, legacy.toJson(indentSpaces = 2, includeSecrets = false))
                        }
                    }
                }
                rawKv = db.getHostKv(NexusClientDatabase.KV_ANDROID_HOST_CONFIG)
            }
        }
        val base = rawKv?.let { runCatching { AndroidHostConfig.fromJson(it) }.getOrNull() } ?: AndroidHostConfig()
        val (davPw, syncPass) = readSyncSecrets()
        val merged = base.copy(
            android = base.android.copy(
                webdavPassword = davPw,
                syncPassphrase = syncPass,
            ),
        )
        return if (paths != null) merged.boundToPaths(paths) else merged
    }

    fun save(config: AndroidHostConfig): AndroidHostConfig {
        db.setHostKv(NexusClientDatabase.KV_ANDROID_HOST_CONFIG, config.toJson(indentSpaces = 0, includeSecrets = false))
        writeSyncSecrets(config.android.webdavPassword, config.android.syncPassphrase)
        return config
    }

    fun writeCoreHostFile(targetFile: File, paths: RuntimeSocketPaths): File {
        val cfg = load(paths)
        SecretFileIO.atomicWriteSecret0600(targetFile, cfg.toJson(indentSpaces = 2, includeSecrets = false))
        return targetFile
    }

    private fun readSyncSecrets(): Pair<String, String> {
        if (!secretFile.isFile) return "" to ""
        return runCatching {
            val obj = JSONObject(secretFile.readText(Charsets.UTF_8))
            obj.optString("webdav_password", "") to obj.optString("sync_passphrase", "")
        }.getOrDefault("" to "")
    }

    private fun writeSyncSecrets(webdavPassword: String, syncPassphrase: String) {
        if (webdavPassword.isEmpty() && syncPassphrase.isEmpty()) {
            WorkspaceSyncBridge.wipeAndDelete(secretFile)
            return
        }
        val payload = JSONObject().apply {
            put("webdav_password", webdavPassword)
            put("sync_passphrase", syncPassphrase)
        }.toString(2) + "\n"
        SecretFileIO.atomicWriteSecret0600(secretFile, payload)
    }
}
