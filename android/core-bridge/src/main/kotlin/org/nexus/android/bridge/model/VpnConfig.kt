package org.nexus.android.bridge.model

import java.io.File

enum class Ipv6Mode {
    DUAL_STACK,
    BLOCK_LEAK,
    BYPASS,
}

enum class PerAppMode {
    ALL_APPS,
    ALLOW_LIST,
    DISALLOW_LIST,
}

enum class MeteredMode {
    FOLLOW_UNDERLYING,
    FORCE_UNMETERED,
    FORCE_METERED,
}

data class VpnProfileConfig(
    val sessionName: String = "Nexus",
    val inet4Address: String = "172.19.0.1/30",
    val inet6Address: String = "fdfe:dcba:9876::1/126",
    val dnsServers: List<String> = listOf("172.19.0.2", "fdfe:dcba:9876::2"),
    val mtu: Int = 9000,
    val routeExcludePrivate: Boolean = true,
    val routeExcludeCidrs: List<String> = emptyList(),
    val ipv6Mode: Ipv6Mode = Ipv6Mode.DUAL_STACK,
    val perAppMode: PerAppMode = PerAppMode.DISALLOW_LIST,
    val packages: Set<String> = emptySet(),
    val httpProxyPort: Int? = null,
    val httpProxyBypassDomains: List<String> = listOf("localhost", "127.0.0.1", "::1"),
    val meteredMode: MeteredMode = MeteredMode.FOLLOW_UNDERLYING,
    val memoryBudgetMiB: Int = 48,
    val userKdlConfig: String = "",
)

/**
 * Runtime paths inside context.noBackupFilesDir.
 * Short filenames keep sockaddr_un.sun_path comfortably below the 108-byte Linux limit.
 */
data class RuntimeSocketPaths(
    val rootDir: File,
) {
    val protectSocket: File = File(rootDir, "p.sock")
    val controlSocket: File = File(rootDir, "c.sock")
    val dnsBridgeSocket: File = File(rootDir, "d.sock")
    val tunFdSocket: File = File(rootDir, "t.sock")
    val controlTokenFile: File = File(rootDir, "control.token")
    val runtimeConfigFile: File = File(rootDir, "runtime.kdl")
    val composedConfigFile: File = File(rootDir, "composed.kdl")
    val telemetryFile: File = File(rootDir, "telemetry.json")
    val secretsDir: File = File(rootDir, "secrets")
    val stateDir: File = File(rootDir, "state")
    val cacheDir: File = File(rootDir, "cache")

    fun validatePaths() {
        listOf(protectSocket, controlSocket, dnsBridgeSocket, tunFdSocket).forEach { file ->
            val path = file.absolutePath
            require(path.startsWith("/")) { "UDS path must be absolute: $path" }
            require(path.toByteArray(Charsets.UTF_8).size < MAX_UNIX_PATH_BYTES) {
                "UDS path exceeds Linux sun_path limit ($MAX_UNIX_PATH_BYTES): $path"
            }
        }
    }

    companion object {
        const val MAX_UNIX_PATH_BYTES = 108
    }
}

enum class VpnState {
    STOPPED,
    STARTING,
    RUNNING,
    STOPPING,
    ERROR,
}

data class PrivateDnsWarning(
    val active: Boolean,
    val strictHostname: String?,
) {
    val isStrictMode: Boolean get() = active && !strictHostname.isNullOrBlank()
}

data class NetworkSnapshot(
    val interfaceName: String?,
    val mtu: Int,
    val dnsServers: List<String>,
    val searchDomains: List<String>,
    val metered: Boolean,
    val privateDns: PrivateDnsWarning,
) {
    fun equivalentRoutingKey(other: NetworkSnapshot?): Boolean {
        if (other == null) return false
        return interfaceName == other.interfaceName &&
            dnsServers == other.dnsServers &&
            searchDomains == other.searchDomains &&
            metered == other.metered &&
            privateDns == other.privateDns
    }
}
