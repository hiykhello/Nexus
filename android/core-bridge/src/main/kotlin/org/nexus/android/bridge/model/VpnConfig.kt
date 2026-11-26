package org.nexus.android.bridge.model

import java.io.File

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
    val composeWorkspaceFile: File = File(rootDir, "compose-workspace.json")
    val composeHostFile: File = File(rootDir, "compose-host.json")
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

/**
 * Pure host:port / IPv4 / IPv6 target endpoint parser used by connection inspection and quick rules.
 */
object EndpointParser {
    fun stripPortAndBrackets(raw: String): String {
        val t = raw.trim()
        if (t.startsWith("[")) {
            val close = t.indexOf(']')
            if (close > 1) return t.substring(1, close)
        }
        val firstColon = t.indexOf(':')
        val lastColon = t.lastIndexOf(':')
        return if (firstColon > 0 && firstColon == lastColon && t.substring(lastColon + 1).all { it.isDigit() }) {
            t.substring(0, lastColon)
        } else {
            t
        }
    }

    fun isIpv4Literal(host: String): Boolean {
        val parts = host.split('.')
        if (parts.size != 4) return false
        return parts.all { p -> p.isNotEmpty() && p.all { it.isDigit() } && (p.toIntOrNull() in 0..255) }
    }

    fun isIpv6Literal(host: String): Boolean =
        host.contains(':') && host.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' }
}
