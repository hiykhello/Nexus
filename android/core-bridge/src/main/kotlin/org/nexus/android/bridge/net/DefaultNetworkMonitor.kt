package org.nexus.android.bridge.net

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.nexus.android.bridge.model.NetworkSnapshot
import org.nexus.android.bridge.model.PrivateDnsWarning

/**
 * Monitors the active non-VPN physical default network (Wi-Fi / Cellular / Ethernet)
 * and publishes debounced, deduplicated NetworkSnapshots + underlying Network handles
 * without requiring root or location permission.
 */
class DefaultNetworkMonitor(
    context: Context,
    private val scope: CoroutineScope,
    private val onUnderlyingNetworkChanged: (Network?, NetworkSnapshot?) -> Unit,
) {
    private val connectivityManager =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    @Volatile
    private var activeNetwork: Network? = null

    @Volatile
    private var lastSnapshot: NetworkSnapshot? = null

    private var debounceJob: Job? = null
    private var registered = false

    private val _snapshot = MutableStateFlow<NetworkSnapshot?>(null)
    val snapshot: StateFlow<NetworkSnapshot?> = _snapshot.asStateFlow()

    val currentPhysicalNetwork: Network? get() = activeNetwork

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            scheduleRefresh(network)
        }

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return
            scheduleRefresh(network, caps)
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            scheduleRefresh(network, linkProperties = linkProperties)
        }

        override fun onLost(network: Network) {
            if (activeNetwork == network) {
                activeNetwork = null
                scheduleLoss()
            }
        }
    }

    fun start() {
        if (registered) return
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            connectivityManager.registerBestMatchingNetworkCallback(request, callback, null)
        } else {
            connectivityManager.registerNetworkCallback(request, callback)
        }
        registered = true
    }

    fun stop() {
        if (!registered) return
        debounceJob?.cancel()
        runCatching { connectivityManager.unregisterNetworkCallback(callback) }
        registered = false
        activeNetwork = null
        lastSnapshot = null
        _snapshot.value = null
    }

    private fun scheduleRefresh(
        network: Network,
        knownCaps: NetworkCapabilities? = null,
        linkProperties: LinkProperties? = null,
    ) {
        val caps = knownCaps ?: connectivityManager.getNetworkCapabilities(network) ?: return
        if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) ||
            !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        ) {
            return
        }
        val lp = linkProperties ?: connectivityManager.getLinkProperties(network) ?: return
        val next = NetworkSnapshot(
            interfaceName = lp.interfaceName,
            mtu = lp.mtu,
            dnsServers = lp.dnsServers.mapNotNull { it.hostAddress },
            searchDomains = lp.domains
                ?.split(',', ' ')
                ?.map { it.trim() }
                ?.filter { it.isNotEmpty() }
                ?: emptyList(),
            metered = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
            privateDns = PrivateDnsWarning(
                active = lp.isPrivateDnsActive,
                strictHostname = lp.privateDnsServerName,
            ),
        )

        val sameNetwork = activeNetwork == network
        activeNetwork = network
        if (sameNetwork && next.equivalentRoutingKey(lastSnapshot)) {
            return
        }

        debounceJob?.cancel()
        debounceJob = scope.launch {
            delay(DEBOUNCE_MS)
            lastSnapshot = next
            _snapshot.value = next
            onUnderlyingNetworkChanged(network, next)
        }
    }

    private fun scheduleLoss() {
        debounceJob?.cancel()
        debounceJob = scope.launch {
            delay(DEBOUNCE_MS)
            if (activeNetwork == null) {
                lastSnapshot = null
                _snapshot.value = null
                onUnderlyingNetworkChanged(null, null)
            }
        }
    }

    companion object {
        private const val DEBOUNCE_MS = 180L
    }
}
