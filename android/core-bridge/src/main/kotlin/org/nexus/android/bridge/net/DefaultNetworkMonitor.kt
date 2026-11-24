package org.nexus.android.bridge.net

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.Looper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.nexus.android.bridge.model.NetworkSnapshot
import org.nexus.android.bridge.model.PrivateDnsWarning
import java.util.concurrent.atomic.AtomicBoolean

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
    private val lock = Any()
    private val registered = AtomicBoolean(false)

    @Volatile
    private var activeNetwork: Network? = null

    @Volatile
    private var lastSnapshot: NetworkSnapshot? = null

    private var debounceJob: Job? = null

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
            synchronized(lock) {
                if (activeNetwork == network) {
                    activeNetwork = null
                    scheduleLossLocked()
                }
            }
        }
    }

    fun start() {
        synchronized(lock) {
            if (!registered.compareAndSet(false, true)) return
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            val handler = Handler(Looper.getMainLooper())
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    connectivityManager.registerBestMatchingNetworkCallback(request, callback, handler)
                } else {
                    connectivityManager.registerNetworkCallback(request, callback, handler)
                }
            } catch (t: Throwable) {
                registered.set(false)
                throw t
            }
        }
    }

    fun stop() {
        synchronized(lock) {
            if (!registered.compareAndSet(true, false)) return
            debounceJob?.cancel()
            debounceJob = null
            runCatching { connectivityManager.unregisterNetworkCallback(callback) }
            activeNetwork = null
            lastSnapshot = null
            _snapshot.value = null
        }
    }

    private fun scheduleRefresh(
        network: Network,
        knownCaps: NetworkCapabilities? = null,
        linkProperties: LinkProperties? = null,
    ) {
        if (!registered.get()) return
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

        synchronized(lock) {
            if (!registered.get()) return
            val sameNetwork = activeNetwork == network
            activeNetwork = network
            if (sameNetwork && next.equivalentRoutingKey(lastSnapshot)) {
                return
            }

            debounceJob?.cancel()
            var job: Job? = null
            job = scope.launch {
                delay(DEBOUNCE_MS)
                val shouldEmit = synchronized(lock) {
                    if (!registered.get() || debounceJob !== job) {
                        false
                    } else {
                        lastSnapshot = next
                        _snapshot.value = next
                        true
                    }
                }
                if (shouldEmit) {
                    onUnderlyingNetworkChanged(network, next)
                }
            }
            debounceJob = job
        }
    }

    private fun scheduleLossLocked() {
        if (!registered.get()) return
        debounceJob?.cancel()
        var job: Job? = null
        job = scope.launch {
            delay(DEBOUNCE_MS)
            val shouldEmit = synchronized(lock) {
                if (!registered.get() || debounceJob !== job || activeNetwork != null) {
                    false
                } else {
                    lastSnapshot = null
                    _snapshot.value = null
                    true
                }
            }
            if (shouldEmit) {
                onUnderlyingNetworkChanged(null, null)
            }
        }
        debounceJob = job
    }

    companion object {
        private const val DEBOUNCE_MS = 180L
    }
}
