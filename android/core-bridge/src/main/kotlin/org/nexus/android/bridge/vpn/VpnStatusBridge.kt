package org.nexus.android.bridge.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.nexus.android.bridge.model.NetworkSnapshot
import org.nexus.android.bridge.model.PrivateDnsWarning
import org.nexus.android.bridge.model.VpnState
import java.io.Closeable

data class VpnRuntimeStatus(
    val state: VpnState = VpnState.STOPPED,
    val interfaceName: String? = null,
    val mtu: Int = 0,
    val dnsServers: List<String> = emptyList(),
    val metered: Boolean = false,
    val privateDnsActive: Boolean = false,
    val privateDnsHostname: String? = null,
    val lastError: String? = null,
) {
    val privateDnsWarning: PrivateDnsWarning
        get() = PrivateDnsWarning(privateDnsActive, privateDnsHostname)
}

/**
 * Cross-process status publisher/subscriber between :bg (NexusVpnService) and main UI/TileService.
 * Uses package-scoped explicit broadcasts (not exported) plus a lightweight state file fallback
 * so UI & Quick Settings Tile never read stale in-process companion state across process boundaries.
 */
object VpnStatusContract {
    const val ACTION_STATUS = "org.nexus.android.internal.VPN_STATUS"
    const val ACTION_QUERY_STATUS = "org.nexus.android.internal.QUERY_STATUS"
    const val EXTRA_STATE = "state"
    const val EXTRA_IFACE = "iface"
    const val EXTRA_MTU = "mtu"
    const val EXTRA_DNS = "dns"
    const val EXTRA_METERED = "metered"
    const val EXTRA_PRIVATE_DNS_ACTIVE = "private_dns_active"
    const val EXTRA_PRIVATE_DNS_HOST = "private_dns_host"
    const val EXTRA_ERROR = "error"

    fun broadcast(
        context: Context,
        state: VpnState,
        snapshot: NetworkSnapshot?,
        lastError: String?,
    ) {
        val intent = Intent(ACTION_STATUS).apply {
            setPackage(context.packageName)
            putExtra(EXTRA_STATE, state.name)
            putExtra(EXTRA_IFACE, snapshot?.interfaceName)
            putExtra(EXTRA_MTU, snapshot?.mtu ?: 0)
            putStringArrayListExtra(EXTRA_DNS, ArrayList(snapshot?.dnsServers.orEmpty()))
            putExtra(EXTRA_METERED, snapshot?.metered ?: false)
            putExtra(EXTRA_PRIVATE_DNS_ACTIVE, snapshot?.privateDns?.active ?: false)
            putExtra(EXTRA_PRIVATE_DNS_HOST, snapshot?.privateDns?.strictHostname)
            putExtra(EXTRA_ERROR, lastError)
        }
        val permission = "${context.packageName}.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
        context.sendBroadcast(intent, permission)
    }

    fun fromIntent(intent: Intent): VpnRuntimeStatus {
        val parsedState = runCatching {
            VpnState.valueOf(intent.getStringExtra(EXTRA_STATE) ?: VpnState.STOPPED.name)
        }.getOrDefault(VpnState.STOPPED)
        return VpnRuntimeStatus(
            state = parsedState,
            interfaceName = intent.getStringExtra(EXTRA_IFACE),
            mtu = intent.getIntExtra(EXTRA_MTU, 0),
            dnsServers = intent.getStringArrayListExtra(EXTRA_DNS).orEmpty(),
            metered = intent.getBooleanExtra(EXTRA_METERED, false),
            privateDnsActive = intent.getBooleanExtra(EXTRA_PRIVATE_DNS_ACTIVE, false),
            privateDnsHostname = intent.getStringExtra(EXTRA_PRIVATE_DNS_HOST),
            lastError = intent.getStringExtra(EXTRA_ERROR),
        )
    }
}

class VpnStatusObserver(
    private val context: Context,
) : Closeable {
    private val _status = MutableStateFlow(VpnRuntimeStatus())
    val status: StateFlow<VpnRuntimeStatus> = _status.asStateFlow()
    private var registered = false

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context?, intent: Intent?) {
            if (intent?.action == VpnStatusContract.ACTION_STATUS) {
                _status.value = VpnStatusContract.fromIntent(intent)
            }
        }
    }

    fun start() {
        if (registered) return
        val filter = IntentFilter(VpnStatusContract.ACTION_STATUS)
        ContextCompat.registerReceiver(context, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
        registered = true
        // Ask :bg service to re-broadcast current snapshot if already running.
        context.startService(
            Intent(context, NexusVpnService::class.java).setAction(VpnStatusContract.ACTION_QUERY_STATUS)
        )
    }

    override fun close() {
        if (!registered) return
        runCatching { context.unregisterReceiver(receiver) }
        registered = false
    }
}
