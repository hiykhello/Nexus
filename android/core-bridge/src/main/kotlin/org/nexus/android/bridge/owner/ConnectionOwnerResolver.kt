package org.nexus.android.bridge.owner

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.os.Process
import android.util.LruCache
import java.io.Closeable
import java.net.InetAddress
import java.net.InetSocketAddress

data class ConnectionOwnerInfo(
    val uid: Int,
    val packageNames: List<String>,
)

/**
 * Non-root per-app connection owner lookup for Android 10+ (API 29+).
 * Uses ConnectivityManager.getConnectionOwnerUid (available to the active VpnService without root)
 * and caches UID -> packageNames with automatic invalidation on package install/remove broadcasts.
 */
class ConnectionOwnerResolver(
    private val context: Context,
) : Closeable {
    private val connectivityManager =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val packageManager = context.packageManager
    private val uidCache = object : LruCache<Int, List<String>>(256) {}
    private var receiverRegistered = false

    private val packageReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context?, intent: Intent?) {
            uidCache.evictAll()
        }
    }

    fun start() {
        if (receiverRegistered) return
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }
        context.registerReceiver(packageReceiver, filter)
        receiverRegistered = true
    }

    fun resolve(
        ipProtocol: Int,
        sourceAddress: InetAddress,
        sourcePort: Int,
        destinationAddress: InetAddress,
        destinationPort: Int,
    ): ConnectionOwnerInfo? {
        val uid = runCatching {
            connectivityManager.getConnectionOwnerUid(
                ipProtocol,
                InetSocketAddress(sourceAddress, sourcePort),
                InetSocketAddress(destinationAddress, destinationPort),
            )
        }.getOrElse { return null }

        if (uid == Process.INVALID_UID || uid < 0) return null
        val packages = uidCache.get(uid) ?: run {
            val resolved = packageManager.getPackagesForUid(uid)?.toList().orEmpty()
            uidCache.put(uid, resolved)
            resolved
        }
        return ConnectionOwnerInfo(uid = uid, packageNames = packages)
    }

    override fun close() {
        if (receiverRegistered) {
            runCatching { context.unregisterReceiver(packageReceiver) }
            receiverRegistered = false
        }
        uidCache.evictAll()
    }
}
