package org.nexus.android.bridge.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import java.io.Closeable
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Tracks device interactive/screen state so background polling and UI telemetry
 * automatically pause during screen-off / Doze windows to save battery.
 */
class ScreenStateMonitor(
    private val context: Context,
    private val onScreenInteractiveChanged: (Boolean) -> Unit,
) : Closeable {
    private val interactive = AtomicBoolean(true)
    private var registered = false

    val isInteractive: Boolean get() = interactive.get()

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context?, intent: Intent?) {
            when (intent?.action) {
                Intent.ACTION_SCREEN_OFF -> {
                    if (interactive.getAndSet(false)) {
                        onScreenInteractiveChanged(false)
                    }
                }
                Intent.ACTION_SCREEN_ON -> {
                    if (!interactive.getAndSet(true)) {
                        onScreenInteractiveChanged(true)
                    }
                }
            }
        }
    }

    fun start() {
        if (registered) return
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
        }
        context.registerReceiver(receiver, filter)
        registered = true
    }

    override fun close() {
        if (!registered) return
        runCatching { context.unregisterReceiver(receiver) }
        registered = false
    }
}
