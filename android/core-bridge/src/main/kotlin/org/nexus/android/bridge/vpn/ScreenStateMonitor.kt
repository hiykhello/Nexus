package org.nexus.android.bridge.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.PowerManager
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
    private val powerManager = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
    private val interactive = AtomicBoolean(powerManager?.isInteractive ?: true)
    private val registered = AtomicBoolean(false)

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
        if (!registered.compareAndSet(false, true)) return
        interactive.set(powerManager?.isInteractive ?: true)
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                @Suppress("UnspecifiedRegisterReceiverFlag")
                context.registerReceiver(receiver, filter)
            }
        } catch (t: Throwable) {
            registered.set(false)
            throw t
        }
    }

    override fun close() {
        if (!registered.compareAndSet(true, false)) return
        runCatching { context.unregisterReceiver(receiver) }
    }
}
