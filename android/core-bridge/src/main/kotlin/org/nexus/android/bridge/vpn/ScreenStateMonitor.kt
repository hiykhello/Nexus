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
 * Tracks device interactive/screen state AND Android Doze (`ACTION_DEVICE_IDLE_MODE_CHANGED`)
 * so background polling and UI telemetry automatically pause during screen-off / Doze windows.
 */
class ScreenStateMonitor(
    private val context: Context,
    private val onPowerStateChanged: (interactive: Boolean, deviceIdle: Boolean) -> Unit,
) : Closeable {
    constructor(
        context: Context,
        onScreenInteractiveChanged: (Boolean) -> Unit,
    ) : this(context, { interactive, _ -> onScreenInteractiveChanged(interactive) })

    private val powerManager = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
    private val interactive = AtomicBoolean(powerManager?.isInteractive ?: true)
    private val deviceIdle = AtomicBoolean(powerManager?.isDeviceIdleMode ?: false)
    private val registered = AtomicBoolean(false)

    val isInteractive: Boolean get() = interactive.get()
    val isDeviceIdle: Boolean get() = deviceIdle.get()

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context?, intent: Intent?) {
            when (intent?.action) {
                Intent.ACTION_SCREEN_OFF -> {
                    if (interactive.getAndSet(false)) {
                        onPowerStateChanged(false, deviceIdle.get())
                    }
                }
                Intent.ACTION_SCREEN_ON -> {
                    if (!interactive.getAndSet(true)) {
                        onPowerStateChanged(true, deviceIdle.get())
                    }
                }
                PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED -> {
                    val idle = powerManager?.isDeviceIdleMode ?: false
                    if (deviceIdle.getAndSet(idle) != idle) {
                        onPowerStateChanged(interactive.get(), idle)
                    }
                }
            }
        }
    }

    fun start() {
        if (!registered.compareAndSet(false, true)) return
        interactive.set(powerManager?.isInteractive ?: true)
        deviceIdle.set(powerManager?.isDeviceIdleMode ?: false)
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
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

    companion object {
        fun shouldPausePolling(
            interactive: Boolean,
            deviceIdle: Boolean,
            screenOffPauseStats: Boolean,
            dozePauseEnabled: Boolean,
        ): Boolean = (!interactive && screenOffPauseStats) || (deviceIdle && dozePauseEnabled)
    }
}
