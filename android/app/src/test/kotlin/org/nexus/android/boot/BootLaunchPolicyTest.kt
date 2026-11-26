package org.nexus.android.boot

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.nexus.android.bridge.workspace.AndroidHostConfig
import org.nexus.android.bridge.workspace.AndroidHostConfigStore
import org.nexus.android.bridge.workspace.AndroidHostSection
import org.nexus.android.bridge.workspace.AndroidRunMode
import org.nexus.android.bridge.workspace.NexusClientDatabase
import org.nexus.android.bridge.workspace.TelemetryStore
import java.io.File
import java.nio.file.Files

class BootLaunchPolicyTest {
    @Test
    fun skipsWhenUserLockedOrAutoStartDisabled() {
        val dir = Files.createTempDirectory("nexus-boot-1").toFile()
        try {
            val db = NexusClientDatabase.inMemory()
            val hostStore = AndroidHostConfigStore(File(dir, "host.json"), db)
            val telStore = TelemetryStore(db)
            hostStore.save(AndroidHostConfig(android = AndroidHostSection(autoStartOnBoot = true)))

            assertEquals(
                BootLaunchDecision.SKIP_USER_LOCKED,
                BootLaunchPolicy.evaluate(
                    userUnlocked = false,
                    hostStore = hostStore,
                    telemetryStore = telStore,
                    vpnPrepared = true,
                    configReady = true,
                ),
            )

            hostStore.save(AndroidHostConfig(android = AndroidHostSection(autoStartOnBoot = false)))
            assertEquals(
                BootLaunchDecision.SKIP_DISABLED,
                BootLaunchPolicy.evaluate(
                    userUnlocked = true,
                    hostStore = hostStore,
                    telemetryStore = telStore,
                    vpnPrepared = true,
                    configReady = true,
                ),
            )
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun abortsAndClearsAutoStartOnUnreadUnexpectedCrashSentinel() {
        val dir = Files.createTempDirectory("nexus-boot-crash").toFile()
        try {
            val db = NexusClientDatabase.inMemory()
            val hostStore = AndroidHostConfigStore(File(dir, "host.json"), db)
            val telStore = TelemetryStore(db)
            hostStore.save(AndroidHostConfig(android = AndroidHostSection(autoStartOnBoot = true)))
            telStore.recordUnexpectedCrash("exit=134")

            val decision = BootLaunchPolicy.evaluate(
                userUnlocked = true,
                hostStore = hostStore,
                telemetryStore = telStore,
                vpnPrepared = true,
                configReady = true,
            )
            assertEquals(BootLaunchDecision.ABORT_CRASH_LOOP, decision)
            assertFalse(hostStore.load().android.autoStartOnBoot)
            assertFalse(telStore.hasUnreadUnexpectedCrash())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun proxyOnlyModeLaunchesWithoutVpnConsentWhileVpnModeRequiresPrepared() {
        val dir = Files.createTempDirectory("nexus-boot-mode").toFile()
        try {
            val db = NexusClientDatabase.inMemory()
            val hostStore = AndroidHostConfigStore(File(dir, "host.json"), db)
            val telStore = TelemetryStore(db)

            hostStore.save(AndroidHostConfig(android = AndroidHostSection(runMode = AndroidRunMode.VPN, autoStartOnBoot = true)))
            assertEquals(
                BootLaunchDecision.SKIP_VPN_NOT_PREPARED,
                BootLaunchPolicy.evaluate(true, hostStore, telStore, vpnPrepared = false, configReady = true),
            )
            assertEquals(
                BootLaunchDecision.LAUNCH,
                BootLaunchPolicy.evaluate(true, hostStore, telStore, vpnPrepared = true, configReady = true),
            )

            hostStore.save(AndroidHostConfig(android = AndroidHostSection(runMode = AndroidRunMode.PROXY_ONLY, autoStartOnBoot = true)))
            assertEquals(
                BootLaunchDecision.LAUNCH,
                BootLaunchPolicy.evaluate(true, hostStore, telStore, vpnPrepared = false, configReady = true),
            )
        } finally {
            dir.deleteRecursively()
        }
    }
}
