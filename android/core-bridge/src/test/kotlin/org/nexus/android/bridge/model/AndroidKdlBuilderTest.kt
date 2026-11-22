package org.nexus.android.bridge.model

import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class AndroidKdlBuilderTest {
    @Test
    fun generatesValidTunAndStateBlocks() {
        val paths = RuntimeSocketPaths(File("/data/user/0/org.nexus.android/no_backup"))
        val profile = VpnProfileConfig(
            inet4Address = "172.19.0.1/30",
            inet6Address = "fdfe:dcba:9876::1/126",
            mtu = 9000,
            userKdlConfig = AndroidKdlBuilder.defaultSampleUserKdl(),
        )
        val rendered = AndroidKdlBuilder.buildRuntimeConfig(profile, paths, tunFd = 17)
        assertTrue(rendered.contains("""schema-version 1"""))
        assertTrue(rendered.contains("""device-fd 17 ownership="borrow""""))
        assertTrue(rendered.contains("""control socket="/data/user/0/org.nexus.android/no_backup/c.sock""""))
        assertTrue(rendered.contains("""directory "/data/user/0/org.nexus.android/no_backup/state""""))
        assertTrue(rendered.contains("""cache-directory "/data/user/0/org.nexus.android/no_backup/cache""""))
        assertTrue(rendered.contains("""outbound "direct" type="direct""""))
        assertTrue(rendered.contains("""default-outbound "direct""""))
    }

    @Test
    fun rejectsLowFileDescriptors() {
        val paths = RuntimeSocketPaths(File("/data/user/0/org.nexus.android/no_backup"))
        assertThrows(IllegalArgumentException::class.java) {
            AndroidKdlBuilder.buildRuntimeConfig(VpnProfileConfig(), paths, tunFd = 2)
        }
    }
}
