package org.nexus.android.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.nexus.android.bridge.workspace.AndroidHostConfig
import org.nexus.android.bridge.workspace.AndroidHostSection
import org.nexus.android.bridge.workspace.AndroidPerAppMode

class PerAppBypassActionTest {
    @Test
    fun excludeModeAddsPackageAndDisablesWhenAlreadyExcluded() {
        val pkg = "com.android.chrome"
        val addAction = computePerAppConnectionAction(AndroidPerAppMode.EXCLUDE, pkg, emptySet())
        assertTrue(addAction.enabled)
        assertFalse(addAction.removeFromList)
        assertFalse(addAction.switchToExcludeMode)
        assertEquals("绕过应用", addAction.label)

        val mutated = MainTunnelCoordinator.applyBypassFromConnection(
            AndroidHostConfig(android = AndroidHostSection(perAppMode = AndroidPerAppMode.EXCLUDE, perAppPackages = emptyList())),
            pkg,
        )
        assertEquals(AndroidPerAppMode.EXCLUDE, mutated.android.perAppMode)
        assertEquals(listOf(pkg), mutated.android.perAppPackages)

        val already = computePerAppConnectionAction(AndroidPerAppMode.EXCLUDE, pkg, setOf(pkg))
        assertFalse(already.enabled)
        assertEquals("已绕过应用", already.label)
    }

    @Test
    fun includeModeRemovesPackageToBypassAndShowsAlreadyDirectWhenAbsent() {
        val pkg = "org.mozilla.firefox"
        val removeAction = computePerAppConnectionAction(AndroidPerAppMode.INCLUDE, pkg, setOf(pkg, "com.android.chrome"))
        assertTrue(removeAction.enabled)
        assertTrue(removeAction.removeFromList)
        assertFalse(removeAction.switchToExcludeMode)
        assertEquals("移出代理列表", removeAction.label)

        val mutated = MainTunnelCoordinator.applyBypassFromConnection(
            AndroidHostConfig(
                android = AndroidHostSection(
                    perAppMode = AndroidPerAppMode.INCLUDE,
                    perAppPackages = listOf(pkg, "com.android.chrome"),
                ),
            ),
            pkg,
        )
        assertEquals(AndroidPerAppMode.INCLUDE, mutated.android.perAppMode)
        assertEquals(listOf("com.android.chrome"), mutated.android.perAppPackages)

        val absent = computePerAppConnectionAction(AndroidPerAppMode.INCLUDE, pkg, setOf("com.android.chrome"))
        assertFalse(absent.enabled)
        assertEquals("已直连绕过", absent.label)
    }

    @Test
    fun offModeSwitchesToExcludeAndAddsPackage() {
        val pkg = "com.example.bank"
        val action = computePerAppConnectionAction(AndroidPerAppMode.OFF, pkg, emptySet())
        assertTrue(action.enabled)
        assertTrue(action.switchToExcludeMode)
        assertFalse(action.removeFromList)

        val mutated = MainTunnelCoordinator.applyBypassFromConnection(
            AndroidHostConfig(android = AndroidHostSection(perAppMode = AndroidPerAppMode.OFF, perAppPackages = emptyList())),
            pkg,
        )
        assertEquals(AndroidPerAppMode.EXCLUDE, mutated.android.perAppMode)
        assertEquals(listOf(pkg), mutated.android.perAppPackages)
    }
}
