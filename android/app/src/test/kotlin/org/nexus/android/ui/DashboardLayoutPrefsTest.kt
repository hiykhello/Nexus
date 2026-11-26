package org.nexus.android.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DashboardLayoutPrefsTest {
    @Test
    fun defaultStateUsesCanonicalOrderAndHasNoCustomLayout() {
        val state = DashboardCardVisibility()
        assertEquals(DashboardCardVisibility.DEFAULT_CARD_ORDER, state.sanitizedOrder)
        assertFalse(state.hasCustomHidden)
        assertFalse(state.hasCustomOrder)
        assertFalse(state.hasCustomLayout)
        assertEquals(
            listOf(
                DashboardCardVisibility.KEY_SPARKLINE,
                DashboardCardVisibility.KEY_NETWORK_MEMORY,
                DashboardCardVisibility.KEY_QUICK_NODES,
                DashboardCardVisibility.KEY_TRAFFIC_SPLIT,
            ),
            state.visibleOrderedCards(allowQuickNodes = true),
        )
    }

    @Test
    fun sanitizeOrderRecoversFromCorruptDuplicatesAndMissingKeys() {
        val raw = listOf(
            "unknown_junk",
            DashboardCardVisibility.KEY_TRAFFIC_SPLIT,
            "  ${DashboardCardVisibility.KEY_SPARKLINE} ",
            DashboardCardVisibility.KEY_TRAFFIC_SPLIT,
            "",
        )
        val clean = DashboardCardVisibility.sanitizeOrder(raw)
        assertEquals(
            listOf(
                DashboardCardVisibility.KEY_TRAFFIC_SPLIT,
                DashboardCardVisibility.KEY_SPARKLINE,
                DashboardCardVisibility.KEY_NETWORK_MEMORY,
                DashboardCardVisibility.KEY_QUICK_NODES,
                DashboardCardVisibility.KEY_KPI_GRID,
            ),
            clean,
        )
        assertEquals(DashboardCardVisibility.DEFAULT_CARD_ORDER.size, clean.distinct().size)
    }

    @Test
    fun moveCardSwapsVisibleNeighborsAndSkipsHiddenCards() {
        val initial = DashboardCardVisibility(showQuickNodes = false)
        val visible = initial.visibleOrderedCards(allowQuickNodes = true)
        assertEquals(
            listOf(
                DashboardCardVisibility.KEY_SPARKLINE,
                DashboardCardVisibility.KEY_NETWORK_MEMORY,
                DashboardCardVisibility.KEY_TRAFFIC_SPLIT,
            ),
            visible,
        )

        val movedDown = initial.moveCard(
            cardId = DashboardCardVisibility.KEY_NETWORK_MEMORY,
            delta = +1,
            activePool = visible,
        )
        assertTrue(movedDown.hasCustomOrder)
        assertTrue(movedDown.hasCustomLayout)
        assertEquals(
            listOf(
                DashboardCardVisibility.KEY_SPARKLINE,
                DashboardCardVisibility.KEY_TRAFFIC_SPLIT,
                DashboardCardVisibility.KEY_NETWORK_MEMORY,
            ),
            movedDown.visibleOrderedCards(allowQuickNodes = true),
        )
    }

    @Test
    fun moveCardAtBoundaryIsNoOp() {
        val state = DashboardCardVisibility()
        val visible = state.visibleOrderedCards(allowQuickNodes = true)
        assertEquals(state.sanitizedOrder, state.moveCard(visible.first(), -1, visible).sanitizedOrder)
        assertEquals(state.sanitizedOrder, state.moveCard(visible.last(), +1, visible).sanitizedOrder)
    }

    @Test
    fun serializeAndParseRoundTripPreservesOrderAndVisibility() {
        val custom = DashboardCardVisibility(
            showQuickNodes = false,
            showKpiGrid = true,
            cardOrder = listOf(
                DashboardCardVisibility.KEY_TRAFFIC_SPLIT,
                DashboardCardVisibility.KEY_KPI_GRID,
                DashboardCardVisibility.KEY_SPARKLINE,
                DashboardCardVisibility.KEY_NETWORK_MEMORY,
                DashboardCardVisibility.KEY_QUICK_NODES,
            ),
        )
        val hidden = custom.toHiddenKeySet()
        val rawOrder = custom.toSerializedOrder()
        val restored = DashboardCardVisibility.fromPersisted(hidden, rawOrder)

        assertEquals(custom.showQuickNodes, restored.showQuickNodes)
        assertEquals(custom.showKpiGrid, restored.showKpiGrid)
        assertEquals(custom.sanitizedOrder, restored.sanitizedOrder)
        assertTrue(restored.hasCustomLayout)

        val db = org.nexus.android.bridge.workspace.NexusClientDatabase.inMemory()
        DashboardLayoutPrefs.save(db, custom)
        val loadedFromDb = DashboardLayoutPrefs.load(db)
        assertEquals(custom, loadedFromDb)
    }
}
