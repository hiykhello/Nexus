package org.nexus.android.ui

import android.content.SharedPreferences
import androidx.compose.runtime.Immutable

/**
 * Persistent Overview dashboard card visibility + custom order model.
 * Keeps pure layout operations decoupled from Android framework APIs for JVM unit testing.
 */
@Immutable
data class DashboardCardVisibility(
    val showQuickNodes: Boolean = true,
    val showNetworkMemory: Boolean = true,
    val showSparkline: Boolean = true,
    val showTrafficSplit: Boolean = true,
    val showKpiGrid: Boolean = false,
    val cardOrder: List<String> = DEFAULT_CARD_ORDER,
) {
    val sanitizedOrder: List<String>
        get() = sanitizeOrder(cardOrder)

    val hasCustomHidden: Boolean
        get() = !(showQuickNodes && showNetworkMemory && showSparkline && showTrafficSplit && !showKpiGrid)

    val hasCustomOrder: Boolean
        get() = sanitizedOrder != DEFAULT_CARD_ORDER

    val hasCustomLayout: Boolean
        get() = hasCustomHidden || hasCustomOrder

    fun isCardVisible(cardId: String): Boolean = when (cardId) {
        KEY_SPARKLINE -> showSparkline
        KEY_NETWORK_MEMORY -> showNetworkMemory
        KEY_QUICK_NODES -> showQuickNodes
        KEY_TRAFFIC_SPLIT -> showTrafficSplit
        KEY_KPI_GRID -> showKpiGrid
        else -> false
    }

    fun toggleCard(cardId: String): DashboardCardVisibility = when (cardId) {
        KEY_SPARKLINE -> copy(showSparkline = !showSparkline)
        KEY_NETWORK_MEMORY -> copy(showNetworkMemory = !showNetworkMemory)
        KEY_QUICK_NODES -> copy(showQuickNodes = !showQuickNodes)
        KEY_TRAFFIC_SPLIT -> copy(showTrafficSplit = !showTrafficSplit)
        KEY_KPI_GRID -> copy(showKpiGrid = !showKpiGrid)
        else -> this
    }

    fun visibleOrderedCards(allowQuickNodes: Boolean = true): List<String> =
        sanitizedOrder.filter { id ->
            isCardVisible(id) && (id != KEY_QUICK_NODES || allowQuickNodes)
        }

    /**
     * Moves [cardId] by [delta] (-1 up, +1 down) within [activePool] so every tap or drag step
     * swaps directly with the adjacent visible card instead of getting stuck behind hidden cards.
     */
    fun moveCard(
        cardId: String,
        delta: Int,
        activePool: List<String> = visibleOrderedCards(),
    ): DashboardCardVisibility {
        if (delta == 0) return this
        val poolIdx = activePool.indexOf(cardId)
        if (poolIdx < 0) return this
        val targetPoolIdx = (poolIdx + delta).coerceIn(0, activePool.lastIndex)
        if (targetPoolIdx == poolIdx) return this
        val targetId = activePool[targetPoolIdx]
        val next = sanitizedOrder.toMutableList()
        val fromIdx = next.indexOf(cardId)
        val toIdx = next.indexOf(targetId)
        if (fromIdx < 0 || toIdx < 0) return this
        next[fromIdx] = targetId
        next[toIdx] = cardId
        return copy(cardOrder = next)
    }

    fun toHiddenKeySet(): Set<String> = buildSet {
        if (!showQuickNodes) add(KEY_QUICK_NODES)
        if (!showNetworkMemory) add(KEY_NETWORK_MEMORY)
        if (!showSparkline) add(KEY_SPARKLINE)
        if (!showTrafficSplit) add(KEY_TRAFFIC_SPLIT)
        if (showKpiGrid) add(KEY_SHOW_KPI_OPTIN)
    }

    fun toSerializedOrder(): String = serializeOrder(cardOrder)

    companion object {
        const val PREF_HIDDEN_CARDS = "dash_hidden_cards"
        const val PREF_CARD_ORDER = "dash_card_order"

        const val KEY_SPARKLINE = "sparkline"
        const val KEY_NETWORK_MEMORY = "network_memory"
        const val KEY_QUICK_NODES = "quick_nodes"
        const val KEY_TRAFFIC_SPLIT = "traffic_split"
        const val KEY_KPI_GRID = "kpi_grid"
        const val KEY_SHOW_KPI_OPTIN = "show_kpi_optin"

        val DEFAULT_CARD_ORDER: List<String> = listOf(
            KEY_SPARKLINE,
            KEY_NETWORK_MEMORY,
            KEY_QUICK_NODES,
            KEY_TRAFFIC_SPLIT,
            KEY_KPI_GRID,
        )

        fun cardLabel(cardId: String): String = when (cardId) {
            KEY_SPARKLINE -> "实时网速"
            KEY_NETWORK_MEMORY -> "网络与连接"
            KEY_QUICK_NODES -> "快捷切换"
            KEY_TRAFFIC_SPLIT -> "快捷工具"
            KEY_KPI_GRID -> "扩展指标"
            else -> cardId
        }

        /**
         * Produces a guaranteed exact permutation of [DEFAULT_CARD_ORDER], stripping unknown or
         * duplicate entries and appending any missing keys in canonical default order.
         */
        fun sanitizeOrder(raw: List<String>): List<String> {
            val validSet = DEFAULT_CARD_ORDER.toSet()
            val seen = LinkedHashSet<String>(DEFAULT_CARD_ORDER.size)
            for (token in raw) {
                val clean = token.trim()
                if (clean in validSet) seen.add(clean)
            }
            for (key in DEFAULT_CARD_ORDER) {
                seen.add(key)
            }
            return seen.toList()
        }

        fun serializeOrder(order: List<String>): String =
            sanitizeOrder(order).joinToString(",")

        fun parseOrder(raw: String?): List<String> {
            if (raw.isNullOrBlank()) return DEFAULT_CARD_ORDER
            return sanitizeOrder(raw.split(','))
        }

        fun fromPersisted(hidden: Set<String>, rawOrder: String?): DashboardCardVisibility =
            DashboardCardVisibility(
                showQuickNodes = KEY_QUICK_NODES !in hidden,
                showNetworkMemory = KEY_NETWORK_MEMORY !in hidden,
                showSparkline = KEY_SPARKLINE !in hidden,
                showTrafficSplit = KEY_TRAFFIC_SPLIT !in hidden,
                showKpiGrid = KEY_SHOW_KPI_OPTIN in hidden,
                cardOrder = parseOrder(rawOrder),
            )

        fun fromHiddenKeySet(hidden: Set<String>): DashboardCardVisibility =
            fromPersisted(hidden = hidden, rawOrder = null)
    }
}

object DashboardLayoutPrefs {
    fun load(prefs: SharedPreferences): DashboardCardVisibility =
        DashboardCardVisibility.fromPersisted(
            hidden = prefs.getStringSet(DashboardCardVisibility.PREF_HIDDEN_CARDS, emptySet()).orEmpty(),
            rawOrder = prefs.getString(DashboardCardVisibility.PREF_CARD_ORDER, null),
        )

    fun save(prefs: SharedPreferences, state: DashboardCardVisibility) {
        prefs.edit()
            .putStringSet(DashboardCardVisibility.PREF_HIDDEN_CARDS, state.toHiddenKeySet())
            .putString(DashboardCardVisibility.PREF_CARD_ORDER, state.toSerializedOrder())
            .apply()
    }
}
