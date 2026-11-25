package org.nexus.android.ui

import androidx.compose.runtime.Immutable
import org.nexus.android.bridge.workspace.AndroidHostConfig
import org.nexus.android.bridge.workspace.DnsConfig
import org.nexus.android.bridge.workspace.ProfileItem
import org.nexus.android.bridge.workspace.RoutingRuleItem
import org.nexus.android.bridge.workspace.WorkspaceDocument

@Immutable
data class WorkspaceUiState(
    val document: WorkspaceDocument = WorkspaceDocument(),
    val host: AndroidHostConfig = AndroidHostConfig(),
    val activeProfileId: String = "",
    val outboundMode: String = "rule",
    val selectorTag: String = "proxy",
    val selectorMembers: List<String> = emptyList(),
    val composeWarnings: List<String> = emptyList(),
    val isRefreshingSub: Boolean = false,
) {
    val activeProfile: ProfileItem?
        get() = document.profiles.firstOrNull { it.id == activeProfileId }
            ?: document.profiles.firstOrNull()

    val activeProfileTitle: String
        get() = activeProfile?.remarks?.ifBlank { activeProfile?.id.orEmpty() }
            ?.ifBlank { "默认配置" }
            ?: "默认配置"

    val hasAnyRemoteProfile: Boolean
        get() = document.profiles.isNotEmpty()
}

data class WorkspaceUiActions(
    val onSelectProfile: suspend (String) -> String = { "" },
    val onAddProfile: suspend (ProfileItem) -> String = { "" },
    val onDeleteProfile: suspend (String) -> String = { "" },
    val onAddSubscription: suspend (name: String, url: String) -> String = { _, _ -> "" },
    val onRefreshSubscription: suspend (subId: String) -> String = { "" },
    val onUpdateSubscriptionChain: suspend (subId: String, prevId: String, nextId: String) -> String = { _, _, _ -> "" },
    val onSelectRoutingProfile: suspend (routingId: String) -> String = { "" },
    val onAddRoutingRule: suspend (RoutingRuleItem) -> String = { "" },
    val onUpdateDns: suspend (DnsConfig) -> String = { "" },
    val onUpdateHost: suspend (AndroidHostConfig) -> String = { "" },
    val onExportWorkspaceJson: () -> String = { "" },
    val onImportWorkspaceJson: suspend (String) -> String = { "" },
)
