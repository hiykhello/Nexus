package org.nexus.android.bridge.workspace

import java.io.File

data class ReplacementResult(
    val workspace: WorkspaceDocument,
    val activeProfileId: String,
    val matchedCount: Int,
    val addedCount: Int,
    val removedIds: List<String>,
    val orphanedChainRefs: List<String>,
    val abortedEmpty: Boolean = false,
)

/**
 * 5-tier identity-preserving subscription replacement + fail-closed orphan GC:
 * - Never wipes existing subscription nodes when incoming list is empty (fail-closed).
 * - Preserves all manual profiles, other subscriptions' nodes, user PolicyGroups, and ProxyChains.
 * - Reuses matched profile IDs across refreshes so active selection, routing targets, chains, and
 *   telemetry remain stable.
 * - Reports broken ProxyChain hop references without silently mutating/shortening chains.
 */
object ProfileReplacement {
    fun replaceSubscriptionNodes(
        workspace: WorkspaceDocument,
        subscriptionId: String,
        incomingNodes: List<ProfileItem>,
        activeProfileId: String = "",
    ): ReplacementResult {
        if (incomingNodes.isEmpty()) {
            return ReplacementResult(
                workspace = workspace,
                activeProfileId = activeProfileId,
                matchedCount = 0,
                addedCount = 0,
                removedIds = emptyList(),
                orphanedChainRefs = findOrphanedChainRefs(workspace),
                abortedEmpty = true,
            )
        }

        val existingForSub = workspace.profiles.filter {
            it.isFromSub && it.subscriptionId == subscriptionId && it.kind == ProfileKind.NODE
        }
        val preservedOthers = workspace.profiles.filterNot {
            it.isFromSub && it.subscriptionId == subscriptionId && it.kind == ProfileKind.NODE
        }

        val remainingExisting = existingForSub.toMutableList()
        val usedIds = preservedOthers.map { it.id }.toMutableSet()
        val candidates = incomingNodes.map {
            it.copy(subscriptionId = subscriptionId, isFromSub = true, kind = ProfileKind.NODE)
        }
        val matchedIds = arrayOfNulls<String>(candidates.size)
        var matchedCount = 0

        // Multi-pass Tier 1 -> Tier 5 so an earlier weak match never steals an ID from a later exact match.
        for (tier in 1..5) {
            for (i in candidates.indices) {
                if (matchedIds[i] != null) continue
                val match = findMatchAtTier(tier, candidates[i], remainingExisting)
                if (match != null) {
                    remainingExisting.remove(match)
                    usedIds.add(match.id)
                    matchedIds[i] = match.id
                    matchedCount++
                }
            }
        }

        val replaced = mutableListOf<ProfileItem>()
        var addedCount = 0
        for (i in candidates.indices) {
            val candidate = candidates[i]
            val existingId = matchedIds[i]
            if (existingId != null) {
                replaced.add(candidate.copy(id = existingId))
            } else {
                val baseId = candidate.id.ifBlank {
                    WorkspaceStore.newProfileId("sub-${subscriptionId.take(12)}")
                }
                val uniqueId = WorkspaceStore.makeUniqueId(baseId, usedIds)
                usedIds.add(uniqueId)
                replaced.add(candidate.copy(id = uniqueId))
                addedCount++
            }
        }

        val removedIds = remainingExisting.map { it.id }
        val nextProfiles = preservedOthers + replaced
        val nextWorkspace = workspace.copy(profiles = nextProfiles)

        val survivingIds = nextProfiles.map { it.id }.toSet()
        val nextActive = when {
            activeProfileId.isNotEmpty() && activeProfileId in survivingIds -> activeProfileId
            activeProfileId in removedIds -> replaced.firstOrNull()?.id ?: ""
            else -> activeProfileId
        }

        return ReplacementResult(
            workspace = nextWorkspace,
            activeProfileId = nextActive,
            matchedCount = matchedCount,
            addedCount = addedCount,
            removedIds = removedIds,
            orphanedChainRefs = findOrphanedChainRefs(nextWorkspace),
            abortedEmpty = false,
        )
    }

    /**
     * Applies optional subscription `includeRegex` and `excludeRegex` filters safely.
     * Malformed regex patterns are ignored fail-safe rather than throwing.
     */
    fun filterNodesByRegex(
        nodes: List<ProfileItem>,
        includeRegex: String,
        excludeRegex: String,
    ): List<ProfileItem> {
        val inc = includeRegex.trim().takeIf { it.isNotEmpty() }?.let { runCatching { Regex(it) }.getOrNull() }
        val exc = excludeRegex.trim().takeIf { it.isNotEmpty() }?.let { runCatching { Regex(it) }.getOrNull() }
        if (inc == null && exc == null) return nodes
        return nodes.filter { item ->
            val label = item.remarks.ifBlank { item.id }
            (inc == null || inc.containsMatchIn(label)) && (exc == null || !exc.containsMatchIn(label))
        }
    }

    /**
     * Fail-closed orphan secret file GC:
     * Only deletes `*.secret`, `*.pem`, and `*.ech` files inside [secretsDir] when [composeOk]
     * is true and the file is not listed in [activeSecretFiles].
     */
    fun gcOrphanSecretFiles(
        secretsDir: File,
        activeSecretFiles: Collection<String>,
        composeOk: Boolean,
    ): List<File> {
        if (!composeOk || !secretsDir.isDirectory) return emptyList()
        val activeCanonical = activeSecretFiles.mapNotNull { path ->
            val f = File(path)
            runCatching { f.canonicalPath }.getOrElse { f.absolutePath }
        }.toSet()
        val deleted = mutableListOf<File>()
        val managedExts = setOf("secret", "pem", "ech")
        val candidates = secretsDir.listFiles { f -> f.isFile && f.extension.lowercase() in managedExts }.orEmpty()
        for (file in candidates) {
            val canonical = runCatching { file.canonicalPath }.getOrElse { file.absolutePath }
            if (canonical !in activeCanonical) {
                if (runCatching { file.delete() }.getOrDefault(false)) {
                    deleted.add(file)
                }
            }
        }
        return deleted
    }

    fun findOrphanedChainRefs(workspace: WorkspaceDocument): List<String> {
        val validIds = workspace.profiles.map { it.id }.toSet()
        val broken = mutableListOf<String>()
        for (profile in workspace.profiles) {
            if (profile.kind == ProfileKind.PROXY_CHAIN) {
                profile.proxyChain?.hopIds.orEmpty().forEach { hopId ->
                    if (hopId.isNotEmpty() && hopId !in validIds) {
                        broken.add("${profile.id}->$hopId")
                    }
                }
            }
        }
        for (sub in workspace.subscriptions) {
            if (sub.prevProfileId.isNotEmpty() && sub.prevProfileId !in validIds) {
                broken.add("sub:${sub.id}:prev->${sub.prevProfileId}")
            }
            if (sub.nextProfileId.isNotEmpty() && sub.nextProfileId !in validIds) {
                broken.add("sub:${sub.id}:next->${sub.nextProfileId}")
            }
        }
        return broken
    }

    private fun findMatchAtTier(tier: Int, incoming: ProfileItem, pool: List<ProfileItem>): ProfileItem? {
        val inc = incoming.node ?: return null
        return when (tier) {
            1 -> pool.firstOrNull { existing ->
                val ex = existing.node ?: return@firstOrNull false
                fullTransportCredentialMatch(inc, ex) && existing.remarks == incoming.remarks
            }
            2 -> pool.firstOrNull { existing ->
                val ex = existing.node ?: return@firstOrNull false
                fullTransportCredentialMatch(inc, ex)
            }
            3 -> pool.firstOrNull { existing ->
                val ex = existing.node ?: return@firstOrNull false
                endpointMatch(inc, ex) &&
                    inc.transport.type.equals(ex.transport.type, ignoreCase = true) &&
                    existing.remarks == incoming.remarks
            }
            4 -> {
                val matches = pool.filter { existing ->
                    val ex = existing.node ?: return@filter false
                    endpointMatch(inc, ex)
                }
                matches.singleOrNull()
            }
            5 -> if (incoming.remarks.isNotBlank()) {
                val matches = pool.filter { existing ->
                    val ex = existing.node ?: return@filter false
                    existing.remarks == incoming.remarks && inc.protocol.equals(ex.protocol, ignoreCase = true)
                }
                matches.singleOrNull()
            } else null
            else -> null
        }
    }

    private fun endpointMatch(a: NodeConfig, b: NodeConfig): Boolean =
        a.protocol.equals(b.protocol, ignoreCase = true) &&
            a.server.equals(b.server, ignoreCase = true) &&
            a.port == b.port

    private fun fullTransportCredentialMatch(a: NodeConfig, b: NodeConfig): Boolean =
        endpointMatch(a, b) &&
            a.username == b.username &&
            a.password == b.password &&
            a.tls.sni.equals(b.tls.sni, ignoreCase = true) &&
            a.transport.type.equals(b.transport.type, ignoreCase = true) &&
            a.transport.path == b.transport.path
}
