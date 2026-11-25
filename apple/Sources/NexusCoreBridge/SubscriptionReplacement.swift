import Foundation

public struct WorkspaceReplacementResult: Sendable, Equatable {
    public let workspace: WorkspaceDocument
    public let activeProfileId: String
    public let matchedCount: Int
    public let addedCount: Int
    public let removedIds: [String]
    public let orphanedChainRefs: [String]
    public let abortedEmpty: Bool

    public init(
        workspace: WorkspaceDocument,
        activeProfileId: String,
        matchedCount: Int,
        addedCount: Int,
        removedIds: [String],
        orphanedChainRefs: [String],
        abortedEmpty: Bool = false
    ) {
        self.workspace = workspace
        self.activeProfileId = activeProfileId
        self.matchedCount = matchedCount
        self.addedCount = addedCount
        self.removedIds = removedIds
        self.orphanedChainRefs = orphanedChainRefs
        self.abortedEmpty = abortedEmpty
    }
}

public struct ParsedSubscriptionHeaders: Sendable, Equatable {
    public let usage: WorkspaceSubscriptionUsage
    public let updateIntervalMinutes: Int

    public init(usage: WorkspaceSubscriptionUsage, updateIntervalMinutes: Int = 0) {
        self.usage = usage
        self.updateIntervalMinutes = updateIntervalMinutes
    }
}

/// Parses standard subscription HTTP headers (`Subscription-Userinfo`, `Profile-Title`,
/// `Profile-Web-Page-URL`, `Support-URL`, `Profile-Update-Interval`) with strict scheme filtering.
public enum SubscriptionInfoParser {
    private static let allowedSchemes: Set<String> = ["http", "https", "tg"]

    public static func parseHeaders(_ headers: [String: String]) -> ParsedSubscriptionHeaders {
        var lists: [String: [String]] = [:]
        lists.reserveCapacity(headers.count)
        for (k, v) in headers { lists[k] = [v] }
        return parseHeaderLists(lists)
    }

    public static func parseHeaderLists(_ headers: [String: [String]]) -> ParsedSubscriptionHeaders {
        var lookup: [String: String] = [:]
        for (k, values) in headers {
            let key = k.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let first = values.first(where: { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty })?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if !key.isEmpty, let first, !first.isEmpty {
                lookup[key] = first
            }
        }

        let quad = parseUserinfo(lookup["subscription-userinfo"] ?? "")
        let title = decodeProfileTitle(lookup["profile-title"] ?? "")
        let webPage = sanitizeSafeURL(lookup["profile-web-page-url"] ?? "")
        let support = sanitizeSafeURL(lookup["support-url"] ?? "")
        let hours = Int((lookup["profile-update-interval"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
        let minutes = hours > 0 ? min(max(hours * 60, 15), 7 * 24 * 60) : 0

        return ParsedSubscriptionHeaders(
            usage: WorkspaceSubscriptionUsage(
                uploadBytes: quad.upload,
                downloadBytes: quad.download,
                totalBytes: quad.total,
                expireUnixSec: quad.expire,
                profileTitle: title,
                webPageUrl: webPage,
                supportUrl: support
            ),
            updateIntervalMinutes: minutes
        )
    }

    public static func parseUserinfo(_ raw: String) -> (upload: Int64, download: Int64, total: Int64, expire: Int64) {
        var upload: Int64 = -1
        var download: Int64 = -1
        var total: Int64 = -1
        var expire: Int64 = -1
        for part in raw.split(separator: ";") {
            guard let eq = part.firstIndex(of: "="), eq > part.startIndex else { continue }
            let key = part[..<eq].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let valueStr = part[part.index(after: eq)...].trimmingCharacters(in: .whitespacesAndNewlines)
            guard let parsed = parseNonNegativeInt64(valueStr) else { continue }
            switch key {
            case "upload": upload = parsed
            case "download": download = parsed
            case "total": total = parsed
            case "expire": expire = parsed
            default: break
            }
        }
        return (upload, download, total, expire)
    }

    public static func decodeProfileTitle(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "" }
        let decoded: String
        if trimmed.lowercased().hasPrefix("base64:") {
            let b64 = String(trimmed.dropFirst(7)).trimmingCharacters(in: .whitespacesAndNewlines)
            let maybe = decodeBase64Relaxed(b64)
            decoded = maybe.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? trimmed : maybe
        } else if trimmed.contains("%") {
            decoded = trimmed.removingPercentEncoding ?? trimmed
        } else {
            decoded = trimmed
        }
        return String(sanitizeControlChars(decoded).prefix(128))
    }

    public static func sanitizeSafeURL(_ raw: String) -> String {
        let trimmed = sanitizeControlChars(raw.trimmingCharacters(in: .whitespacesAndNewlines))
        guard !trimmed.isEmpty, !trimmed.contains(where: { $0.isWhitespace }) else { return "" }
        guard let colon = trimmed.firstIndex(of: ":"), colon > trimmed.startIndex else { return "" }
        let scheme = String(trimmed[..<colon]).lowercased()
        guard allowedSchemes.contains(scheme) else { return "" }
        guard trimmed.lowercased().hasPrefix("\(scheme)://") else { return "" }
        return String(trimmed.prefix(512))
    }

    private static func parseNonNegativeInt64(_ raw: String) -> Int64? {
        guard !raw.isEmpty else { return nil }
        if let direct = Int64(raw) { return direct >= 0 ? direct : nil }
        guard let dbl = Double(raw), dbl.isFinite, dbl >= 0.0, dbl <= Double(Int64.max) else { return nil }
        return Int64(dbl)
    }

    private static func decodeBase64Relaxed(_ raw: String) -> String {
        let compact = raw.filter { !$0.isWhitespace }
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        guard !compact.isEmpty else { return "" }
        let padCount = (4 - (compact.count % 4)) % 4
        let padded = compact + String(repeating: "=", count: padCount)
        guard let data = Data(base64Encoded: padded), let text = String(data: data, encoding: .utf8) else { return "" }
        return text
    }

    private static func sanitizeControlChars(_ text: String) -> String {
        var out = ""
        out.reserveCapacity(text.count)
        for scalar in text.unicodeScalars {
            if scalar.value >= 0x20 && scalar.value != 0x7F {
                out.unicodeScalars.append(scalar)
            }
        }
        return out
    }
}

/// 5-tier identity-preserving subscription replacement + fail-closed orphan secret GC.
public enum WorkspaceProfileReplacement {
    public static func replaceSubscriptionNodes(
        workspace: WorkspaceDocument,
        subscriptionId: String,
        incomingNodes: [WorkspaceProfileItem],
        activeProfileId: String = ""
    ) -> WorkspaceReplacementResult {
        if incomingNodes.isEmpty {
            return WorkspaceReplacementResult(
                workspace: workspace,
                activeProfileId: activeProfileId,
                matchedCount: 0,
                addedCount: 0,
                removedIds: [],
                orphanedChainRefs: findOrphanedChainRefs(in: workspace),
                abortedEmpty: true
            )
        }

        let isSubNode: (WorkspaceProfileItem) -> Bool = {
            $0.isFromSub && $0.subscriptionId == subscriptionId && $0.kind == .node
        }
        var remainingExisting = workspace.profiles.filter(isSubNode)
        let preservedOthers = workspace.profiles.filter { !isSubNode($0) }
        var usedIds = Set(preservedOthers.map(\.id))

        let candidates: [WorkspaceProfileItem] = incomingNodes.map { item in
            var copy = item
            copy.subscriptionId = subscriptionId
            copy.isFromSub = true
            copy.kind = .node
            return copy
        }

        var matchedIds = [String?](repeating: nil, count: candidates.count)
        var matchedCount = 0

        // Multi-pass Tier 1 -> Tier 5 so an earlier weak match never steals an ID from a later exact match.
        for tier in 1...5 {
            let tierUnmatched = candidates.indices.compactMap { matchedIds[$0] == nil ? candidates[$0] : nil }
            for idx in candidates.indices {
                if matchedIds[idx] != nil { continue }
                if let matchIndex = findMatchIndex(
                    tier: tier,
                    incoming: candidates[idx],
                    pool: remainingExisting,
                    unmatchedCandidates: tierUnmatched
                ) {
                    let matched = remainingExisting.remove(at: matchIndex)
                    usedIds.insert(matched.id)
                    matchedIds[idx] = matched.id
                    matchedCount += 1
                }
            }
        }

        var replaced: [WorkspaceProfileItem] = []
        replaced.reserveCapacity(candidates.count)
        var addedCount = 0
        for idx in candidates.indices {
            var item = candidates[idx]
            if let existingId = matchedIds[idx] {
                item.id = existingId
            } else {
                let rawBase = item.id.trimmingCharacters(in: .whitespacesAndNewlines)
                let baseId = rawBase.isEmpty
                    ? WorkspaceStore.newProfileID(prefix: "sub-\(String(subscriptionId.prefix(12)))")
                    : rawBase
                let uniqueId = WorkspaceStore.makeUniqueID(baseId, existing: usedIds)
                usedIds.insert(uniqueId)
                item.id = uniqueId
                addedCount += 1
            }
            replaced.append(item)
        }

        let removedIds = remainingExisting.map(\.id)
        let removedSet = Set(removedIds)
        var nextWorkspace = workspace
        nextWorkspace.profiles = preservedOthers + replaced
        let survivingIds = Set(nextWorkspace.profiles.map(\.id))

        let nextActive: String
        if !activeProfileId.isEmpty && survivingIds.contains(activeProfileId) {
            nextActive = activeProfileId
        } else if removedSet.contains(activeProfileId) {
            nextActive = replaced.first?.id ?? ""
        } else {
            nextActive = activeProfileId
        }

        return WorkspaceReplacementResult(
            workspace: nextWorkspace,
            activeProfileId: nextActive,
            matchedCount: matchedCount,
            addedCount: addedCount,
            removedIds: removedIds,
            orphanedChainRefs: findOrphanedChainRefs(in: nextWorkspace),
            abortedEmpty: false
        )
    }

    public static func filterNodesByRegex(
        _ nodes: [WorkspaceProfileItem],
        includeRegex: String,
        excludeRegex: String
    ) -> [WorkspaceProfileItem] {
        let incPattern = includeRegex.trimmingCharacters(in: .whitespacesAndNewlines)
        let excPattern = excludeRegex.trimmingCharacters(in: .whitespacesAndNewlines)
        let inc = incPattern.isEmpty ? nil : (try? NSRegularExpression(pattern: incPattern))
        let exc = excPattern.isEmpty ? nil : (try? NSRegularExpression(pattern: excPattern))
        guard inc != nil || exc != nil else { return nodes }

        return nodes.filter { item in
            let label = item.remarks.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? item.id : item.remarks
            let range = NSRange(label.startIndex..<label.endIndex, in: label)
            let includeOK = inc.map { $0.firstMatch(in: label, range: range) != nil } ?? true
            let excludeHit = exc.map { $0.firstMatch(in: label, range: range) != nil } ?? false
            return includeOK && !excludeHit
        }
    }

    public static func findOrphanedChainRefs(in workspace: WorkspaceDocument) -> [String] {
        let validIds = Set(workspace.profiles.map(\.id))
        var broken: [String] = []
        for profile in workspace.profiles where profile.kind == .proxyChain {
            for hopId in profile.proxyChain?.hopIds ?? [] where !hopId.isEmpty && !validIds.contains(hopId) {
                broken.append("\(profile.id)->\(hopId)")
            }
        }
        for sub in workspace.subscriptions {
            if !sub.prevProfileId.isEmpty && !validIds.contains(sub.prevProfileId) {
                broken.append("sub:\(sub.id):prev->\(sub.prevProfileId)")
            }
            if !sub.nextProfileId.isEmpty && !validIds.contains(sub.nextProfileId) {
                broken.append("sub:\(sub.id):next->\(sub.nextProfileId)")
            }
        }
        return broken
    }

    /// Fail-closed orphan secret file GC covering `.secret`, `.pem`, and `.ech`.
    /// Never deletes anything when `composeOk == false`.
    @discardableResult
    public static func gcOrphanSecretFiles(
        in secretsDir: URL,
        activeSecretFiles: [String],
        composeOk: Bool,
        fileManager: FileManager = .default
    ) -> [URL] {
        guard composeOk else { return [] }
        var isDir: ObjCBool = false
        guard fileManager.fileExists(atPath: secretsDir.path, isDirectory: &isDir), isDir.boolValue else {
            return []
        }

        let activeCanonical = Set(activeSecretFiles.map {
            URL(fileURLWithPath: $0).resolvingSymlinksInPath().standardizedFileURL.path
        })
        let managedExts: Set<String> = ["secret", "pem", "ech"]
        guard let entries = try? fileManager.contentsOfDirectory(
            at: secretsDir,
            includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
            options: [.skipsSubdirectoryDescendants]
        ) else {
            return []
        }

        var deleted: [URL] = []
        for url in entries {
            let ext = url.pathExtension.lowercased()
            guard managedExts.contains(ext) else { continue }
            guard let vals = try? url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey]),
                  vals.isRegularFile == true,
                  vals.isSymbolicLink != true
            else { continue }
            let canonical = url.resolvingSymlinksInPath().standardizedFileURL.path
            if !activeCanonical.contains(canonical) {
                if (try? fileManager.removeItem(at: url)) != nil {
                    deleted.append(url)
                }
            }
        }
        return deleted
    }

    private static func findMatchIndex(
        tier: Int,
        incoming: WorkspaceProfileItem,
        pool: [WorkspaceProfileItem],
        unmatchedCandidates: [WorkspaceProfileItem]
    ) -> Int? {
        guard let inc = incoming.node else { return nil }
        switch tier {
        case 1:
            return pool.firstIndex { exItem in
                guard let ex = exItem.node else { return false }
                return fullTransportCredentialMatch(inc, ex) && exItem.remarks == incoming.remarks
            }
        case 2:
            return pool.firstIndex { exItem in
                guard let ex = exItem.node else { return false }
                return fullTransportCredentialMatch(inc, ex)
            }
        case 3:
            return pool.firstIndex { exItem in
                guard let ex = exItem.node else { return false }
                return endpointMatch(inc, ex)
                    && inc.transport.type.caseInsensitiveCompare(ex.transport.type) == .orderedSame
                    && exItem.remarks == incoming.remarks
            }
        case 4:
            let poolIndices = pool.indices.filter { idx in
                guard let ex = pool[idx].node else { return false }
                return endpointMatch(inc, ex)
            }
            guard poolIndices.count == 1 else { return nil }
            let incomingCount = unmatchedCandidates.filter { cand in
                guard let cn = cand.node else { return false }
                return endpointMatch(inc, cn)
            }.count
            return incomingCount == 1 ? poolIndices[0] : nil
        case 5:
            guard !incoming.remarks.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
            let poolIndices = pool.indices.filter { idx in
                guard let ex = pool[idx].node else { return false }
                return pool[idx].remarks == incoming.remarks
                    && inc.protocolName.caseInsensitiveCompare(ex.protocolName) == .orderedSame
            }
            guard poolIndices.count == 1 else { return nil }
            let incomingCount = unmatchedCandidates.filter { cand in
                guard let cn = cand.node else { return false }
                return cand.remarks == incoming.remarks
                    && inc.protocolName.caseInsensitiveCompare(cn.protocolName) == .orderedSame
            }.count
            return incomingCount == 1 ? poolIndices[0] : nil
        default:
            return nil
        }
    }

    private static func endpointMatch(_ a: WorkspaceNodeConfig, _ b: WorkspaceNodeConfig) -> Bool {
        a.protocolName.caseInsensitiveCompare(b.protocolName) == .orderedSame
            && a.server.caseInsensitiveCompare(b.server) == .orderedSame
            && a.port == b.port
    }

    private static func fullTransportCredentialMatch(_ a: WorkspaceNodeConfig, _ b: WorkspaceNodeConfig) -> Bool {
        endpointMatch(a, b)
            && a.username == b.username
            && a.password == b.password
            && a.tls.sni.caseInsensitiveCompare(b.tls.sni) == .orderedSame
            && a.transport.type.caseInsensitiveCompare(b.transport.type) == .orderedSame
            && a.transport.path == b.transport.path
    }
}
