#if canImport(SwiftUI)
import Foundation
import SwiftUI
import NexusCoreBridge

/// Cross-platform Proxies & Outbound Groups screen with tactile group rail, latency sorting,
/// batch group probing, deferred probe spinners, and actionable empty/search states.
public struct ProxiesGroupsView: View {
    public let groups: [OutboundGroupSnapshot]
    public let probingOutbounds: Set<String>
    public let lastProbeBanner: String?
    public let focusSearchTrigger: Int
    public let shouldAutoFocusSearch: Bool
    public let onConsumeSearchFocus: () -> Void
    public let onSelectMember: (String, String) -> Void
    public let onProbeGroup: (String) -> Void
    public let onProbeOutbound: (String) -> Void
    public let onResetGroupAuto: (String) -> Void
    public let onRefresh: () -> Void

    @State private var selectedGroupTag: String = ""
    @State private var searchText: String = ""
    @State private var sortByLatency: Bool = false
    @FocusState private var isSearchFocused: Bool
    @Environment(\.colorSchemeContrast) private var contrast
    #if os(iOS)
    @Environment(\.horizontalSizeClass) private var sizeClass
    #endif

    public init(
        groups: [OutboundGroupSnapshot],
        probingOutbounds: Set<String> = [],
        lastProbeBanner: String? = nil,
        focusSearchTrigger: Int = 0,
        shouldAutoFocusSearch: Bool = false,
        onConsumeSearchFocus: @escaping () -> Void = {},
        onSelectMember: @escaping (String, String) -> Void,
        onProbeGroup: @escaping (String) -> Void,
        onProbeOutbound: @escaping (String) -> Void,
        onResetGroupAuto: @escaping (String) -> Void,
        onRefresh: @escaping () -> Void
    ) {
        self.groups = groups
        self.probingOutbounds = probingOutbounds
        self.lastProbeBanner = lastProbeBanner
        self.focusSearchTrigger = focusSearchTrigger
        self.shouldAutoFocusSearch = shouldAutoFocusSearch
        self.onConsumeSearchFocus = onConsumeSearchFocus
        self.onSelectMember = onSelectMember
        self.onProbeGroup = onProbeGroup
        self.onProbeOutbound = onProbeOutbound
        self.onResetGroupAuto = onResetGroupAuto
        self.onRefresh = onRefresh
    }

    private var activeGroup: OutboundGroupSnapshot? {
        if let match = groups.first(where: { $0.tag == selectedGroupTag }) {
            return match
        }
        return groups.first
    }

    private func preparedMembers(for group: OutboundGroupSnapshot) -> [OutboundMemberSnapshot] {
        let q = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        var list = q.isEmpty ? group.members : group.members.filter {
            $0.name.lowercased().contains(q) || $0.state.lowercased().contains(q)
        }
        if sortByLatency {
            list.sort { lhs, rhs in
                let lVal = effectiveLatency(lhs) ?? Int64.max
                let rVal = effectiveLatency(rhs) ?? Int64.max
                if lVal != rVal { return lVal < rVal }
                return lhs.name < rhs.name
            }
        }
        return list
    }

    private func effectiveLatency(_ member: OutboundMemberSnapshot) -> Int64? {
        if let ewma = member.ewmaMs, ewma >= 0 { return ewma }
        return member.latencyMs >= 0 ? member.latencyMs : nil
    }

    private let nodeColumns = [
        GridItem(.adaptive(minimum: 220, maximum: 320), spacing: 10),
    ]

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            headerControls
            if let banner = lastProbeBanner, !banner.isEmpty {
                Text(banner)
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(NexusPalette.subtleSurface, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            }
            if groups.isEmpty {
                ContentUnavailableView {
                    Label("暂无策略组", systemImage: "arrow.triangle.branch")
                } description: {
                    Text("连接内核后将展示所有出站策略组与节点延迟。")
                } actions: {
                    Button("刷新", action: onRefresh)
                        .buttonStyle(.borderedProminent)
                }
            } else {
                groupRail
                if let group = activeGroup {
                    activeGroupToolbar(group)
                    let members = preparedMembers(for: group)
                    if members.isEmpty {
                        if !searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                            ContentUnavailableView {
                                Label("未找到“\(searchText)”", systemImage: "magnifyingglass")
                            } description: {
                                Text("请尝试其他关键词或重置筛选条件。")
                            } actions: {
                                Button("重置筛选") { searchText = "" }
                                    .buttonStyle(.bordered)
                            }
                        } else {
                            ContentUnavailableView {
                                Label("策略组暂无成员", systemImage: "tray")
                            } description: {
                                Text("请刷新或检查当前配置中的出站节点。")
                            } actions: {
                                Button("刷新", action: onRefresh)
                                    .buttonStyle(.bordered)
                            }
                        }
                    } else {
                        ScrollView {
                            LazyVGrid(columns: nodeColumns, spacing: 10) {
                                ForEach(members) { member in
                                    ProxyNodeCard(
                                        member: member,
                                        isActive: member.name == group.active,
                                        canSelect: group.supportsManualSelection,
                                        isProbing: probingOutbounds.contains(member.name),
                                        onSelect: { onSelectMember(group.tag, member.name) },
                                        onProbe: { onProbeOutbound(member.name) }
                                    )
                                }
                            }
                            .padding(.bottom, 8)
                        }
                    }
                }
            }
        }
        .padding()
        .onAppear {
            consumePendingSearchFocusIfNeeded()
        }
        .onChange(of: groups.map(\.tag)) { _, tags in
            if !tags.contains(selectedGroupTag), let first = tags.first {
                selectedGroupTag = first
            }
        }
        .onChange(of: focusSearchTrigger) { _, _ in
            consumePendingSearchFocusIfNeeded()
        }
        #if os(iOS)
        .sensoryFeedback(.selection, trigger: activeGroup?.active ?? "")
        #endif
    }

    private func consumePendingSearchFocusIfNeeded() {
        if shouldAutoFocusSearch {
            isSearchFocused = true
            onConsumeSearchFocus()
        }
    }

    private var isCompactLayout: Bool {
        #if os(iOS)
        return sizeClass == .compact
        #else
        return false
        #endif
    }

    @ViewBuilder
    private var headerControls: some View {
        if isCompactLayout {
            VStack(alignment: .leading, spacing: 8) {
                searchField
                HStack(spacing: 8) {
                    sortToggle
                    Spacer()
                    refreshButton
                }
            }
        } else {
            HStack(spacing: 8) {
                searchField
                sortToggle
                refreshButton
            }
        }
    }

    private var searchField: some View {
        TextField("搜索节点名称或状态…", text: $searchText)
            .textFieldStyle(.roundedBorder)
            .focused($isSearchFocused)
            .accessibilityLabel("搜索节点")
    }

    private var sortToggle: some View {
        Toggle(isOn: $sortByLatency) {
            Label("按延迟", systemImage: "arrow.up.arrow.down")
        }
        .toggleStyle(.button)
        .accessibilityHint("切换按实测延迟升序排序")
        #if os(iOS)
        .frame(minHeight: 44)
        #endif
    }

    private var refreshButton: some View {
        Button(action: onRefresh) {
            Label("刷新", systemImage: "arrow.clockwise")
        }
        #if os(iOS)
        .frame(minHeight: 44)
        #endif
    }

    private var groupRail: some View {
        let increased = contrast == .increased
        return ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(groups) { group in
                    let isSelected = activeGroup?.tag == group.tag
                    Button {
                        selectedGroupTag = group.tag
                    } label: {
                        HStack(spacing: 6) {
                            Text(group.tag)
                                .font(.subheadline.weight(.semibold))
                            Text(group.mode)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 7)
                        .background(
                            isSelected ? Color.accentColor.opacity(0.16) : NexusPalette.subtleSurface,
                            in: Capsule()
                        )
                        .overlay(
                            Capsule().strokeBorder(
                                isSelected
                                    ? Color.accentColor
                                    : NexusPalette.hairlineBorder(increasedContrast: increased),
                                lineWidth: (isSelected || increased) ? 1.25 : 1
                            )
                        )
                    }
                    .buttonStyle(NexusPillButtonStyle())
                    .accessibilityAddTraits(isSelected ? .isSelected : [])
                }
            }
        }
    }

    private func activeGroupToolbar(_ group: OutboundGroupSnapshot) -> some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 10) {
                groupTitleBlock(group)
                Spacer(minLength: 8)
                groupActionButtons(group)
            }
            VStack(alignment: .leading, spacing: 8) {
                groupTitleBlock(group)
                HStack(spacing: 8) {
                    groupActionButtons(group)
                }
            }
        }
        .bentoCard(padding: 12, cornerRadius: 14)
    }

    private func groupTitleBlock(_ group: OutboundGroupSnapshot) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(group.tag) · \(group.mode)")
                .font(.headline)
                .lineLimit(1)
            Text("当前出站：\(group.active.isEmpty ? "未选择" : group.active) · \(group.members.count) 节点")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
                .nexusTooltip(group.active)
        }
    }

    @ViewBuilder
    private func groupActionButtons(_ group: OutboundGroupSnapshot) -> some View {
        if group.manualOverride {
            Button("恢复自动") { onResetGroupAuto(group.tag) }
                .buttonStyle(.bordered)
                .accessibilityHint("取消手动锁定并恢复策略组自动选优")
                #if os(iOS)
                .frame(minHeight: 44)
                #endif
        }
        Button {
            onProbeGroup(group.tag)
        } label: {
            Label("整组测速", systemImage: "bolt.horizontal")
        }
        .buttonStyle(.borderedProminent)
        .accessibilityHint("对当前策略组内全部成员执行并发测速")
        #if os(iOS)
        .frame(minHeight: 44)
        #endif
    }
}

private struct ProxyNodeCard: View {
    let member: OutboundMemberSnapshot
    let isActive: Bool
    let canSelect: Bool
    let isProbing: Bool
    let onSelect: () -> Void
    let onProbe: () -> Void
    @Environment(\.colorSchemeContrast) private var contrast

    private var displayLatency: Int64? {
        if let ewma = member.ewmaMs, ewma >= 0 { return ewma }
        return member.latencyMs >= 0 ? member.latencyMs : nil
    }

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: 14, style: .continuous)
        let increased = contrast == .increased
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 6) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(member.name)
                        .font(.subheadline.weight(.semibold))
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .nexusTooltip(member.name)
                    HStack(spacing: 6) {
                        Text(NexusDisplayCopy.coreStateTitle(member.state))
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                        if member.breakerOpen {
                            Label("熔断", systemImage: "exclamationmark.octagon.fill")
                                .font(.caption2.weight(.semibold))
                                .foregroundStyle(.red)
                        }
                    }
                }
                Spacer(minLength: 4)
                RttPillView(latencyMs: displayLatency, state: member.state)
            }

            HStack(spacing: 8) {
                Button(action: onSelect) {
                    Label(
                        isActive ? "已选中" : (canSelect ? "切换" : "自动"),
                        systemImage: isActive ? "checkmark.circle.fill" : (canSelect ? "circle" : "lock.circle")
                    )
                    .font(.caption.weight(.medium))
                }
                .buttonStyle(.bordered)
                .disabled(isActive || !canSelect)
                .accessibilityLabel(isActive ? "\(member.name) 已为当前出站" : (canSelect ? "切换至 \(member.name)" : "\(member.name) 由策略组自动调度"))
                #if os(iOS)
                .frame(minHeight: 44)
                #endif

                Spacer()

                Button(action: onProbe) {
                    HStack(spacing: 4) {
                        if isProbing {
                            DeferredSpinnerView(isActive: isProbing)
                            Text("测速中")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        } else {
                            Label("测速", systemImage: "speedometer")
                                .font(.caption)
                        }
                    }
                }
                .buttonStyle(.borderless)
                .disabled(isProbing)
                .accessibilityLabel("测速 \(member.name)")
                .accessibilityHint("向内核发送单节点探测请求")
                #if os(iOS)
                .frame(minWidth: 44, minHeight: 44)
                .contentShape(Rectangle())
                #endif
            }
        }
        .padding(12)
        .background(isActive ? Color.accentColor.opacity(0.08) : NexusPalette.cardSurface, in: shape)
        .overlay(
            shape.strokeBorder(
                isActive ? Color.accentColor : NexusPalette.hairlineBorder(increasedContrast: increased),
                lineWidth: (isActive || increased) ? 1.5 : 1
            )
        )
    }
}
#endif
