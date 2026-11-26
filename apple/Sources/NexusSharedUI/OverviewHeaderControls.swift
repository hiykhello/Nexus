#if canImport(SwiftUI)
import Foundation
import SwiftUI
import NexusCoreBridge

/// Shared Overview hero status + mode switcher + cache actions for both macOS and iOS.
/// Deduplicates macOS window toolbar actions (`刷新`/`热重载`) while giving iOS full primary controls.
public struct OverviewHeaderControls: View {
    public let activeProfileName: String
    public let activeProfileKind: String
    public let isRunning: Bool
    public let statusSummary: String
    public let workspaceSummary: String
    public let outboundMode: String
    public let cacheActionMessage: String?
    public let actionErrorMessage: String?
    public let showPrimaryRefreshActions: Bool
    public let onSelectMode: (String) -> Void
    public let onRefresh: (() -> Void)?
    public let onReload: (() -> Void)?
    public let onFlushFakeIp: () -> Void
    public let onClearAllCache: () -> Void
    public let onDismissError: () -> Void
    public let onRetryError: (() -> Void)?

    @State private var showClearAllConfirm = false

    public init(
        activeProfileName: String,
        activeProfileKind: String,
        isRunning: Bool,
        statusSummary: String,
        workspaceSummary: String,
        outboundMode: String,
        cacheActionMessage: String? = nil,
        actionErrorMessage: String? = nil,
        showPrimaryRefreshActions: Bool = false,
        onSelectMode: @escaping (String) -> Void,
        onRefresh: (() -> Void)? = nil,
        onReload: (() -> Void)? = nil,
        onFlushFakeIp: @escaping () -> Void,
        onClearAllCache: @escaping () -> Void,
        onDismissError: @escaping () -> Void = {},
        onRetryError: (() -> Void)? = nil
    ) {
        self.activeProfileName = activeProfileName
        self.activeProfileKind = activeProfileKind
        self.isRunning = isRunning
        self.statusSummary = statusSummary
        self.workspaceSummary = workspaceSummary
        self.outboundMode = outboundMode
        self.cacheActionMessage = cacheActionMessage
        self.actionErrorMessage = actionErrorMessage
        self.showPrimaryRefreshActions = showPrimaryRefreshActions
        self.onSelectMode = onSelectMode
        self.onRefresh = onRefresh
        self.onReload = onReload
        self.onFlushFakeIp = onFlushFakeIp
        self.onClearAllCache = onClearAllCache
        self.onDismissError = onDismissError
        self.onRetryError = onRetryError
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            ViewThatFits(in: .horizontal) {
                HStack(alignment: .top, spacing: 12) {
                    titleBlock
                    Spacer(minLength: 8)
                    modePicker
                        .frame(minWidth: 180, idealWidth: 210, maxWidth: 240)
                }
                VStack(alignment: .leading, spacing: 10) {
                    titleBlock
                    modePicker
                }
            }

            if let err = actionErrorMessage, !err.isEmpty {
                ActionErrorBanner(
                    message: err,
                    flush: true,
                    onRetry: onRetryError,
                    onDismiss: onDismissError
                )
            }

            actionStrip
        }
        .bentoCard(padding: 14, cornerRadius: 14)
        .confirmationDialog(
            "确认清空全部缓存？",
            isPresented: $showClearAllConfirm,
            titleVisibility: .visible
        ) {
            Button("清空全部缓存", role: .destructive, action: onClearAllCache)
            Button("取消", role: .cancel) {}
        } message: {
            Text("将清理 DNS 解析与路由状态缓存，不会删除本地配置与节点。")
        }
    }

    private var titleBlock: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Text(activeProfileName)
                    .font(.title2.weight(.bold))
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .nexusTooltip(activeProfileName)
                Text(activeProfileKind)
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                StatusBadgeView(isOnline: isRunning, label: isRunning ? "在线" : "离线")
            }
            Text("\(statusSummary) · \(workspaceSummary)")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
                .lineLimit(2)
        }
    }

    private var modePicker: some View {
        Picker("出站模式", selection: Binding(
            get: { outboundMode },
            set: { onSelectMode($0) }
        )) {
            Text("规则").tag("rule")
            Text("全局").tag("global")
            Text("直连").tag("direct")
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        #if os(iOS)
        .sensoryFeedback(.selection, trigger: outboundMode)
        #endif
    }

    private var actionStrip: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 8) {
                actionButtons
                Spacer(minLength: 4)
                cacheBannerText
            }
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 8) {
                    actionButtons
                }
                cacheBannerText
            }
        }
    }

    @ViewBuilder
    private var actionButtons: some View {
        if showPrimaryRefreshActions, let onRefresh {
            Button(action: onRefresh) {
                Label("刷新状态", systemImage: "arrow.clockwise")
            }
            .buttonStyle(.borderedProminent)
            #if os(iOS)
            .frame(minHeight: 44)
            #endif
        }
        if showPrimaryRefreshActions, let onReload {
            Button(action: onReload) {
                Label("热重载", systemImage: "arrow.triangle.2.circlepath")
            }
            .buttonStyle(.bordered)
            .disabled(!isRunning)
            #if os(iOS)
            .frame(minHeight: 44)
            #endif
        }
        Button(action: onFlushFakeIp) {
            Label("刷新 FakeIP", systemImage: "sparkles")
        }
        .buttonStyle(.bordered)
        .disabled(!isRunning)
        #if os(iOS)
        .frame(minHeight: 44)
        #endif

        Button {
            showClearAllConfirm = true
        } label: {
            Label("清缓存", systemImage: "trash")
        }
        .buttonStyle(.bordered)
        .disabled(!isRunning)
        #if os(iOS)
        .frame(minHeight: 44)
        #endif
    }

    @ViewBuilder
    private var cacheBannerText: some View {
        if let msg = cacheActionMessage, !msg.isEmpty {
            Text(msg)
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
    }
}

/// Shared primary outbound group quick switcher for macOS & iOS Overview screens.
public struct QuickGroupSwitcherCard: View {
    public let group: OutboundGroupSnapshot
    public let isRunning: Bool
    public let activeRttMs: Int64?
    public let onSelectMember: (String) -> Void
    public let onProbeGroup: () -> Void

    public init(
        group: OutboundGroupSnapshot,
        isRunning: Bool,
        activeRttMs: Int64?,
        onSelectMember: @escaping (String) -> Void,
        onProbeGroup: @escaping () -> Void
    ) {
        self.group = group
        self.isRunning = isRunning
        self.activeRttMs = activeRttMs
        self.onSelectMember = onSelectMember
        self.onProbeGroup = onProbeGroup
    }

    public var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 12) {
                groupHeader
                Spacer(minLength: 8)
                RttPillView(latencyMs: activeRttMs, state: isRunning ? "up" : "idle")
                memberPicker
                    .frame(minWidth: 150, idealWidth: 210, maxWidth: 240)
                probeButton
            }
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    groupHeader
                    Spacer(minLength: 6)
                    RttPillView(latencyMs: activeRttMs, state: isRunning ? "up" : "idle")
                }
                HStack(spacing: 8) {
                    memberPicker
                    probeButton
                }
            }
        }
        .bentoCard(padding: 12, cornerRadius: 14)
    }

    private var groupHeader: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("快速切换 · \(group.tag)")
                .font(.subheadline.weight(.semibold))
                .lineLimit(1)
            Text("策略 \(group.mode) · 当前 \(group.active)")
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
                .nexusTooltip("\(group.tag) · \(group.active)")
        }
    }

    private var memberPicker: some View {
        Picker("出站成员", selection: Binding(
            get: { group.active },
            set: { onSelectMember($0) }
        )) {
            ForEach(group.members) { member in
                Text(member.name).tag(member.name)
            }
        }
        .labelsHidden()
        .disabled(!group.supportsManualSelection)
        #if os(iOS)
        .sensoryFeedback(.selection, trigger: group.active)
        #endif
    }

    private var probeButton: some View {
        Button("测速", action: onProbeGroup)
            .buttonStyle(.bordered)
            #if os(iOS)
            .frame(minHeight: 44)
            #endif
    }
}
#endif
