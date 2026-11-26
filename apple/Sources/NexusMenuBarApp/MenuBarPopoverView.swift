#if os(macOS)
import AppKit
import Foundation
import SwiftUI
import NexusCoreBridge
import NexusSharedUI

/// Native macOS `.window`-style MenuBarExtra popover with flattened hairline dividers,
/// single primary CTA, fixed-width live rates, and honest offline feedback.
struct MenuBarPopoverView: View {
    @Bindable var model: NexusAppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            headerSection
            if let err = model.actionErrorMessage, !err.isEmpty {
                ActionErrorBanner(
                    message: err,
                    flush: false,
                    onRetry: {
                        Task {
                            await model.refreshStatus()
                            await model.refreshGroupsAndMetrics()
                        }
                    },
                    onDismiss: { model.clearActionError() }
                )
            }
            Divider()
            modePickerSection
            PopoverThroughputStrip(model: model)
            Divider()
            if let group = model.primaryGroup {
                quickGroupSection(group)
            } else {
                emptyGroupHint
            }
            Divider()
            quickActionsFooter
        }
        .padding(14)
        .frame(minWidth: 300, idealWidth: 320, maxWidth: 360)
        .task {
            await model.refreshStatus()
            await model.refreshGroupsAndMetrics()
        }
    }

    private var headerSection: some View {
        let subtitle = "\(model.activeProfileDisplayName) · \(model.activeProfileKindBadge)"
        return HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text("Nexus")
                        .font(.headline)
                    StatusBadgeView(isOnline: model.isRunning, label: model.isRunning ? "运行中" : "未连接")
                }
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(subtitle)
            }
            Spacer(minLength: 6)
            Button {
                Task {
                    if model.isRunning {
                        await model.reloadConfig()
                    } else {
                        await model.refreshStatus()
                        await model.refreshGroupsAndMetrics()
                    }
                }
            } label: {
                Image(systemName: model.isRunning ? "arrow.triangle.2.circlepath" : "arrow.clockwise")
                    .font(.subheadline.weight(.semibold))
            }
            .buttonStyle(.bordered)
            .help(model.isRunning ? "热重载当前配置" : "刷新内核连接状态")
            .accessibilityLabel(model.isRunning ? "热重载当前配置" : "刷新内核连接状态")
        }
    }

    private var modePickerSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("出站模式")
                .font(.caption)
                .foregroundStyle(.secondary)
            Picker("出站模式", selection: Binding(
                get: { model.outboundMode },
                set: { mode in Task { await model.setOutboundMode(mode) } }
            )) {
                Text("规则").tag("rule")
                Text("全局").tag("global")
                Text("直连").tag("direct")
            }
            .pickerStyle(.segmented)
            .labelsHidden()
        }
    }

    private func quickGroupSection(_ group: OutboundGroupSnapshot) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("当前策略组：\(group.tag)")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(group.tag)
                Spacer(minLength: 4)
                RttPillView(latencyMs: model.activeGroupRttMs, state: model.isRunning ? "up" : "idle")
            }
            Picker("当前出站", selection: Binding(
                get: { group.active },
                set: { member in Task { await model.selectMember(group: group.tag, member: member) } }
            )) {
                ForEach(group.members) { member in
                    Text(member.latencyMs >= 0 ? "\(member.name) (\(member.latencyMs) ms)" : member.name)
                        .tag(member.name)
                }
            }
            .labelsHidden()
            .disabled(!group.supportsManualSelection)
        }
    }

    private var emptyGroupHint: some View {
        HStack(spacing: 8) {
            Image(systemName: model.isRunning ? "arrow.triangle.branch" : "bolt.slash")
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text(model.isRunning ? "暂无可切换策略组" : "内核未连接，请启动或打开控制台查看")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 4)
    }

    private var quickActionsFooter: some View {
        VStack(spacing: 8) {
            HStack(spacing: 8) {
                Button {
                    Task { await model.flushFakeIpCache() }
                } label: {
                    Label("刷新 FakeIP", systemImage: "sparkles")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .disabled(!model.isRunning)

                Button {
                    openWindow(id: "dashboard")
                    NSApp.activate()
                } label: {
                    Label("打开控制台", systemImage: "macwindow")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
            }

            HStack {
                SettingsLink {
                    Label("设置…", systemImage: "gearshape")
                }
                .buttonStyle(.borderless)
                Spacer()
                Button("退出 Nexus", role: .destructive) {
                    NSApp.terminate(nil)
                }
                .buttonStyle(.borderless)
            }
            .font(.caption)
        }
    }
}

/// Isolated 1Hz leaf inside the menu bar popover preventing header/picker redraws on each tick.
private struct PopoverThroughputStrip: View {
    var model: NexusAppModel

    var body: some View {
        HStack(spacing: 8) {
            LiveRateLabel(text: NexusByteFormat.rate(model.rxRateBytesPerSec), systemImage: "arrow.down", tint: .blue)
            LiveRateLabel(text: NexusByteFormat.rate(model.txRateBytesPerSec), systemImage: "arrow.up", tint: .green)
            Spacer(minLength: 4)
            Text("\(model.metrics.activeSessions) 连接")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .padding(.vertical, 2)
    }
}
#endif
