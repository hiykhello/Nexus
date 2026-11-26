#if os(macOS)
import AppKit
import SwiftUI
import NexusCoreBridge
import NexusSharedUI

/// Native macOS `.window`-style MenuBarExtra popover for instant core switching,
/// outbound mode control, active group selection, live throughput, and FakeIP flush.
struct MenuBarPopoverView: View {
    @Bindable var model: NexusAppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            headerCard
            modePickerSection
            throughputStrip
            if let group = model.primaryGroup {
                quickGroupSection(group)
            }
            Divider()
            quickActionsFooter
        }
        .padding(14)
        .frame(width: 320)
        .task {
            await model.refreshStatus()
            await model.refreshGroupsAndMetrics()
        }
    }

    private var headerCard: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text("Nexus")
                        .font(.headline)
                    StatusBadgeView(isOnline: model.isRunning, label: model.isRunning ? "运行中" : "未连接")
                }
                Text("\(model.activeProfileDisplayName) · \(model.activeProfileKindBadge)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            Button {
                Task {
                    if model.isRunning {
                        await model.reloadConfig()
                    } else {
                        await model.refreshStatus()
                    }
                }
            } label: {
                Image(systemName: model.isRunning ? "arrow.triangle.2.circlepath" : "play.fill")
                    .font(.subheadline.weight(.semibold))
            }
            .buttonStyle(.borderedProminent)
            .accessibilityLabel(model.isRunning ? "热重载核心" : "连接核心状态")
        }
    }

    private var modePickerSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("路由模式")
                .font(.caption)
                .foregroundStyle(.secondary)
            Picker("路由模式", selection: Binding(
                get: { model.outboundMode },
                set: { mode in Task { await model.setOutboundMode(mode) } }
            )) {
                Text("Rule").tag("rule")
                Text("Global").tag("global")
                Text("Direct").tag("direct")
            }
            .pickerStyle(.segmented)
            .labelsHidden()
        }
    }

    private var throughputStrip: some View {
        HStack(spacing: 10) {
            Label(NexusByteFormat.rate(model.rxRateBytesPerSec), systemImage: "arrow.down")
                .font(.caption.weight(.medium).monospacedDigit())
                .foregroundStyle(.blue)
            Label(NexusByteFormat.rate(model.txRateBytesPerSec), systemImage: "arrow.up")
                .font(.caption.weight(.medium).monospacedDigit())
                .foregroundStyle(.green)
            Spacer()
            Text("\(model.metrics.activeSessions) 连接")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(NexusPalette.subtleSurface, in: RoundedRectangle(cornerRadius: 8))
    }

    private func quickGroupSection(_ group: OutboundGroupSnapshot) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("当前策略组: \(group.tag)")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
                Spacer()
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
        .bentoCard(padding: 10, cornerRadius: 10)
    }

    private var quickActionsFooter: some View {
        VStack(spacing: 6) {
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
                    Label("设置...", systemImage: "gearshape")
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
#endif
