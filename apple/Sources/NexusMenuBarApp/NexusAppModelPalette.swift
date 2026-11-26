#if os(macOS) || os(iOS)
import Foundation
import NexusCoreBridge
import NexusSharedUI

/// Command Palette quick actions and command dispatch for `NexusAppModel`.
extension NexusAppModel {
    func commandPaletteQuickActions(allowedSections: [AppSection] = AppSection.allCases) -> [CommandPaletteAction] {
        var actions: [CommandPaletteAction] = [
            CommandPaletteAction(id: "mode.rule", title: "切换为规则模式", subtitle: "按路由规则分流流量", systemImage: "arrow.triangle.branch"),
            CommandPaletteAction(id: "mode.global", title: "切换为全局模式", subtitle: "全部流量经主出口转发", systemImage: "globe"),
            CommandPaletteAction(id: "mode.direct", title: "切换为直连模式", subtitle: "全部流量直接连接目标", systemImage: "arrow.right.circle"),
            CommandPaletteAction(id: "core.reload", title: "热重载配置", subtitle: "在不中断应用的情况下重载生效配置", systemImage: "arrow.triangle.2.circlepath", shortcutHint: "⌘R"),
            CommandPaletteAction(id: "cache.fakeip", title: "刷新 FakeIP 缓存", subtitle: "清理未固定的 FakeIP 地址映射", systemImage: "sparkles"),
            CommandPaletteAction(id: "cache.dns", title: "清空 DNS 缓存", subtitle: "清除当前内核 DNS 解析缓存", systemImage: "trash"),
        ]
        if let primary = primaryGroup {
            actions.append(CommandPaletteAction(
                id: "probe.primary",
                title: "测速策略组 · \(primary.tag)",
                subtitle: "并发检测主策略组全部成员延迟",
                systemImage: "bolt.horizontal"
            ))
        }
        for section in allowedSections {
            actions.append(CommandPaletteAction(
                id: "nav.\(section.rawValue)",
                title: "前往 \(section.rawValue)",
                subtitle: "切换主界面功能区",
                systemImage: section.systemImage
            ))
        }
        for preset in NexusThemePreset.allCases {
            actions.append(CommandPaletteAction(
                id: "theme.\(preset.rawValue)",
                title: "主题：\(preset.displayTitle)",
                subtitle: preset.subtitle,
                systemImage: "paintpalette"
            ))
        }
        return actions
    }

    func runCommandPaletteAction(_ actionID: String, allowedSections: [AppSection] = AppSection.allCases) {
        switch actionID {
        case "mode.rule":
            Task { await setOutboundMode("rule") }
        case "mode.global":
            Task { await setOutboundMode("global") }
        case "mode.direct":
            Task { await setOutboundMode("direct") }
        case "core.reload":
            Task { await reloadConfig() }
        case "cache.fakeip":
            Task { await flushFakeIpCache() }
        case "cache.dns":
            Task { await clearCache(scope: "dns") }
        case "probe.primary":
            if let tag = primaryGroup?.tag {
                Task { await probeGroup(group: tag) }
            }
        default:
            if actionID.hasPrefix("nav.") {
                let raw = String(actionID.dropFirst(4))
                if let target = AppSection(rawValue: raw), allowedSections.contains(target) {
                    selectedSection = target
                }
            } else if actionID.hasPrefix("theme.") {
                let raw = String(actionID.dropFirst(6))
                setThemePreset(NexusThemePreset.fromStored(raw))
            }
        }
    }
}
#endif
