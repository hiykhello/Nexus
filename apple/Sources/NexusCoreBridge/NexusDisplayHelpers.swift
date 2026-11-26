import Foundation

/// Pure user-facing display formatters and optimistic state-transition helpers shared by
/// macOS/iOS SwiftUI surfaces and unit tests (zero raw SDK/IPC/storage jargon).
public enum NexusDisplayCopy {
    public static func coreStateTitle(_ rawState: String) -> String {
        switch rawState.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "running", "online", "connected":
            return "运行中"
        case "starting", "reloading":
            return "启动中"
        case "stopping":
            return "停止中"
        case "degraded":
            return "降级运行"
        case "error", "failed":
            return "异常"
        case "stopped", "idle", "offline", "":
            return "未连接"
        default:
            return rawState
        }
    }

    public static func outboundModeTitle(_ rawMode: String) -> String {
        switch rawMode.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "rule":
            return "规则"
        case "global":
            return "全局"
        case "direct":
            return "直连"
        default:
            return rawMode.isEmpty ? "规则" : rawMode
        }
    }

    public static func connectionInboundLabel(inbound: String, listener: Int) -> String {
        let trimmed = inbound.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty { return trimmed }
        return listener > 0 ? "入站 #\(listener)" : "本地入站"
    }

    public static func friendlyErrorMessage(_ error: Error) -> String {
        if let httpError = error as? HttpControlError {
            switch httpError {
            case .invalidURL:
                return "控制面地址格式无效，请检查设置"
            case .invalidResponse:
                return "控制面返回了无效响应"
            case .httpStatus(let code, _):
                switch code {
                case 401, 403:
                    return "访问凭据无效或已过期，请检查系统钥匙串中的访问密钥"
                case 404:
                    return "当前内核版本不支持该操作"
                case 500...599:
                    return "内核处理请求失败，请稍后重试"
                default:
                    return "请求未成功（状态码 \(code)）"
                }
            }
        }
        if let urlError = error as? URLError {
            switch urlError.code {
            case .cannotConnectToHost, .networkConnectionLost, .notConnectedToInternet:
                return "无法连接到内核服务，请确认内核已运行"
            case .timedOut:
                return "连接内核超时，请稍后重试"
            case .cancelled:
                return "操作已取消"
            default:
                return "网络通信异常，请稍后重试"
            }
        }
        let desc = error.localizedDescription.trimmingCharacters(in: .whitespacesAndNewlines)
        return desc.isEmpty ? "操作未能完成，请稍后重试" : desc
    }
}

/// Deterministic optimistic state-transition helper with monotonic generation tokens
/// guaranteeing exact rollback and rejecting stale responses from overlapping async calls.
public struct OptimisticTransition<Value: Equatable & Sendable>: Sendable, Equatable {
    public private(set) var current: Value
    public private(set) var pendingFrom: Value?
    public private(set) var generation: UInt64

    public init(initial: Value) {
        self.current = initial
        self.pendingFrom = nil
        self.generation = 0
    }

    @discardableResult
    public mutating func begin(to target: Value) -> (previous: Value, generation: UInt64) {
        let baseline = pendingFrom ?? current
        generation &+= 1
        pendingFrom = baseline
        current = target
        return (baseline, generation)
    }

    public mutating func syncConfirmed(_ confirmed: Value) {
        current = confirmed
        pendingFrom = nil
    }

    @discardableResult
    public mutating func commit(_ confirmed: Value, for token: UInt64? = nil) -> Bool {
        if let token, token != generation { return false }
        current = confirmed
        pendingFrom = nil
        return true
    }

    @discardableResult
    public mutating func rollback(for token: UInt64? = nil) -> Value? {
        if let token, token != generation { return nil }
        if let previous = pendingFrom {
            current = previous
        }
        pendingFrom = nil
        return current
    }
}

/// Normalizes a section raw value when transitioning an adaptive container into a compact tab bar
/// that displays a primary subset of sections, preventing untagged-tab stranding.
public enum CompactTabNormalizer {
    public static func normalize<Section: Equatable>(
        selected: Section,
        compactTabs: [Section],
        fallback: Section
    ) -> Section {
        compactTabs.contains(selected) ? selected : fallback
    }
}
