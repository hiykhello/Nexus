import Foundation
#if os(macOS) && canImport(ServiceManagement)
import ServiceManagement
#endif

public enum LoginItemStatus: String, Sendable, Equatable {
    case enabled
    case requiresApproval
    case notRegistered
    case notFound
    case unsupported

    public var summaryText: String {
        switch self {
        case .enabled: return "已启用开机自启"
        case .requiresApproval: return "请在系统设置中批准后台运行"
        case .notRegistered: return "未注册后台启动项"
        case .notFound: return "未找到主应用签名项"
        case .unsupported: return "当前平台不支持 SMAppService"
        }
    }
}

public enum LoginItemManager {
    public static func currentStatus() -> LoginItemStatus {
        #if os(macOS) && canImport(ServiceManagement)
        return mapStatus(SMAppService.mainApp.status)
        #else
        return .unsupported
        #endif
    }

    public static func register() throws {
        #if os(macOS) && canImport(ServiceManagement)
        try SMAppService.mainApp.register()
        #endif
    }

    public static func unregister() async throws {
        #if os(macOS) && canImport(ServiceManagement)
        try await SMAppService.mainApp.unregister()
        #endif
    }

    #if os(macOS) && canImport(ServiceManagement)
    public static func mapStatus(_ status: SMAppService.Status) -> LoginItemStatus {
        switch status {
        case .enabled: return .enabled
        case .requiresApproval: return .requiresApproval
        case .notRegistered: return .notRegistered
        case .notFound: return .notFound
        @unknown default: return .unsupported
        }
    }
    #endif
}
