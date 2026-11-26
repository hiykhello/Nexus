#if os(macOS) || os(iOS)
import Foundation
import SwiftUI
import NexusCoreBridge
import NexusSharedUI

/// Cross-platform Settings screen using native `.formStyle(.grouped)`, unified save action,
/// plain user-facing copy, and a collapsed `"高级与诊断"` DisclosureGroup.
struct SettingsView: View {
    @Bindable var model: NexusAppModel
    @State private var bearerTokenDraft: String = ""
    @State private var showAdvancedDiagnostics: Bool = false
    @Environment(\.nexusTheme) private var theme

    var body: some View {
        Form {
            appearanceThemeSection
            localProxyAndLoginSection
            tunAndElevationSection
            controlApiAndKeychainSection
            #if os(macOS)
            keyboardShortcutsSection
            #endif
            storageAndAboutSection
            advancedDiagnosticsSection
        }
        .formStyle(.grouped)
        .scrollContentBackground(.hidden)
        .background(theme.canvasBackground)
        .safeAreaInset(edge: .bottom) {
            saveFooterBar
        }
        .task { await model.loadWorkspaceState() }
    }

    private var appearanceThemeSection: some View {
        Section("外观与仪表主题") {
            ThemeSwatchPickerView(selected: model.themePreset) { preset in
                model.setThemePreset(preset)
            }
            Text(model.themePreset.subtitle)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    #if os(macOS)
    private var keyboardShortcutsSection: some View {
        Section("快捷键") {
            LabeledContent("命令与域名诊断", value: "⌘K")
                .font(.caption.monospaced())
            LabeledContent("页内查找筛选", value: "⌘F")
                .font(.caption.monospaced())
            LabeledContent("热重载生效配置", value: "⌘R")
                .font(.caption.monospaced())
            LabeledContent("切换功能区", value: "⌘1 – ⌘6")
                .font(.caption.monospaced())
        }
    }
    #endif

    private var saveFooterBar: some View {
        VStack(spacing: 0) {
            Divider()
            HStack(spacing: 10) {
                if let err = model.actionErrorMessage, !err.isEmpty {
                    Label(err, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(theme.warning)
                        .lineLimit(1)
                } else {
                    Text(model.statusSummary)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer(minLength: 8)
                Button("测试连接") {
                    Task { await model.refreshStatus() }
                }
                .buttonStyle(.bordered)
                #if os(iOS)
                .frame(minHeight: 44)
                #endif
                Button("保存设置") {
                    Task { await model.saveHostConfig() }
                }
                .buttonStyle(NexusProminentButtonStyle())
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
        }
        .background(theme.chassisBackground)
    }

    private var localProxyAndLoginSection: some View {
        Section("本地代理与系统启动") {
            Toggle("启用本地混合代理", isOn: $model.hostConfig.desktop.enableMixed)
            TextField("本地代理监听地址", text: $model.hostConfig.desktop.mixedListen)
                .font(.body.monospaced())
            #if os(macOS)
            LabeledContent("登录项状态", value: model.loginItemStatus.summaryText)
            HStack {
                Button("注册开机自启") { model.registerLoginItem() }
                    .disabled(model.loginItemStatus == .enabled)
                Button("取消开机自启") {
                    Task { await model.unregisterLoginItem() }
                }
                .disabled(model.loginItemStatus != .enabled && model.loginItemStatus != .requiresApproval)
            }
            #endif
        }
    }

    private var tunAndElevationSection: some View {
        Section("虚拟网卡与系统代理") {
            Picker("接管方式", selection: $model.backend) {
                ForEach(AppleTunnelBackend.allCases, id: \.self) { item in
                    Text(item.displayName).tag(item)
                }
            }
            Toggle("隧道内启用系统 HTTP 代理", isOn: $model.hostConfig.desktop.tunHttpProxyEnabled)
            if model.hostConfig.desktop.tunHttpProxyEnabled {
                let effective = AppleTunnelHttpProxyConfig.fromHostConfig(model.hostConfig)
                LabeledContent(
                    "代理目标",
                    value: effective.map { "\($0.host):\($0.port)" } ?? "请启用本地混合代理并填写合法地址与端口"
                )
                .font(.caption.monospacedDigit())
            }

            Stepper(value: $model.hostConfig.workers, in: 1...64) {
                LabeledContent("内核并发线程数", value: "\(model.hostConfig.workers)")
                    .monospacedDigit()
            }

            #if os(macOS)
            Picker("虚拟网卡授权方式", selection: $model.tunElevationMode) {
                ForEach(TunElevationMode.allCases) { mode in
                    Text(mode.displayName).tag(mode)
                }
            }
            Text(model.tunElevationMode.detailText)
                .font(.caption)
                .foregroundStyle(.secondary)

            if model.showDaemonManagementControls {
                LabeledContent("后台权限服务状态", value: model.daemonState.summaryText)
                HStack {
                    if model.tunElevationMode == .persistentDaemon {
                        Button("启用后台服务") { model.registerDaemon() }
                            .disabled(model.daemonState == .enabled)
                    }
                    Button("停用后台服务") {
                        Task { await model.unregisterDaemon() }
                    }
                    .disabled(!model.daemonState.isRegisteredOrPending)
                }
            }
            #endif
        }
    }

    private var controlApiAndKeychainSection: some View {
        Section("控制面访问安全") {
            TextField("控制面监听地址", text: $model.hostConfig.controlHttpListen)
                .font(.body.monospaced())
                .accessibilityLabel("控制面监听地址")
            LabeledContent("访问密钥（系统钥匙串）", value: model.hasStoredBearerToken ? "已安全存储" : "未配置")
            HStack(spacing: 8) {
                SecureField("输入新的访问密钥…", text: $bearerTokenDraft)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit {
                        let trimmed = bearerTokenDraft.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard !trimmed.isEmpty else { return }
                        model.saveBearerToken(trimmed)
                        bearerTokenDraft = ""
                    }
                Button("保存密钥") {
                    model.saveBearerToken(bearerTokenDraft)
                    bearerTokenDraft = ""
                }
                .disabled(bearerTokenDraft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                if model.hasStoredBearerToken {
                    Button("清除", role: .destructive) {
                        model.clearBearerToken()
                    }
                }
            }
        }
    }

    private var storageAndAboutSection: some View {
        Section("存储与关于") {
            LabeledContent("本地存储", value: "应用容器自动管理")
                .font(.caption)
            LabeledContent("应用内存", value: String(format: "%.1f MiB", model.residentMemoryMiB))
                .font(.caption.monospacedDigit())
            HStack {
                Button("回收本地存储内存") {
                    Task { await model.compactDatabase() }
                }
                Spacer()
                Text("Nexus \(NexusAppModel.appVersionLabel)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var advancedDiagnosticsSection: some View {
        Section {
            DisclosureGroup("高级与诊断", isExpanded: $showAdvancedDiagnostics) {
                TextField("高级并发策略（如 auto / max / max-2）", text: $model.hostConfig.workersSpec)
                    .font(.body.monospaced())
                LabeledContent("控制面端点", value: model.controlEndpoint)
                    .font(.caption.monospaced())
                LabeledContent("配置重载序号", value: "#\(model.metrics.controlGeneration)")
                    .font(.caption.monospacedDigit())
                LabeledContent(
                    "已授权 / 已拒绝请求",
                    value: "\(model.diagnostics.authorizedRequests) / \(model.diagnostics.unauthorizedRequests)"
                )
                .font(.caption.monospacedDigit())
            }
        }
    }
}
#endif
