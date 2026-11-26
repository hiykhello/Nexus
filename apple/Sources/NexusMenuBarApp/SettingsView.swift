#if os(macOS) || os(iOS)
import SwiftUI
import NexusCoreBridge
import NexusSharedUI

/// Cross-platform Settings screen (macOS Settings scene + Dashboard Settings tab + iOS Settings)
/// covering Login Item, System Proxy, TUN / `NEProxySettings`, Control API + Keychain Token, and Diagnostics.
struct SettingsView: View {
    @Bindable var model: NexusAppModel
    @State private var bearerTokenDraft: String = ""

    var body: some View {
        Form {
            localProxyAndLoginSection
            tunAndElevationSection
            controlApiAndKeychainSection
            diagnosticsAndAboutSection
        }
        .formStyle(.grouped)
        .task { await model.loadWorkspaceState() }
    }

    private var localProxyAndLoginSection: some View {
        Section("本地代理与系统启动") {
            Toggle("启用本地 Mixed 代理", isOn: $model.hostConfig.desktop.enableMixed)
            TextField("本地代理监听地址", text: $model.hostConfig.desktop.mixedListen)
                .font(.body.monospaced())
            #if os(macOS)
            LabeledContent("登录项状态", value: model.loginItemStatus.summaryText)
            #endif
            HStack {
                #if os(macOS)
                Button("注册开机自启") { model.registerLoginItem() }
                    .disabled(model.loginItemStatus == .enabled)
                Button("取消开机自启") {
                    Task { await model.unregisterLoginItem() }
                }
                .disabled(model.loginItemStatus != .enabled && model.loginItemStatus != .requiresApproval)
                #endif
                Spacer()
                Button("保存主机配置") {
                    Task { await model.saveHostConfig() }
                }
                .buttonStyle(.borderedProminent)
            }
        }
    }

    private var tunAndElevationSection: some View {
        Section("TUN 接管与 NEProxySettings") {
            Picker("接管形态", selection: $model.backend) {
                ForEach(AppleTunnelBackend.allCases, id: \.self) { item in
                    Text(item.rawValue).tag(item)
                }
            }
            Toggle("TUN 启用 HTTP 代理 (NEProxySettings)", isOn: $model.hostConfig.desktop.tunHttpProxyEnabled)
            if model.hostConfig.desktop.tunHttpProxyEnabled {
                let effective = AppleTunnelHttpProxyConfig.fromHostConfig(model.hostConfig)
                LabeledContent(
                    "代理目标",
                    value: effective.map { "\($0.host):\($0.port)" } ?? "请启用本地 Mixed 代理并填写合法 host:port"
                )
                .font(.caption.monospacedDigit())
            }

            Stepper(value: $model.hostConfig.workers, in: 1...64) {
                LabeledContent("核心并发线程 (workers)", value: "\(model.hostConfig.workers)")
                    .monospacedDigit()
            }
            TextField("并发规格 (workers_spec: auto / max / max-2)", text: $model.hostConfig.workersSpec)
                .font(.body.monospaced())

            #if os(macOS)
            Picker("TUN 提权策略", selection: $model.tunElevationMode) {
                ForEach(TunElevationMode.allCases) { mode in
                    Text(mode.displayName).tag(mode)
                }
            }
            Text(model.tunElevationMode.detailText)
                .font(.caption)
                .foregroundStyle(.secondary)

            if model.showDaemonManagementControls {
                LabeledContent("LaunchDaemon 状态", value: model.daemonState.summaryText)
                HStack {
                    if model.tunElevationMode == .persistentDaemon {
                        Button("注册 Daemon") { model.registerDaemon() }
                            .disabled(model.daemonState == .enabled)
                    }
                    Button("注销 Daemon") {
                        Task { await model.unregisterDaemon() }
                    }
                    .disabled(!model.daemonState.isRegisteredOrPending)
                }
            }
            #endif
        }
    }

    private var controlApiAndKeychainSection: some View {
        Section("控制面与 Keychain 鉴权") {
            TextField("HTTP 控制面地址", text: $model.hostConfig.controlHttpListen)
                .font(.body.monospaced())
                .accessibilityLabel("HTTP 控制面监听地址")
            LabeledContent("Keychain Bearer Token", value: model.hasStoredBearerToken ? "已安全存储" : "未配置")
            HStack(spacing: 8) {
                SecureField("输入新的控制面 Bearer Token...", text: $bearerTokenDraft)
                    .textFieldStyle(.roundedBorder)
                Button("存入 Keychain") {
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
            HStack {
                Button("测试连接") {
                    Task { await model.refreshStatus() }
                }
                Spacer()
                Button("保存配置") {
                    Task { await model.saveHostConfig() }
                }
                .buttonStyle(.borderedProminent)
            }
        }
    }

    private var diagnosticsAndAboutSection: some View {
        Section("诊断与关于") {
            LabeledContent("控制面端点", value: model.controlEndpoint)
                .font(.caption.monospaced())
            LabeledContent("SQLite 存储引擎", value: "WAL Schema v\(NexusClientDatabase.schemaVersion) (系统 libsqlite3)")
                .font(.caption.monospacedDigit())
            LabeledContent("授权 / 拒绝请求", value: "\(model.diagnostics.authorizedRequests) / \(model.diagnostics.unauthorizedRequests)")
                .font(.caption.monospacedDigit())
            LabeledContent("常驻内存", value: String(format: "%.1f MiB", model.residentMemoryMiB))
                .font(.caption.monospacedDigit())
            HStack {
                Button("回收 SQLite 内存") {
                    Task { await model.compactDatabase() }
                }
                Spacer()
                Text("Nexus Apple · Swift 6 + SwiftUI")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
#endif
