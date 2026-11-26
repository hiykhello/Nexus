#if canImport(SwiftUI)
import Foundation
import SwiftUI

/// Idiomatic macOS/iOS share-link import modal wrapped in `NavigationStack` with
/// `.cancellationAction`/`.confirmationAction`, `@FocusState`, and keyboard shortcuts.
internal struct ShareLinkImportSheet: View {
    @Binding var shareLinkInput: String
    let onCancel: () -> Void
    let onImport: (String) -> Void
    @FocusState private var isLinkFieldFocused: Bool

    private var trimmedInput: String {
        shareLinkInput.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 12) {
                Text("支持 vless://、trojan://、anytls://、hy2://、tuic://、snell://、ss://、ssh://、naive+https://。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                TextField("粘贴分享链接…", text: $shareLinkInput)
                    .textFieldStyle(.roundedBorder)
                    .focused($isLinkFieldFocused)
                    .onSubmit {
                        if !trimmedInput.isEmpty { onImport(shareLinkInput) }
                    }
                    .accessibilityLabel("节点分享链接")
                Spacer(minLength: 0)
            }
            .padding()
            .navigationTitle("导入节点分享链接")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消", action: onCancel)
                        .keyboardShortcut(.cancelAction)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("解析并保存") {
                        onImport(shareLinkInput)
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(trimmedInput.isEmpty)
                }
            }
            .onAppear {
                isLinkFieldFocused = true
            }
        }
        #if os(macOS)
        .frame(minWidth: 440, minHeight: 190)
        #endif
    }
}
#endif
