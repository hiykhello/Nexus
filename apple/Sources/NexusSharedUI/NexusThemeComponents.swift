#if canImport(SwiftUI)
import Foundation
import SwiftUI
#if os(macOS)
import AppKit
#elseif canImport(UIKit)
import UIKit
#endif

/// Pure byte and transfer-rate formatters (zero formatter object allocations in SwiftUI `body`).
public enum NexusByteFormat {
    public static func bytes(_ count: UInt64) -> String {
        let kb = 1024.0
        let mb = kb * 1024.0
        let gb = mb * 1024.0
        let value = Double(count)
        if value >= gb { return String(format: "%.2f GiB", value / gb) }
        if value >= mb { return String(format: "%.1f MiB", value / mb) }
        if value >= kb { return String(format: "%.1f KiB", value / kb) }
        return "\(count) B"
    }

    public static func rate(_ bytesPerSecond: Double) -> String {
        let clamped = max(0, bytesPerSecond)
        let kb = 1024.0
        let mb = kb * 1024.0
        if clamped >= mb { return String(format: "%.2f MiB/s", clamped / mb) }
        if clamped >= kb { return String(format: "%.1f KiB/s", clamped / kb) }
        return String(format: "%.0f B/s", clamped)
    }

    @MainActor
    public static func copyToClipboard(_ text: String) {
        #if os(macOS)
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(text, forType: .string)
        #elseif canImport(UIKit)
        UIPasteboard.general.string = text
        #endif
    }
}

/// Adaptive semantic system palette honoring Light/Dark Mode and Increased Contrast.
public enum NexusPalette {
    public static var cardSurface: Color {
        #if os(macOS)
        Color(nsColor: .controlBackgroundColor)
        #elseif canImport(UIKit)
        Color(uiColor: .secondarySystemGroupedBackground)
        #else
        Color.secondary.opacity(0.08)
        #endif
    }

    public static var subtleSurface: Color {
        #if os(macOS)
        Color(nsColor: .quaternaryLabelColor).opacity(0.35)
        #elseif canImport(UIKit)
        Color(uiColor: .tertiarySystemFill)
        #else
        Color.primary.opacity(0.06)
        #endif
    }

    public static var hairlineBorder: Color {
        hairlineBorder(increasedContrast: false)
    }

    public static func hairlineBorder(increasedContrast: Bool) -> Color {
        #if os(macOS)
        return increasedContrast
            ? Color(nsColor: .secondaryLabelColor).opacity(0.65)
            : Color(nsColor: .separatorColor)
        #elseif canImport(UIKit)
        return increasedContrast
            ? Color(uiColor: .secondaryLabel).opacity(0.65)
            : Color(uiColor: .separator)
        #else
        return Color.primary.opacity(increasedContrast ? 0.35 : 0.14)
        #endif
    }

    public static func rttColor(latencyMs: Int64?, state: String) -> Color {
        let lower = state.lowercased()
        if lower == "down" || lower == "failed" || lower == "error" || lower == "timeout" {
            return .red
        }
        guard let ms = latencyMs, ms >= 0 else { return .secondary }
        if ms < 120 { return .green }
        if ms < 300 { return .orange }
        return .red
    }

    public static func rttSymbol(latencyMs: Int64?, state: String) -> String {
        let lower = state.lowercased()
        if lower == "down" || lower == "failed" || lower == "error" || lower == "timeout" {
            return "xmark.circle.fill"
        }
        guard let ms = latencyMs, ms >= 0 else { return "minus.circle" }
        if ms < 120 { return "checkmark.circle.fill" }
        if ms < 300 { return "exclamationmark.triangle.fill" }
        return "xmark.octagon.fill"
    }

    public static func logLevelColor(_ level: String) -> Color {
        switch level.lowercased() {
        case "error", "fatal": return .red
        case "warn", "warning": return .orange
        case "info": return .blue
        case "debug": return .purple
        default: return .secondary
        }
    }
}

/// Matte flat card modifier with Increased Contrast border adaptation and zero `.compositingGroup()` overhead.
public struct BentoCardModifier: ViewModifier {
    private let padding: CGFloat
    private let cornerRadius: CGFloat
    @Environment(\.colorSchemeContrast) private var contrast

    public init(padding: CGFloat = 12, cornerRadius: CGFloat = 14) {
        self.padding = padding
        self.cornerRadius = cornerRadius
    }

    public func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        let increased = contrast == .increased
        content
            .padding(padding)
            .background(NexusPalette.cardSurface, in: shape)
            .overlay(
                shape.strokeBorder(
                    NexusPalette.hairlineBorder(increasedContrast: increased),
                    lineWidth: increased ? 1.25 : 1
                )
            )
    }
}

public extension View {
    func bentoCard(padding: CGFloat = 12, cornerRadius: CGFloat = 14) -> some View {
        modifier(BentoCardModifier(padding: padding, cornerRadius: cornerRadius))
    }

    @ViewBuilder
    func nexusTooltip(_ text: String) -> some View {
        #if os(macOS)
        self.help(text)
        #else
        self
        #endif
    }
}

/// Tactile, Reduce-Motion-aware button style for filter & group pills with pointer-down press feedback,
/// subtle macOS hover tint, and >= 44pt iOS touch targets.
public struct NexusPillButtonStyle: ButtonStyle {
    public init() {}

    public func makeBody(configuration: Configuration) -> some View {
        NexusPillButtonBody(configuration: configuration)
    }
}

private struct NexusPillButtonBody: View {
    let configuration: ButtonStyleConfiguration
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    #if os(macOS)
    @State private var isHovered = false
    #endif

    var body: some View {
        configuration.label
            #if os(macOS)
            .background(isHovered ? NexusPalette.subtleSurface : Color.clear, in: Capsule())
            .onHover { isHovered = $0 }
            #elseif os(iOS)
            .frame(minHeight: 44)
            .contentShape(Rectangle())
            #endif
            .scaleEffect((!reduceMotion && configuration.isPressed) ? 0.97 : 1.0)
            .opacity(configuration.isPressed ? 0.85 : 1.0)
            .animation(reduceMotion ? nil : .easeOut(duration: 0.11), value: configuration.isPressed)
    }
}

/// Defers `ProgressView` display by ~250ms so sub-250ms local probes and DNS queries never flash a spinner.
public struct DeferredSpinnerView: View {
    public let isActive: Bool
    public let delayMilliseconds: Int
    @State private var visible = false

    public init(isActive: Bool, delayMilliseconds: Int = 250) {
        self.isActive = isActive
        self.delayMilliseconds = delayMilliseconds
    }

    public var body: some View {
        Group {
            if visible {
                ProgressView()
                    .controlSize(.small)
            }
        }
        .task(id: isActive) {
            guard isActive else {
                visible = false
                return
            }
            try? await Task.sleep(for: .milliseconds(delayMilliseconds))
            guard !Task.isCancelled else { return }
            visible = true
        }
    }
}

/// Fixed-minWidth, right-aligned live numeric label preventing 1Hz horizontal layout jitter.
public struct LiveRateLabel: View {
    public let text: String
    public let systemImage: String
    public let tint: Color
    @ScaledMetric(relativeTo: .caption) private var minSlotWidth: CGFloat = 82

    public init(text: String, systemImage: String, tint: Color) {
        self.text = text
        self.systemImage = systemImage
        self.tint = tint
    }

    public var body: some View {
        HStack(spacing: 4) {
            Image(systemName: systemImage)
                .accessibilityHidden(true)
            Text(text)
                .monospacedDigit()
                .lineLimit(1)
                .minimumScaleFactor(0.85)
                .frame(minWidth: minSlotWidth, alignment: .trailing)
        }
        .font(.caption.weight(.medium))
        .foregroundStyle(tint)
        .accessibilityElement(children: .combine)
    }
}

/// Latency badge combining semantic color, non-color SF Symbol, and monospaced digits for WCAG AA accessibility.
public struct RttPillView: View {
    public let latencyMs: Int64?
    public let state: String

    public init(latencyMs: Int64?, state: String = "up") {
        self.latencyMs = latencyMs
        self.state = state
    }

    private var labelText: String {
        if let ms = latencyMs, ms >= 0 { return "\(ms) ms" }
        switch state.lowercased() {
        case "down", "failed", "error", "timeout": return "超时"
        case "idle", "": return "—"
        default: return state
        }
    }

    public var body: some View {
        let tint = NexusPalette.rttColor(latencyMs: latencyMs, state: state)
        let symbol = NexusPalette.rttSymbol(latencyMs: latencyMs, state: state)
        HStack(spacing: 4) {
            Image(systemName: symbol)
                .font(.caption2)
                .accessibilityHidden(true)
            Text(labelText)
                .font(.caption.weight(.semibold).monospacedDigit())
        }
        .foregroundStyle(tint)
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(tint.opacity(0.12), in: Capsule())
        .accessibilityElement(children: .combine)
        .accessibilityLabel("延迟 \(labelText)")
    }
}

/// Shared dismissible error banner with optional retry CTA, supporting both standalone
/// shell placement and flush hairline-separated placement inside a parent card.
public struct ActionErrorBanner: View {
    public let message: String
    public let flush: Bool
    public let onRetry: (() -> Void)?
    public let onDismiss: () -> Void

    public init(
        message: String,
        flush: Bool = false,
        onRetry: (() -> Void)? = nil,
        onDismiss: @escaping () -> Void
    ) {
        self.message = message
        self.flush = flush
        self.onRetry = onRetry
        self.onDismiss = onDismiss
    }

    public var body: some View {
        let row = HStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            Text(message)
                .font(.caption)
                .foregroundStyle(.primary)
                .lineLimit(2)
            Spacer(minLength: 4)
            if let onRetry {
                Button("重试", action: onRetry)
                    .buttonStyle(.bordered)
                    .controlSize(.small)
            }
            Button(action: onDismiss) {
                Image(systemName: "xmark")
                    .font(.caption2.weight(.semibold))
            }
            .buttonStyle(.borderless)
            .accessibilityLabel("关闭错误提示")
        }
        if flush {
            VStack(alignment: .leading, spacing: 8) {
                Divider()
                row
            }
        } else {
            row
                .padding(.horizontal, 10)
                .padding(.vertical, 8)
                .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        }
    }
}

/// Live connection/core status capsule with icon dot + label.
public struct StatusBadgeView: View {
    public let isOnline: Bool
    public let label: String

    public init(isOnline: Bool, label: String) {
        self.isOnline = isOnline
        self.label = label
    }

    public var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(isOnline ? Color.green : Color.secondary)
                .frame(width: 8, height: 8)
                .accessibilityHidden(true)
            Text(label)
                .font(.caption.weight(.semibold))
        }
        .foregroundStyle(isOnline ? Color.green : Color.secondary)
        .padding(.horizontal, 9)
        .padding(.vertical, 4)
        .background((isOnline ? Color.green : Color.secondary).opacity(0.12), in: Capsule())
        .accessibilityElement(children: .combine)
    }
}

/// Lightweight dual RX/TX throughput sparkline using native SwiftUI `Canvas` with
/// peak scale caption, dashed TX vs solid+fill RX distinction, and full VoiceOver readout.
public struct ThroughputSparklineView: View {
    public let rxSamples: [Double]
    public let txSamples: [Double]

    public init(rxSamples: [Double], txSamples: [Double]) {
        self.rxSamples = rxSamples
        self.txSamples = txSamples
    }

    private var peakValue: Double {
        max(1024.0, (rxSamples + txSamples).max() ?? 1024.0)
    }

    public var body: some View {
        let maxVal = peakValue
        ZStack(alignment: .topTrailing) {
            Canvas { context, size in
                drawSeries(rxSamples, maxVal: maxVal, color: .blue, in: &context, size: size, fill: true, dashed: false)
                drawSeries(txSamples, maxVal: maxVal, color: .green, in: &context, size: size, fill: false, dashed: true)
            }
            .frame(height: 54)

            Text("峰值 \(NexusByteFormat.rate(maxVal))")
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.secondary)
                .padding(.horizontal, 4)
                .padding(.vertical, 1)
                .allowsHitTesting(false)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("实时上下行速率折线图")
        .accessibilityValue(
            "下行 \(NexusByteFormat.rate(rxSamples.last ?? 0))，上行 \(NexusByteFormat.rate(txSamples.last ?? 0))，峰值 \(NexusByteFormat.rate(maxVal))"
        )
    }

    private func drawSeries(
        _ samples: [Double],
        maxVal: Double,
        color: Color,
        in context: inout GraphicsContext,
        size: CGSize,
        fill: Bool,
        dashed: Bool
    ) {
        guard samples.count >= 2, size.width > 4, size.height > 4 else { return }
        let stepX = size.width / CGFloat(samples.count - 1)
        var strokePath = Path()
        for (idx, sample) in samples.enumerated() {
            let x = CGFloat(idx) * stepX
            let ratio = min(1.0, max(0.0, sample / maxVal))
            let y = size.height - CGFloat(ratio) * (size.height - 6) - 3
            if idx == 0 {
                strokePath.move(to: CGPoint(x: x, y: y))
            } else {
                strokePath.addLine(to: CGPoint(x: x, y: y))
            }
        }
        if fill {
            var fillPath = strokePath
            fillPath.addLine(to: CGPoint(x: size.width, y: size.height))
            fillPath.addLine(to: CGPoint(x: 0, y: size.height))
            fillPath.closeSubpath()
            context.fill(fillPath, with: .color(color.opacity(0.12)))
        }
        let style = StrokeStyle(
            lineWidth: 1.8,
            lineCap: .round,
            lineJoin: .round,
            dash: dashed ? [4, 3] : []
        )
        context.stroke(strokePath, with: .color(color), style: style)
    }
}
#endif
