#if canImport(SwiftUI)
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
        Color.primary.opacity(0.04)
    }

    public static var hairlineBorder: Color {
        Color.primary.opacity(0.09)
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

public struct BentoCardModifier: ViewModifier {
    private let padding: CGFloat
    private let cornerRadius: CGFloat

    public init(padding: CGFloat = 14, cornerRadius: CGFloat = 12) {
        self.padding = padding
        self.cornerRadius = cornerRadius
    }

    public func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        content
            .padding(padding)
            .background(NexusPalette.cardSurface)
            .overlay(shape.strokeBorder(NexusPalette.hairlineBorder, lineWidth: 1))
            .compositingGroup()
            .clipShape(shape)
    }
}

public extension View {
    func bentoCard(padding: CGFloat = 14, cornerRadius: CGFloat = 12) -> some View {
        modifier(BentoCardModifier(padding: padding, cornerRadius: cornerRadius))
    }
}

/// Color-coded latency badge with monospaced digits and VoiceOver description.
public struct RttPillView: View {
    public let latencyMs: Int64?
    public let state: String

    public init(latencyMs: Int64?, state: String = "up") {
        self.latencyMs = latencyMs
        self.state = state
    }

    private var labelText: String {
        if let ms = latencyMs, ms >= 0 { return "\(ms) ms" }
        return state.isEmpty ? "—" : state
    }

    public var body: some View {
        let tint = NexusPalette.rttColor(latencyMs: latencyMs, state: state)
        Text(labelText)
            .font(.caption.weight(.semibold).monospacedDigit())
            .foregroundStyle(tint)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(tint.opacity(0.12), in: Capsule())
            .accessibilityLabel("延迟 \(labelText)")
    }
}

/// Live connection/core status capsule.
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

/// Lightweight dual RX/TX throughput sparkline using native SwiftUI `Canvas`.
public struct ThroughputSparklineView: View {
    public let rxSamples: [Double]
    public let txSamples: [Double]

    public init(rxSamples: [Double], txSamples: [Double]) {
        self.rxSamples = rxSamples
        self.txSamples = txSamples
    }

    public var body: some View {
        Canvas { context, size in
            let maxVal = max(1024.0, (rxSamples + txSamples).max() ?? 1024.0)
            drawSeries(rxSamples, maxVal: maxVal, color: .blue, in: &context, size: size, fill: true)
            drawSeries(txSamples, maxVal: maxVal, color: .green, in: &context, size: size, fill: false)
        }
        .frame(height: 54)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("实时上下行速率折线图")
    }

    private func drawSeries(
        _ samples: [Double],
        maxVal: Double,
        color: Color,
        in context: inout GraphicsContext,
        size: CGSize,
        fill: Bool
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
        context.stroke(strokePath, with: .color(color), style: StrokeStyle(lineWidth: 1.8, lineCap: .round, lineJoin: .round))
    }
}
#endif
