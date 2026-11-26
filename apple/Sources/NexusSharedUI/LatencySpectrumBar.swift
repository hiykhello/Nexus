#if canImport(SwiftUI)
import Foundation
import SwiftUI
import NexusCoreBridge

/// Proportional 5-tier latency spectrum capsule bar (`3pt` standard / `2pt` mini) rendered with
/// `Canvas` at `0ms` update latency (`gui-flagship-spec.md` §4.2).
public struct LatencySpectrumBar: View {
    public let summary: GroupLatencySummary
    public let barHeight: CGFloat
    @Environment(\.nexusTheme) private var theme

    public init(summary: GroupLatencySummary, barHeight: CGFloat = 3) {
        self.summary = summary
        self.barHeight = barHeight
    }

    public var body: some View {
        let slowColor = Color(red: 0.94, green: 0.44, blue: 0.24)
        Canvas { context, size in
            let total = max(1, summary.totalCount)
            let segments: [(Int, Color)] = [
                (summary.fastCount, theme.signalEmeraldFill),
                (summary.goodCount, theme.rxLine),
                (summary.midCount, theme.warning),
                (summary.slowCount, slowColor),
                (summary.timeoutCount, theme.danger),
                (summary.unprobedCount, theme.hairlineBorder),
            ]
            var cursorX: CGFloat = 0
            for (count, color) in segments where count > 0 {
                let w = size.width * CGFloat(count) / CGFloat(total)
                let rect = CGRect(x: cursorX, y: 0, width: max(1.0, w), height: size.height)
                context.fill(Path(rect), with: .color(color))
                cursorX += w
            }
            if cursorX == 0 {
                let rect = CGRect(x: 0, y: 0, width: size.width, height: size.height)
                context.fill(Path(rect), with: .color(theme.hairlineBorder))
            }
        }
        .frame(height: barHeight)
        .clipShape(Capsule())
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(accessibilitySummaryText)
    }

    private var accessibilitySummaryText: String {
        if let p50 = summary.p50Ms {
            return "延迟光谱：可用 \(summary.healthyCount) / \(summary.totalCount)，中位数 \(p50) 毫秒"
        }
        return "延迟光谱：可用 \(summary.healthyCount) / \(summary.totalCount)，暂无测速数据"
    }
}

/// Whisper-quiet flat proportional background meter behind healthy `ProxyNodeCard`s
/// (`latency / groupMaxHealthy`, dark `0.075` / light `0.055`, zero gradients/blur).
public struct RelativeLatencyMeterBackground: View {
    public let ratio: Double?
    public let tint: Color
    @Environment(\.nexusTheme) private var theme

    public init(ratio: Double?, tint: Color) {
        self.ratio = ratio
        self.tint = tint
    }

    public var body: some View {
        GeometryReader { geo in
            if let ratio, ratio > 0, geo.size.width > 0 {
                Rectangle()
                    .fill(tint.opacity(theme.meterOpacity))
                    .frame(width: geo.size.width * CGFloat(min(1.0, max(0.0, ratio))))
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
            }
        }
        .allowsHitTesting(false)
    }
}

/// `2pt` dual-tone relative traffic share micro-bar (download Indigo/RX + upload Signal Emerald)
/// scaled against the heaviest active connection (`gui-flagship-spec.md` §5).
public struct TrafficShareMicroBar: View {
    public let uploadBytes: UInt64
    public let downloadBytes: UInt64
    public let maxTotalBytes: UInt64
    @Environment(\.nexusTheme) private var theme

    public init(uploadBytes: UInt64, downloadBytes: UInt64, maxTotalBytes: UInt64) {
        self.uploadBytes = uploadBytes
        self.downloadBytes = downloadBytes
        self.maxTotalBytes = max(1, maxTotalBytes)
    }

    public var body: some View {
        Canvas { context, size in
            let bgRect = CGRect(x: 0, y: 0, width: size.width, height: size.height)
            context.fill(Path(bgRect), with: .color(theme.wellSurface))

            let total = uploadBytes &+ downloadBytes
            guard total > 0 else { return }
            let scale = min(1.0, Double(total) / Double(maxTotalBytes))
            let filledWidth = max(2.0, size.width * CGFloat(scale))
            let downRatio = Double(downloadBytes) / Double(total)
            let downWidth = filledWidth * CGFloat(downRatio)
            let upWidth = filledWidth - downWidth

            if downWidth > 0.5 {
                context.fill(
                    Path(CGRect(x: 0, y: 0, width: downWidth, height: size.height)),
                    with: .color(theme.rxLine)
                )
            }
            if upWidth > 0.5 {
                context.fill(
                    Path(CGRect(x: downWidth, y: 0, width: upWidth, height: size.height)),
                    with: .color(theme.signalEmeraldFill)
                )
            }
        }
        .frame(height: 2)
        .clipShape(Capsule())
        .accessibilityHidden(true)
    }
}

/// Lightweight dual RX/TX throughput sparkline using native SwiftUI `Canvas` with
/// 50% midline, peak scale caption, dashed TX vs solid+fill RX distinction, onset markers,
/// and full VoiceOver readout.
public struct ThroughputSparklineView: View {
    public let rxSamples: [Double]
    public let txSamples: [Double]
    public let onsetMarkers: [SparklineOnsetMarker]
    @Environment(\.nexusTheme) private var theme

    public init(
        rxSamples: [Double],
        txSamples: [Double],
        onsetMarkers: [SparklineOnsetMarker] = []
    ) {
        self.rxSamples = rxSamples
        self.txSamples = txSamples
        self.onsetMarkers = onsetMarkers
    }

    private var peakValue: Double {
        max(1024.0, (rxSamples + txSamples).max() ?? 1024.0)
    }

    public var body: some View {
        let maxVal = peakValue
        let count = max(rxSamples.count, txSamples.count)
        let latestOnset = onsetMarkers.last?.label
        ZStack(alignment: .topTrailing) {
            Canvas { context, size in
                let midY = size.height * 0.5
                var midPath = Path()
                midPath.move(to: CGPoint(x: 0, y: midY))
                midPath.addLine(to: CGPoint(x: size.width, y: midY))
                context.stroke(
                    midPath,
                    with: .color(theme.hairlineBorder.opacity(0.65)),
                    style: StrokeStyle(lineWidth: 0.75, dash: [3, 3])
                )

                drawSeries(rxSamples, maxVal: maxVal, color: theme.rxLine, in: &context, size: size, fill: true, dashed: false)
                drawSeries(txSamples, maxVal: maxVal, color: theme.txLine, in: &context, size: size, fill: false, dashed: true)
                drawOnsets(count: count, in: &context, size: size)
            }
            .frame(height: 54)

            HStack(spacing: 6) {
                if let latestOnset, !latestOnset.isEmpty {
                    Text("◆ \(latestOnset)")
                        .font(.caption2.weight(.medium))
                        .foregroundStyle(theme.accentText)
                }
                Text("峰值 \(NexusByteFormat.rate(maxVal))")
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 4)
            .padding(.vertical, 1)
            .allowsHitTesting(false)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("实时上下行速率折线图")
        .accessibilityValue(accessibilitySummary(maxVal: maxVal))
    }

    private func accessibilitySummary(maxVal: Double) -> String {
        let base = "下行 \(NexusByteFormat.rate(rxSamples.last ?? 0))，上行 \(NexusByteFormat.rate(txSamples.last ?? 0))，峰值 \(NexusByteFormat.rate(maxVal))"
        if let latest = onsetMarkers.last?.label, !latest.isEmpty {
            return "\(base)，最近切换事件 \(latest)"
        }
        return base
    }

    private func drawOnsets(count: Int, in context: inout GraphicsContext, size: CGSize) {
        guard count >= 2, size.width > 8 else { return }
        let stepX = size.width / CGFloat(count - 1)
        for marker in onsetMarkers where marker.sampleIndex >= 0 && marker.sampleIndex < count {
            let x = CGFloat(marker.sampleIndex) * stepX
            var tick = Path()
            tick.move(to: CGPoint(x: x, y: 6))
            tick.addLine(to: CGPoint(x: x, y: size.height - 2))
            context.stroke(
                tick,
                with: .color(theme.accentText.opacity(0.75)),
                style: StrokeStyle(lineWidth: 1, dash: [2, 2])
            )
            var diamond = Path()
            diamond.move(to: CGPoint(x: x, y: 2))
            diamond.addLine(to: CGPoint(x: x + 2.5, y: 4.5))
            diamond.addLine(to: CGPoint(x: x, y: 7))
            diamond.addLine(to: CGPoint(x: x - 2.5, y: 4.5))
            diamond.closeSubpath()
            context.fill(diamond, with: .color(theme.accentText))
        }
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
