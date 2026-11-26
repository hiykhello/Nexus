#if canImport(SwiftUI)
import Foundation
import SwiftUI
import NexusCoreBridge

/// WCAG 2.1 AA verified (`>= 4.5:1`) matte instrument color tokens for Apple macOS 14 / iOS 17
/// (`gui-flagship-spec.md` §1.2). Strictly `Sendable` with zero closures.
public struct NexusThemeTokens: Sendable, Equatable {
    public let preset: NexusThemePreset
    public let isDark: Bool
    public let chassisBackground: Color
    public let canvasBackground: Color
    public let cardSurface: Color
    public let wellSurface: Color
    public let hoverSurface: Color
    public let hairlineBorder: Color
    public let strongBorder: Color
    public let primaryInk: Color
    public let secondaryInk: Color
    public let accentFill: Color
    public let accentFillInk: Color
    public let accentText: Color
    public let signalEmerald: Color
    public let signalEmeraldFill: Color
    public let warning: Color
    public let danger: Color
    public let rxLine: Color
    public let txLine: Color

    public var meterOpacity: Double { isDark ? 0.075 : 0.055 }

    /// WCAG AA verified 5-tier RTT semantic tint aligned with `GroupLatencySummary`
    /// (`< 80 ms` fast, `< 180 ms` good, `< 350 ms` mid, `>= 350 ms` slow/timeout).
    public func rttColor(latencyMs: Int64?, state: String) -> Color {
        let lower = state.lowercased()
        if lower == "down" || lower == "failed" || lower == "error" || lower == "timeout" {
            return danger
        }
        guard let ms = latencyMs, ms >= 0 else { return secondaryInk }
        if ms < 80 { return signalEmerald }
        if ms < 180 { return rxLine }
        if ms < 350 { return warning }
        return danger
    }

    /// WCAG AA verified log severity tint honoring the active instrument theme.
    public func logLevelColor(_ level: String) -> Color {
        switch level.lowercased() {
        case "error", "fatal": return danger
        case "warn", "warning": return warning
        case "info": return rxLine
        case "debug": return txLine
        default: return secondaryInk
        }
    }

    public static func obsidian(increasedContrast: Bool) -> NexusThemeTokens {
        NexusThemeTokens(
            preset: .obsidian,
            isDark: true,
            chassisBackground: Color(red: 0x0D / 255.0, green: 0x0F / 255.0, blue: 0x13 / 255.0),
            canvasBackground: Color(red: 0x12 / 255.0, green: 0x15 / 255.0, blue: 0x1B / 255.0),
            cardSurface: Color(red: 0x19 / 255.0, green: 0x1D / 255.0, blue: 0x25 / 255.0),
            wellSurface: Color(red: 0x20 / 255.0, green: 0x25 / 255.0, blue: 0x30 / 255.0),
            hoverSurface: Color(red: 0x25 / 255.0, green: 0x2A / 255.0, blue: 0x35 / 255.0),
            hairlineBorder: increasedContrast
                ? Color(red: 0x6C / 255.0, green: 0x76 / 255.0, blue: 0x8B / 255.0)
                : Color(red: 0x2A / 255.0, green: 0x30 / 255.0, blue: 0x3E / 255.0),
            strongBorder: Color(red: 0x6C / 255.0, green: 0x76 / 255.0, blue: 0x8B / 255.0),
            primaryInk: Color(red: 0xED / 255.0, green: 0xF0 / 255.0, blue: 0xF5 / 255.0),
            secondaryInk: Color(red: 0x9B / 255.0, green: 0xA4 / 255.0, blue: 0xB5 / 255.0),
            accentFill: Color(red: 0x3B / 255.0, green: 0x57 / 255.0, blue: 0xE0 / 255.0),
            accentFillInk: Color.white,
            accentText: Color(red: 0x7C / 255.0, green: 0x96 / 255.0, blue: 0xFF / 255.0),
            signalEmerald: Color(red: 0x34 / 255.0, green: 0xD3 / 255.0, blue: 0x99 / 255.0),
            signalEmeraldFill: Color(red: 0x10 / 255.0, green: 0xB9 / 255.0, blue: 0x81 / 255.0),
            warning: Color(red: 0xFB / 255.0, green: 0xBF / 255.0, blue: 0x24 / 255.0),
            danger: Color(red: 0xF8 / 255.0, green: 0x71 / 255.0, blue: 0x71 / 255.0),
            rxLine: Color(red: 0x38 / 255.0, green: 0xBD / 255.0, blue: 0xF8 / 255.0),
            txLine: Color(red: 0xC0 / 255.0, green: 0x84 / 255.0, blue: 0xFC / 255.0)
        )
    }

    public static func paper(increasedContrast: Bool) -> NexusThemeTokens {
        NexusThemeTokens(
            preset: .paper,
            isDark: false,
            chassisBackground: Color(red: 0xEC / 255.0, green: 0xEA / 255.0, blue: 0xE4 / 255.0),
            canvasBackground: Color(red: 0xF6 / 255.0, green: 0xF5 / 255.0, blue: 0xF2 / 255.0),
            cardSurface: Color.white,
            wellSurface: Color(red: 0xF0 / 255.0, green: 0xEE / 255.0, blue: 0xE9 / 255.0),
            hoverSurface: Color(red: 0xE6 / 255.0, green: 0xE3 / 255.0, blue: 0xDB / 255.0),
            hairlineBorder: increasedContrast
                ? Color(red: 0x7A / 255.0, green: 0x77 / 255.0, blue: 0x70 / 255.0)
                : Color(red: 0xDD / 255.0, green: 0xD9 / 255.0, blue: 0xD0 / 255.0),
            strongBorder: Color(red: 0x7A / 255.0, green: 0x77 / 255.0, blue: 0x70 / 255.0),
            primaryInk: Color(red: 0x18 / 255.0, green: 0x1C / 255.0, blue: 0x24 / 255.0),
            secondaryInk: Color(red: 0x52 / 255.0, green: 0x5A / 255.0, blue: 0x69 / 255.0),
            accentFill: Color(red: 0x34 / 255.0, green: 0x51 / 255.0, blue: 0xD1 / 255.0),
            accentFillInk: Color.white,
            accentText: Color(red: 0x34 / 255.0, green: 0x51 / 255.0, blue: 0xD1 / 255.0),
            signalEmerald: Color(red: 0x04 / 255.0, green: 0x78 / 255.0, blue: 0x57 / 255.0),
            signalEmeraldFill: Color(red: 0x04 / 255.0, green: 0x78 / 255.0, blue: 0x57 / 255.0),
            warning: Color(red: 0xB4 / 255.0, green: 0x53 / 255.0, blue: 0x09 / 255.0),
            danger: Color(red: 0xB9 / 255.0, green: 0x1C / 255.0, blue: 0x1C / 255.0),
            rxLine: Color(red: 0x03 / 255.0, green: 0x69 / 255.0, blue: 0xA1 / 255.0),
            txLine: Color(red: 0x6D / 255.0, green: 0x28 / 255.0, blue: 0xD9 / 255.0)
        )
    }

    public static func studioAmber(increasedContrast: Bool) -> NexusThemeTokens {
        NexusThemeTokens(
            preset: .studioAmber,
            isDark: true,
            chassisBackground: Color(red: 0x0E / 255.0, green: 0x0D / 255.0, blue: 0x0C / 255.0),
            canvasBackground: Color(red: 0x14 / 255.0, green: 0x13 / 255.0, blue: 0x11 / 255.0),
            cardSurface: Color(red: 0x1C / 255.0, green: 0x1A / 255.0, blue: 0x17 / 255.0),
            wellSurface: Color(red: 0x25 / 255.0, green: 0x22 / 255.0, blue: 0x1E / 255.0),
            hoverSurface: Color(red: 0x2B / 255.0, green: 0x27 / 255.0, blue: 0x22 / 255.0),
            hairlineBorder: increasedContrast
                ? Color(red: 0x7A / 255.0, green: 0x72 / 255.0, blue: 0x66 / 255.0)
                : Color(red: 0x30 / 255.0, green: 0x2C / 255.0, blue: 0x26 / 255.0),
            strongBorder: Color(red: 0x7A / 255.0, green: 0x72 / 255.0, blue: 0x66 / 255.0),
            primaryInk: Color(red: 0xF2 / 255.0, green: 0xEF / 255.0, blue: 0xE9 / 255.0),
            secondaryInk: Color(red: 0xA6 / 255.0, green: 0x9E / 255.0, blue: 0x92 / 255.0),
            accentFill: Color(red: 0xE5 / 255.0, green: 0x9A / 255.0, blue: 0x2E / 255.0),
            accentFillInk: Color(red: 0x14 / 255.0, green: 0x12 / 255.0, blue: 0x0F / 255.0),
            accentText: Color(red: 0xF0 / 255.0, green: 0xB1 / 255.0, blue: 0x4B / 255.0),
            signalEmerald: Color(red: 0x34 / 255.0, green: 0xD3 / 255.0, blue: 0x99 / 255.0),
            signalEmeraldFill: Color(red: 0x10 / 255.0, green: 0xB9 / 255.0, blue: 0x81 / 255.0),
            warning: Color(red: 0xFB / 255.0, green: 0xBF / 255.0, blue: 0x24 / 255.0),
            danger: Color(red: 0xF8 / 255.0, green: 0x71 / 255.0, blue: 0x71 / 255.0),
            rxLine: Color(red: 0xF0 / 255.0, green: 0xB1 / 255.0, blue: 0x4B / 255.0),
            txLine: Color(red: 0x60 / 255.0, green: 0xA5 / 255.0, blue: 0xFA / 255.0)
        )
    }

    public static func resolve(
        preset: NexusThemePreset,
        systemColorScheme: ColorScheme,
        increasedContrast: Bool
    ) -> NexusThemeTokens {
        switch preset {
        case .system:
            return systemColorScheme == .dark
                ? obsidian(increasedContrast: increasedContrast)
                : paper(increasedContrast: increasedContrast)
        case .obsidian:
            return obsidian(increasedContrast: increasedContrast)
        case .paper:
            return paper(increasedContrast: increasedContrast)
        case .studioAmber:
            return studioAmber(increasedContrast: increasedContrast)
        }
    }
}

public extension NexusThemePreset {
    var preferredColorScheme: ColorScheme? {
        switch self {
        case .system: return nil
        case .paper: return .light
        case .obsidian, .studioAmber: return .dark
        }
    }
}

private struct NexusThemeEnvironmentKey: EnvironmentKey {
    static let defaultValue = NexusThemeTokens.obsidian(increasedContrast: false)
}

public extension EnvironmentValues {
    var nexusTheme: NexusThemeTokens {
        get { self[NexusThemeEnvironmentKey.self] }
        set { self[NexusThemeEnvironmentKey.self] = newValue }
    }
}

public struct NexusThemeRootModifier: ViewModifier {
    let preset: NexusThemePreset
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.colorSchemeContrast) private var contrast

    public func body(content: Content) -> some View {
        let tokens = NexusThemeTokens.resolve(
            preset: preset,
            systemColorScheme: colorScheme,
            increasedContrast: contrast == .increased
        )
        content
            .environment(\.nexusTheme, tokens)
            .tint(tokens.accentFill)
            .preferredColorScheme(preset.preferredColorScheme)
    }
}

public extension View {
    func nexusTheme(preset: NexusThemePreset) -> some View {
        modifier(NexusThemeRootModifier(preset: preset))
    }
}

/// High-contrast prominent CTA button style painting `theme.accentFillInk` over `theme.accentFill`
/// (`#14120F` dark ink on `#E59A2E` Studio Amber = `8.01:1`, `5.79:1` Obsidian, `6.47:1` Paper).
public struct NexusProminentButtonStyle: ButtonStyle {
    public init() {}

    public func makeBody(configuration: Configuration) -> some View {
        NexusProminentButtonBody(configuration: configuration)
    }
}

private struct NexusProminentButtonBody: View {
    let configuration: ButtonStyleConfiguration
    @Environment(\.nexusTheme) private var theme
    @Environment(\.isEnabled) private var isEnabled
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    #if os(macOS)
    @State private var isHovered = false
    #endif

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: 8, style: .continuous)
        configuration.label
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(theme.accentFillInk.opacity(isEnabled ? 1.0 : 0.72))
            .padding(.horizontal, 12)
            #if os(iOS)
            .padding(.vertical, 10)
            .frame(minHeight: 44)
            #else
            .padding(.vertical, 6)
            #endif
            .background(
                theme.accentFill.opacity(isEnabled ? (configuration.isPressed ? 0.85 : 1.0) : 0.45),
                in: shape
            )
            #if os(macOS)
            .overlay(shape.fill(Color.white.opacity(isHovered && isEnabled ? 0.08 : 0)).allowsHitTesting(false))
            .onHover { isHovered = $0 }
            #endif
            .contentShape(shape)
            .scaleEffect((!reduceMotion && configuration.isPressed && isEnabled) ? 0.97 : 1.0)
            .animation(reduceMotion ? nil : .easeOut(duration: 0.11), value: configuration.isPressed)
    }
}

/// Tactile Reduce-Motion-aware button style for interactive matte cards, transit stages, and theme swatches.
public struct NexusSurfaceButtonStyle: ButtonStyle {
    public let cornerRadius: CGFloat

    public init(cornerRadius: CGFloat = 10) {
        self.cornerRadius = cornerRadius
    }

    public func makeBody(configuration: Configuration) -> some View {
        NexusSurfaceButtonBody(configuration: configuration, cornerRadius: cornerRadius)
    }
}

private struct NexusSurfaceButtonBody: View {
    let configuration: ButtonStyleConfiguration
    let cornerRadius: CGFloat
    @Environment(\.nexusTheme) private var theme
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    #if os(macOS)
    @State private var isHovered = false
    #endif

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        configuration.label
            #if os(macOS)
            .overlay(
                shape.fill(isHovered ? theme.hoverSurface.opacity(0.45) : Color.clear)
                    .allowsHitTesting(false)
            )
            .onHover { isHovered = $0 }
            #endif
            .scaleEffect((!reduceMotion && configuration.isPressed) ? 0.98 : 1.0)
            .opacity(configuration.isPressed ? 0.9 : 1.0)
            .animation(reduceMotion ? nil : .easeOut(duration: 0.11), value: configuration.isPressed)
    }
}

/// 4 pure-SwiftUI miniature window swatch preview cards (`0ms` instant theme apply, `>= 44pt` on iOS).
public struct ThemeSwatchPickerView: View {
    public let selected: NexusThemePreset
    public let onSelect: (NexusThemePreset) -> Void
    @Environment(\.colorScheme) private var systemScheme
    @Environment(\.colorSchemeContrast) private var contrast

    public init(selected: NexusThemePreset, onSelect: @escaping (NexusThemePreset) -> Void) {
        self.selected = selected
        self.onSelect = onSelect
    }

    private let columns = [
        GridItem(.adaptive(minimum: 112, maximum: 180), spacing: 10),
    ]

    public var body: some View {
        LazyVGrid(columns: columns, spacing: 10) {
            ForEach(NexusThemePreset.allCases) { preset in
                ThemeSwatchCard(
                    preset: preset,
                    previewTokens: NexusThemeTokens.resolve(
                        preset: preset,
                        systemColorScheme: systemScheme,
                        increasedContrast: contrast == .increased
                    ),
                    isSelected: preset == selected,
                    onTap: { onSelect(preset) }
                )
            }
        }
    }
}

private struct ThemeSwatchCard: View {
    let preset: NexusThemePreset
    let previewTokens: NexusThemeTokens
    let isSelected: Bool
    let onTap: () -> Void
    @Environment(\.nexusTheme) private var activeTheme

    var body: some View {
        let outerShape = RoundedRectangle(cornerRadius: 12, style: .continuous)
        let innerShape = RoundedRectangle(cornerRadius: 6, style: .continuous)
        Button(action: onTap) {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 4) {
                    RoundedRectangle(cornerRadius: 3, style: .continuous)
                        .fill(previewTokens.chassisBackground)
                        .frame(width: 14)
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 4) {
                            Circle().fill(previewTokens.accentFill).frame(width: 6, height: 6)
                            Circle().fill(previewTokens.signalEmeraldFill).frame(width: 6, height: 6)
                            Spacer()
                        }
                        RoundedRectangle(cornerRadius: 3, style: .continuous)
                            .fill(previewTokens.cardSurface)
                            .overlay(
                                RoundedRectangle(cornerRadius: 3, style: .continuous)
                                    .strokeBorder(previewTokens.hairlineBorder, lineWidth: 0.75)
                            )
                    }
                    .padding(4)
                }
                .frame(height: 40)
                .background(previewTokens.canvasBackground, in: innerShape)
                .overlay(innerShape.strokeBorder(previewTokens.hairlineBorder, lineWidth: 0.75))

                HStack(spacing: 4) {
                    Text(preset.displayTitle)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                    Spacer(minLength: 2)
                    if isSelected {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.caption2)
                            .foregroundStyle(activeTheme.accentText)
                            .accessibilityHidden(true)
                    }
                }
            }
            .padding(6)
            .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
            .background(activeTheme.cardSurface, in: outerShape)
            .overlay(
                outerShape.strokeBorder(
                    isSelected ? activeTheme.accentFill : activeTheme.hairlineBorder,
                    lineWidth: isSelected ? 1.75 : 1
                )
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(NexusSurfaceButtonStyle(cornerRadius: 12))
        .accessibilityLabel("\(preset.displayTitle)：\(preset.subtitle)")
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }
}
#endif
