---
name: Nexus
description: Modern flagship proxy-client Bento card console across Desktop and Android with single-level 12px proportional cards, decoupled cobalt/emerald telemetry, and full-capability multi-protocol server workflows.
colors:
  electric-cobalt: "#2563eb"
  cobalt-deep: "#1d4ed8"
  luminous-cobalt: "#60a5fa"
  cobalt-wash: "#dbeafe"
  cobalt-night-well: "#172b4d"
  signal-emerald: "#059669"
  emerald-pressed: "#047857"
  phosphor-emerald: "#10b981"
  mint-luminous: "#34d399"
  emerald-wash: "#ecfdf5"
  emerald-night-well: "#0e2e24"
  warm-amber: "#d97706"
  studio-amber: "#f59e0b"
  amber-luminous: "#fbbf24"
  amber-wash: "#fef3c7"
  crimson-fault: "#dc2626"
  coral-fault-dark: "#f87171"
  crimson-wash: "#fef2f2"
  mist-slate-canvas: "#f4f6f9"
  pure-white-card: "#ffffff"
  cloud-well: "#f8fafc"
  cool-recessed-track: "#f1f5f9"
  mist-inset: "#eef2f6"
  slate-card-border: "#e2e8f0"
  slate-well-border: "#dbe2ea"
  slate-strong-border: "#cbd5e1"
  obsidian-canvas: "#0f141c"
  obsidian-rail: "#131923"
  obsidian-card: "#171e29"
  obsidian-well: "#1e2736"
  obsidian-inset: "#263244"
  obsidian-card-border: "#263142"
  obsidian-strong-border: "#37465e"
  amber-night-canvas: "#12100e"
  amber-night-card: "#1b1815"
  amber-night-border: "#2f2a23"
  deep-slate-ink: "#0f172a"
  slate-secondary-ink: "#475569"
  slate-muted-ink: "#526071"
  ice-slate-ink: "#f1f5f9"
  frost-secondary-ink: "#a3b3c9"
  steel-muted-ink: "#94a3b8"
typography:
  display:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Noto Sans CJK SC', sans-serif"
    fontSize: "26px"
    fontWeight: 700
    lineHeight: 1.23
    letterSpacing: "-0.01em"
  headline:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Noto Sans CJK SC', sans-serif"
    fontSize: "20px"
    fontWeight: 800
    lineHeight: 1.25
    letterSpacing: "-0.01em"
    fontFeature: "tnum"
  title:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Noto Sans CJK SC', sans-serif"
    fontSize: "16px"
    fontWeight: 800
    lineHeight: 1.35
    fontFeature: "tnum"
  subtitle:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Noto Sans CJK SC', sans-serif"
    fontSize: "15px"
    fontWeight: 800
    lineHeight: 1.35
  body:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Noto Sans CJK SC', sans-serif"
    fontSize: "13px"
    fontWeight: 600
    lineHeight: 1.4
  label:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Noto Sans CJK SC', sans-serif"
    fontSize: "12px"
    fontWeight: 700
    lineHeight: 1.35
    fontFeature: "tnum"
  caption:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Noto Sans CJK SC', sans-serif"
    fontSize: "11px"
    fontWeight: 700
    lineHeight: 1.3
    letterSpacing: "0.02em"
    fontFeature: "tnum"
  mono-kpi:
    fontFamily: "ui-monospace, 'SFMono-Regular', 'JetBrains Mono', Menlo, Consolas, monospace"
    fontSize: "22px"
    fontWeight: 800
    lineHeight: 1.2
    letterSpacing: "-0.015em"
    fontFeature: "tnum"
  mono-data:
    fontFamily: "ui-monospace, 'SFMono-Regular', 'JetBrains Mono', Menlo, Consolas, monospace"
    fontSize: "12px"
    fontWeight: 700
    lineHeight: 1.35
    fontFeature: "tnum"
rounded:
  xs: "6px"
  md: "8px"
  cta: "10px"
  card: "12px"
  pill: "9999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  card-pad: "18px"
  xl: "20px"
components:
  tunnel-cta-standby:
    backgroundColor: "{colors.electric-cobalt}"
    textColor: "{colors.pure-white-card}"
    typography: "{typography.subtitle}"
    rounded: "{rounded.md}"
    height: "52px"
    padding: "0 16px"
  tunnel-cta-connected:
    backgroundColor: "{colors.signal-emerald}"
    textColor: "{colors.pure-white-card}"
    typography: "{typography.subtitle}"
    rounded: "{rounded.md}"
    height: "52px"
    padding: "0 16px"
  button-primary:
    backgroundColor: "{colors.cobalt-deep}"
    textColor: "{colors.pure-white-card}"
    typography: "{typography.label}"
    rounded: "{rounded.md}"
    height: "32px"
    padding: "0 12px"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.deep-slate-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.md}"
    height: "32px"
    padding: "0 12px"
  button-ghost-hover:
    backgroundColor: "{colors.cool-recessed-track}"
    textColor: "{colors.deep-slate-ink}"
  button-danger:
    backgroundColor: "{colors.crimson-wash}"
    textColor: "{colors.crimson-fault}"
    typography: "{typography.label}"
    rounded: "{rounded.md}"
    height: "32px"
    padding: "0 12px"
  chip-filter:
    backgroundColor: "transparent"
    textColor: "{colors.slate-secondary-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.xs}"
    height: "28px"
    padding: "0 10px"
  chip-filter-active:
    backgroundColor: "{colors.cobalt-deep}"
    textColor: "{colors.pure-white-card}"
    typography: "{typography.label}"
    rounded: "{rounded.xs}"
    height: "28px"
    padding: "0 10px"
  segmented-track:
    backgroundColor: "{colors.cool-recessed-track}"
    textColor: "{colors.slate-secondary-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.md}"
    height: "36px"
    padding: "3px"
  segmented-pill-active:
    backgroundColor: "{colors.pure-white-card}"
    textColor: "{colors.electric-cobalt}"
    typography: "{typography.label}"
    rounded: "{rounded.xs}"
    height: "30px"
  input-search:
    backgroundColor: "{colors.cloud-well}"
    textColor: "{colors.deep-slate-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.md}"
    height: "32px"
    padding: "0 10px"
  nav-rail-item:
    backgroundColor: "transparent"
    textColor: "{colors.deep-slate-ink}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    height: "38px"
    padding: "0 12px"
  nav-rail-item-active:
    backgroundColor: "{colors.cobalt-wash}"
    textColor: "{colors.electric-cobalt}"
    rounded: "{rounded.md}"
    height: "38px"
  console-card:
    backgroundColor: "{colors.pure-white-card}"
    textColor: "{colors.deep-slate-ink}"
    rounded: "{rounded.card}"
    padding: "18px"
---

# Design System: Nexus

## Overview

**Creative North Star: "The Flagship Card Console"**

Nexus presents high-speed native proxy and tunnel operation as a crisp, modern flagship Bento card console calibrated to **Fluent 2** on Desktop (Slint v1.19 + C++26, targeting Windows & Linux), **Material 3 Adaptive** on Android (Kotlin + Jetpack Compose), and **Apple HIG** on Apple platforms (SwiftUI). Daily one-second operation is organized into a responsive multi-column Bento grid of proportional, single-level cards (`10px` Fluent 2 cards on Desktop, `12dp` MD3 cards on Android) resting on a layered cool mist-slate (`#f4f6f9`) or deep slate-obsidian (`#0f141c`) canvas ground: compact Quick-Control Tiles (`4-col` / `2×2` for Core, System Proxy, TUN, and LAN/DNS), Outbound Mode & Subscription Quota, Realtime Network Speed, Multi-Column Quick Server Tiles, and a `2×2` Connectivity & Inbound Matrix. Alongside the dashboard, a full-capability Profiles & Subscriptions console exposes subscription group tabs, instant URI/clipboard import, and structured visual editors across all 13 Nexus outbound protocols (`VLESS`, `Trojan`, `Hysteria2`, `TUIC`, `WireGuard`, `MASQUE`, `Shadowsocks-2022`, `AnyTLS`, `Naive`, `Snell`, `SSH`, `SOCKS5`, `HTTP`), Policy Groups, Proxy Chains, and Advanced Custom Configurations.

Every material and layout decision honors Nexus's zero-bloat native architecture. Cards separate cleanly from the canvas via `1px` (`1dp`) structural hairlines and tonal contrast with zero drop shadows, while continuous user-adjustable translucency (`40%–100%` `window-opacity` on Desktop, `50%–100%` `surfaceAlpha` on Android, with no Reduced Motion toggle in settings) lets the console sit lightly over desktop wallpapers when desired. The system explicitly rejects austere borderless monograph sheets, nested cards-inside-cards, drop-shadow elevation soup, hollow Standby dashboards, multi-hue neon telemetry rainbows, kickers or eyebrows above headings, and decorative monospace on UI prose.

**Key Characteristics:**
- Layered cool mist-slate (`#f4f6f9`) and deep slate-obsidian (`#0f141c`) canvas grounds framing single-level `12px`-radius (`12dp`), `1px`-bordered (`#e2e8f0` / `#263142`) functional cards, plus an optional warm Studio Amber (`#12100e` / `#1b1815`) dark preset.
- Decoupled semantic signal pair combining Electric Cobalt (`#2563eb` / `#60a5fa`) for primary interactive state and `RX` download telemetry with Signal Emerald (`#059669` / `#10b981`) for live tunnel confirmation, `TX` upload telemetry, and fast RTT (`< 80ms`).
- Recessed segmented controls (`#eef2f6` / `#f1f5f9` light, `#1e2736` / `#263244` dark) with elevated solid card-fill active pills (`#ffffff` / `#171e29` or `primaryContainer`) and borderless interior `well-bg` rows that prevent nested card borders.
- Continuous surface translucency (`0.40..1.0` `Theme.window-opacity` on Desktop with opt-in native backdrop blur; `0.50..1.0` `surfaceAlpha` + API 31+ Material You Dynamic Color on Android) with zero resting or modal drop shadows.
- Crisp platform sans-serif UI hierarchy paired with tabular monospace (`tnum`) strictly for endpoints, ports, latencies, byte rates, protocol badges, and clocks.

## Colors

Nexus pairs cool mist-slate and slate-obsidian neutrals (plus an optional warm Studio Amber dark preset) with Electric Cobalt interactive focus, Signal Emerald live/upload confirmation, and Warm Amber / Crimson diagnostic states.

### Primary
- **Electric Cobalt** (`#2563eb`): Default interactive brand accent in Light mode, Standby `52px`/`52dp` primary tunnel CTA fill, `RX` download waveform and KPI figure in Light mode, TLS protocol badge ink, and good-tier (`80–179ms` on Desktop) latency readout.
- **Cobalt Deep** (`#1d4ed8`): Primary action button (`NexusButton`) and active filter chip (`NexusChip`) fill in Light mode, plus hover/pressed anchor for cobalt controls (`#2563eb` in Dark mode).
- **Luminous Cobalt** (`#60a5fa`): Default interactive accent, active navigation ink, and `RX` download waveform/KPI figure on `#0f141c` Dark surfaces (with optional user accent presets on Desktop for Emerald, Violet `#6d28d9`/`#a78bfa`, Amber, and Rose `#e11d48`/`#f87171`).
- **Cobalt Wash** (`#dbeafe`): Light `primaryContainer` / `telemetryDownloadContainer` tint on Android and hue-tinted secondary cue ink (`Start` / `立即启动`) inside the Standby Electric Cobalt primary CTA.
- **Cobalt Night Well** (`#172b4d`): Dark `telemetryDownloadContainer` and TLS badge container on Android (`#1e3a6e` `primaryContainer` in `ObsidianDarkColorScheme`).

### Secondary
- **Signal Emerald** (`#059669`): Connected primary tunnel CTA fill across Light and Dark modes, Light-mode live status dot, active switch badge ink, `TX` upload rate and dashed waveform stroke, Direct outbound badge ink, and fast RTT (`< 80ms`) readout.
- **Emerald Pressed** (`#047857`): Pressed state on the Connected primary tunnel CTA and dark active emerald pill anchor.
- **Phosphor Emerald** (`#10b981`): Dark-mode live tunnel indicator, `TX` upload rate and dashed waveform stroke, fast/healthy status dot, and Connected CTA hover state (`#34d399` **Mint Luminous** for Dark fast-RTT text).
- **Emerald Wash** (`#ecfdf5`): Soft container tint (`live-emerald-soft` / `lat-fast-bg`) for fast RTT and Direct badges in Light mode (`#d1fae5` on Android `successContainer` and Connected CTA secondary text), paired with **Emerald Night Well** (`#0e2e24`) in Dark mode.

### Tertiary
- **Warm Amber** (`#d97706`): Light-mode caution/degraded status, mid-tier RTT (`180–349ms` Desktop, `80–179ms` Android `LatencyBadge`), QUIC protocol badge ink (`#b45309` on Desktop), and node/mode switch onset marker line on the throughput chart.
- **Studio Amber** (`#f59e0b`): Primary interactive accent and `RX` telemetry ink in the Studio Amber dark preset, plus Dark-mode warning indicator (`#fbbf24` **Amber Luminous** for Dark warning/QUIC badge ink and **Amber Wash** `#fef3c7` for Light warning/QUIC containers).
- **Crimson Fault** (`#dc2626`): Error tunnel CTA fill, timeout/unreachable RTT (`0ms` or `>= 350ms`) alert ink, and destructive button foreground in Light mode, paired with **Coral Fault Dark** (`#f87171`) in Dark mode and **Crimson Wash** (`#fef2f2`, `#fee2e2` on Android) error containers.

### Neutral
- **Mist-Slate Canvas** (`#f4f6f9`): Root window and scaffold background (`surface-bg-solid` / `PaperLightColorScheme.surface`) in Light mode, giving white cards unmistakable separation without drop shadows.
- **Pure White Card** (`#ffffff`): Single-level card surface (`card-bg-solid` / `surfaceContainerLow`), Desktop left navigation rail (`rail-bg-solid`), modal overlay sheet (`overlay-bg`), and active segmented control pill in Light mode.
- **Cloud Well & Cool Recessed Track** (`#f8fafc` / `#f1f5f9`): Borderless interior well fills (`well-bg-solid` `#f8fafc` on Desktop, `wellSurface` `#f1f5f9` on Android), zebra table rows, rail/row hover washes (`#f1f5f9`), and **Mist Inset** (`#eef2f6`) segmented control tracks and inactive switch tracks on Desktop (`#eef2f7` `surfaceContainer` rail tint on Android).
- **Slate Card, Well & Strong Borders** (`#e2e8f0` / `#dbe2ea` / `#cbd5e1`): `1px` (`1dp`) card and navigation rail hairline (`#e2e8f0`), recessed input border (`#dbe2ea`), and modal/outline stroke (`#cbd5e1`; `#94a3b8` input hover border on Desktop).
- **Obsidian Canvas, Rail & Card** (`#0f141c` / `#131923` / `#171e29`): Root Dark canvas ground (`#0f141c`), elevated navigation rail (`#131923`), and single-level Dark card surface (`#171e29`; `#1b2432` on transient overlays).
- **Obsidian Well, Inset & Borders** (`#1e2736` / `#263244` / `#263142` / `#37465e`): Borderless Dark interior well (`#1e2736`), segmented/switch inset track (`#263244` Desktop, `#283447` Android), `1px` Dark card border (`#263142`; `#222c3c` rail border), and strong outline (`#37465e` Android, `#475569` Desktop).
- **Studio Amber Night Surfaces** (`#12100e` / `#1b1815` / `#2f2a23`): Warm dark preset pairing **Amber Night Canvas** (`#12100e`, `#161411` rail) with **Amber Night Card** (`#1b1815`, `#24201b` well) and **Amber Night Border** (`#2f2a23`, `#2e2923` on Android).
- **Calibrated Slate Ink Hierarchy:** Light mode pairs **Deep Slate Ink** (`#0f172a`) primary text with **Slate Secondary Ink** (`#475569`) and **Slate Muted Ink** (`#526071`; `#64748b` on rail/Android muted). Dark mode pairs **Ice Slate Ink** (`#f1f5f9`; `#f5f1e8` in Studio Amber) with **Frost Secondary Ink** (`#a3b3c9`) and **Steel Muted Ink** (`#94a3b8`).

### Named Rules
**The Decoupled Signal Pair Rule.** Interactive selection and download (`RX`) telemetry use Electric Cobalt (`#2563eb` light / `#60a5fa` dark), while live tunnel confirmation, upload (`TX`) telemetry, and fast RTT (`< 80ms`) use Signal Emerald (`#059669` light / `#10b981` dark); electric-purple or multi-hue SaaS rainbows are forbidden.

**The Hue-Tinted CTA Ink Rule.** Secondary action cues and inline latency readouts inside the filled `52px`/`52dp` primary tunnel button must use hue-tinted Cobalt Wash (`#dbeafe`) in Standby and pale emerald/white (`#d1fae5` / `rgba(255,255,255,0.9)`) when Connected—never muddy neutral gray.

## Typography

**Display Font:** Platform system sans-serif (`system-ui, -apple-system, 'Segoe UI', Roboto, 'Noto Sans CJK SC', sans-serif`)
**Body Font:** Platform system sans-serif (`system-ui, -apple-system, 'Segoe UI', Roboto, 'Noto Sans CJK SC', sans-serif`)
**Label/Mono Font:** Platform sans-serif for UI labels and actions; platform monospace (`ui-monospace, 'SFMono-Regular', 'JetBrains Mono', Menlo, Consolas, monospace`) strictly for machine endpoints, ports, badges, and live telemetry.

**Character:** Clean, high-legibility native grotesque sans-serif (`500`–`800`) keeps bilingual Chinese and English console labels crisp at compact desktop and mobile densities, while tabular monospace (`tnum`) locks live byte rates, ports, and millisecond latencies against horizontal jitter.

### Hierarchy
- **Display** (`700`, `26px` / `26sp` Android `displaySmall`, line-height `1.23`, tracking `-0.01em`): Large diagnostic and hero state readouts on expanded mobile/tablet surfaces.
- **Headline** (`800` Desktop / `700` Android, `20px` Desktop identity title & `22sp` Android `headlineSmall`, line-height `1.25`, tracking `-0.01em`, `tnum`): Top-level identity headers (`Nexus` `18px`–`20px` `800`) and major workspace sheet titles.
- **Title** (`800` Desktop / `700` Android, `16px` Desktop card headers & `16sp` Android `titleMedium`, line-height `1.35`, `tnum`): Primary header of each console card (`运行状态与代理模式`, `实时网络速率`, `当前订阅与快速选点`, `入站端口与连通性检测`).
- **Subtitle** (`800` Desktop / `600`–`700` Android, `15px` Desktop primary CTA title & `14sp`–`15sp` Android `titleSmall` / `bodyLarge`, line-height `1.35`): Primary `52px`/`52dp` tunnel button label, active exit row title, and Android two-tier server card remarks.
- **Body** (`500`–`700`, `13px` Desktop / `13.5sp` Android `bodyMedium`, line-height `1.4`): Navigation rail items (`13px`), `FlushSwitchRow` titles, quick-switch server/profile names, and inbound summary rows.
- **Label** (`600`–`700`, `12px` Desktop / `11.5sp`–`13sp` Android `labelMedium` / `labelLarge`, line-height `1.35`, `tnum`): `NexusButton` actions, `NexusChip` subscription filters, `SlidingSegmentBar` / `OpticalSegmentedControl` mode tabs, and `NexusInput` text.
- **Caption** (`700`, `11px` / `11sp` Android `labelSmall`, line-height `1.3`, tracking `0.02em`, `tnum`): `ProfilesPanel` table column headers (`Type`, `Remarks`, `Address:Port`, `RTT`), secondary hints, and compact status pills.
- **Mono KPI & Data** (`800` at `22px` Desktop / `19sp`–`20sp` Android `kpiHero` for `mono-kpi`; `600`–`800` at `10px`–`13px` / `11sp`–`12.5sp` `monoBadge` for `mono-data`, `tnum`): Live `↓ / ↑` speed readouts, cumulative totals, `00:00:00` uptime clocks, `server:port · transport+tls` endpoints, `:7890` listener ports, millisecond RTTs, and uppercase protocol codes (`VLESS`, `HY2`, `WG`, `GROUP`).

### Named Rules
**The Monospace Boundary Rule.** Monospace (`mono-kpi`, `mono-data`) is reserved strictly for endpoints, ports, latencies, throughput figures, clocks, memory counters, and short protocol codes; card titles, navigation items, and action verbs always set in platform sans-serif.

**The Tabular Telemetry Lock Rule.** Every live throughput figure, uptime timer, active-flow pill, and RTT readout enforces `font-variant-numeric: tabular-nums` (`tnum`) so 1Hz telemetry ticks never shift neighboring controls.

## Layout

Nexus uses a structured card-console grid on an `8px`-anchored spatial scale (`4px`, `8px`, `12px`, `16px`, `18px`, `20px`) engineered to eliminate both hollow whitespace in Standby and nested container clutter when Connected.

- **Desktop Window & Responsive Tiers (`1280×760px` preferred, `780×560px` minimum):**
  - **Left Navigation Rail (`Sidebar`):** Collapses to `60px` icon-only width (automatically below `900px` `LayoutMetrics.is-compact` unless overridden) and expands to `176px–220px` (`196px` default), bounded by a `1px` right hairline (`#e2e8f0` / `#222c3c`). Houses 8 primary console routes (`仪表盘`, `配置文件`, `代理组`, `路由与规则`, `DNS 与入站`, `连接`, `日志`, `设置`) above a `1px` divider and 3 utility buttons (`Command Palette`, theme toggle, and rail expand-collapse).
  - **Dashboard 2×2 Card Grid (`StatusCard`):** At window widths `>= 920px`, fills the workspace (`20px` outer padding, `16px` horizontal and vertical gutters) with two equal-stretch rows and a `1.0 : 1.15` left-to-right column ratio: top-left `DashboardTunnelCard`, top-right `DashboardTrafficCard`, bottom-left `DashboardServersCard`, and bottom-right `DashboardInboundCard`. Below `920px`, transitions cleanly into a single-column whole-card scrollable stack (`16px` left, `20px` right, `14px` top/bottom padding, `12px` card spacing) with a custom `10px` `NexusVScrollBar`.
  - **Operational & Server Workspace Views:** Non-dashboard tabs use `20px` left (`10px`–`20px` right) and `18px` top / `16px` bottom canvas padding. `ProfilesPanel` stacks a single-row search/URI-import/sort/action toolbar, a wrapping `FlexboxLayout` subscription group chip bar (`全部`, `手动配置`, and live subscription tabs), an optional collapsible subscription drawer, and a full-height `12px`-radius virtualized 7-column server table card (`46px` row height).
- **Android Material 3 Adaptive (`1120dp` max container width, `16dp` horizontal screen padding, `12dp` vertical rhythm):**
  - **Compact (`< 600dp`):** Pairs a pinned `NexusTopAppBar` and `CompactBottomChrome` with a single-column `LazyColumn` (`12dp` card gap) stacking `FiveStateHeroCard`, `ThroughputSparklineCard`, `QuickNodesCarouselCard`, and `TrafficSplitCard` (preceded by `QuickOnboardingCard` only when zero remote profiles exist). All interactive rows, chips, and icon actions enforce `>= 48dp` touch targets.
  - **Medium (`600dp–839dp`) & Expanded (`>= 840dp`):** Moves navigation to `MediumNavigationRail` or `PermanentNavigationDrawer` (with live status and quick-power access outside Overview) and arranges the four Overview console cards into a 2×2 grid (`14dp` column gutter, `12dp` row gap).

## Elevation & Depth

Nexus is a **flat-matte, single-level tonal system with zero drop shadows** (`box-shadow: none`, `0dp` shadow elevation) and continuous user-adjustable surface translucency. On Desktop, `Theme.window-opacity` (`0.40..1.0`, with `100%`, `88%`, `75%`, and `60%` quick presets) composites with optional OS-level Wayland/KWin/DWM `blur-enabled` backdrop blur (`effective-alpha` steps to `0.88` when blur is enabled above `96%`). On Android, `surfaceAlpha` (`0.50f..1.0f` in `5%` slider increments) scales container alpha alongside optional Android 12+ Material You Dynamic Color, with no app-level Reduced Motion toggle in settings (Android segmented controls still respect OS-level `ANIMATOR_DURATION_SCALE` accessibility). Depth is conveyed across four crisp tonal planes:

1. **Canvas Ground & Chrome Spine:** Root `#f4f6f9` (Light), `#0f141c` (Dark), or `#12100e` (Studio Amber) canvas provides calm contrast behind cards, paired with `#ffffff` / `#131923` / `#161411` navigation chrome and a `1px` `#e2e8f0` / `#222c3c` border.
2. **Single-Level Functional Cards:** Primary content groups sit on `#ffffff` / `#171e29` / `#1b1815` containers (`card-bg` lifts alpha by `+0.05` when translucent on Desktop) with a `1px` (`1dp`) `#e2e8f0` / `#263142` / `#2f2a23` border—never drop shadows.
3. **Borderless Interior Wells:** Inside a card, sub-regions (`FlushSwitchRow`, dual-track waveform plot, subscription quota strip, and 4-target RTT cells) step to borderless `#f8fafc` / `#f1f5f9` (Light) or `#1e2736` (Dark) `well-bg` fills or `1px` flush dividers—never nested bordered cards.
4. **Modal & Sheet Scrims:** `CommandPaletteModal` (`Ctrl+K`), `OutboundModalDialog`, `RuleModalDialog`, and Android diagnostic/command sheets use opaque `#ffffff` / `#1b2432` fills with a `1px` `#cbd5e1` / `#36455c` border over a flat dim scrim (`#0f172a54` light, `#00000094` dark).

### Named Rules
**The Single-Level Card Rule.** Top-level functional groups live in `12px`-radius (`12dp`) `1px`-bordered cards on the `#f4f6f9` / `#0f141c` canvas ground, while interior groupings use borderless `well-bg` fills or `1px` dividers—never bordered cards nested inside cards.

**The Zero-Shadow Translucency Rule.** Resting, hovered, and modal surfaces render with zero drop shadows; hierarchy relies strictly on canvas-to-card luminance contrast, `1px` hairlines, and user-controlled continuous alpha (`0.40..1.0` Desktop, `0.50..1.0` Android).

## Shapes

Nexus pairs a crisp **Fluent 2 radius scale on Desktop (`4px` / `6px` / `10px`)** with a **Material 3 card-console scale on Android (`6dp` / `8dp` / `12dp`)**:

- **Top-Level Console Cards & Modals (`10px` Desktop `Theme.radius-card`, `12dp` Android):** All four dashboard cards (`DashboardTunnelCard`, `DashboardTrafficCard`, `DashboardServersCard`, `DashboardInboundCard` / Android `OpticalCard`), `ProfilesPanel` server table container, Android two-tier `ProfileListRow` server cards, `ThemeStudioCard`, and Desktop modal dialogs (`CommandPaletteModal`, `OutboundModalDialog`, `RuleModalDialog`).
- **Interactive Controls & Interior Wells (`6px` Desktop `Theme.radius-md`, `8dp` Android — `10dp` on Android's `52dp` hero button):** `NexusButton`, `IconActionButton`, `NexusInput` / `OutlinedTextField`, `NexusSelect`, `NavRailItem`, `SlidingSegmentBar` / `OpticalSegmentedControl` outer track, `FlushSwitchRow`, recessed waveform chart wells, `ProbeCell` targets, and `ThemeSwatchCard`.
- **Compact Badges, Chips & Active Pills (`4px` Desktop `Theme.radius-sm`, `6dp` Android):** `NexusChip` subscription/group filters, active segmented control pill inside `SlidingSegmentBar` / `OpticalSegmentedControl`, `StatusPill`, `LatencyBadge`, protocol kind badges (`VLESS`, `HY2`, `GROUP`), and `ESC` shortcut caps.
- **Full-Capsule Indicators (`9999px`, `rounded.pill`):** Fluent 2 `40×20px` `NexusSwitch` tracks & circular morphing thumb (`12px` rest → `14px` hover → `17×12px` pressed), Fluent 2 `18px` circular `NexusOpacitySlider` thumb with inner accent core, `5px`–`6px` `ProportionBar` traffic/subscription quota bars, and `7px`–`9px` circular connection status dots.

## Components

Controls across Desktop and Android feel **crisp, tactile, and responsive**, pairing `120ms` (`Motion.fast`) hover/border transitions and `140ms` sliding segmented pills with a `100ms` (`Motion.micro`, `cubic-bezier(0.23, 1, 0.32, 1)`) `0.97`–`0.98` press-scale response.

### Buttons
- **Primary Tunnel Hero CTA:** Full-width `52px` height (`8px` radius) on Desktop and `52dp` min-height (`10dp` radius) on Android, `16px` horizontal padding, leading `18px`/`18dp` state icon (`play`, `stop`, `refresh`, or `CircularProgressIndicator`), `15px` `800` / `titleSmall` Bold state verb (`Connect · <Node>` / `Running · <Node>`), and right-aligned action cue or live RTT (`34 ms`). Standby fills solid `#2563eb` Electric Cobalt (`#dbeafe` secondary cue); Connected fills solid `#059669` Signal Emerald (`#10b981` hover, `#047857` pressed, `#d1fae5` cue); Error fills `#dc2626` Crimson. Keyboard focus renders a `2px` `#ffffff` border.
- **Standard Console Button (`NexusButton` & Android Toolbar Buttons):** `32px` default height (`28px` in compact card headers; `48dp` touch height on Android), `6px` Desktop (`8dp` Android) radius, `10px`–`12px` horizontal padding, optional `13px`–`16dp` icon.
  - **Primary:** `#1d4ed8` (`#2563eb` dark) fill, `1px` Fluent 2 top-lit accent elevation bevel border (`accent-control-border`), `#ffffff` `12px` `700` label.
  - **Secondary / Control Fill (Default on Desktop):** Fluent 2 `control-fill` (`#ffffff` light / `#202938` dark) with `1px` top-lit elevation bevel border (`control-border-brush`, zero drop shadow); hovers to `control-fill-hover` with `control-border-hover-brush`; active toggle state uses `8%`–`16%` cobalt wash (`selected-bg`) with `selected-border`.
  - **Danger / Warn:** `#fef2f2` (`#f8717122` dark) fill with `#dc2626` (`#f87171` dark) ink and `1px` error border, or `#fffbeb` warn fill with `#d97706` ink.
  - **Focus / Disabled:** `2px` `#2563eb` (`#60a5fa` dark) focus ring; `0.48` opacity when disabled.

### Chips
- **Subscription & Group Filter Chips (`NexusChip` / `EditorChoiceChip`):** `28px` height (`24px` inside dashboard group strips; `>= 48dp` hit target on Android), `6px` (`6dp`–`8dp`) radius, `10px` horizontal padding. Unselected chips use transparent fill with `1px` `#e2e8f0` (`#263142` dark) border and `#475569` `12px` `500` text; active chips fill solid `#1d4ed8` (`#2563eb` dark) with `#ffffff` `700` text.
- **Status, Protocol & Latency Pills (`StatusPill` & `LatencyBadge`):** `22px`–`24dp` visual pill height, `6px` (`6dp`) radius, `7px`–`8dp` horizontal padding, pairing soft semantic container fills (`#ecfdf5`, `#eff6ff`, `#fef3c7`, `#fef2f2` in Light; `#0e2e24`, `#172b4d`, `#332512`, `#381a1f` in Dark) with bold `10px`–`11sp` tabular monospace labels (`VLESS`, `HY2`, `24 ms`).

### Cards / Containers
- **4-Card Dashboard Console Containers (`OpticalCard` & `Dashboard*Card`):** `12px` (`12dp`) corner radius, `#ffffff` (`#171e29` dark, `#1b1815` Studio Amber) fill, `1px` (`1dp`) `#e2e8f0` (`#263142` dark) border, zero shadow, `18px` padding on Desktop (`16dp` on Android), and `10px`–`12px` internal vertical rhythm. Interior switches, charts, and probe cells use borderless `8px`-radius `well-bg` fills (`#f8fafc` / `#f1f5f9` light, `#1e2736` dark).
- **Server Profiles Containers:** Desktop `ProfilesPanel` renders a `12px`-radius bordered table card with a `36px` `#f8fafc` (`#1e2736` dark) column header and virtualized `46px` rows (`selected-bg` wash + `7px` `#059669` dot when active, subtle `#f8fafc` / `#1b2330` alternating rows, and inline Edit/Share/Delete icon buttons). Android `ConfigWorkspacePanes` renders virtualized `12dp`-radius two-tier `ProfileListRow` cards (`1.5dp` primary border + `7%`–`16%` primary wash when active) displaying full remarks + RTT on row 1 and protocol badge + `server:port · transport+tls` + `48dp` Edit/Overflow buttons on row 2.

### Inputs / Fields
- **Search & URI Input (`NexusInput` / `OutlinedTextField`):** `32px` height on Desktop (`6px` radius, Fluent 2 `control-fill` surface with `control-border-brush` and signature bottom focus stroke: `1px` `input-bottom-rest` hairline expanding to a `2px` Electric Cobalt `#2563eb`/`#60a5fa` bottom bar on focus; `10px` left padding, optional `14px` search icon and `18px` clear button) and single-line `8dp`-radius `OutlinedTextField` on Android.
- **Combobox (`NexusSelect`):** `32px` height (`6px` radius, `control-fill` + `control-border-brush`); transient popup uses `overlay-bg` with Fluent 2 `3px × 14px` left accent selection pill on the active option.
- **Recessed Segmented Controls (`SlidingSegmentBar` & `OpticalSegmentedControl`):** `34px`–`36px` height on Desktop (`42dp` min slot height on Android), `6px` Desktop (`8dp` Android) outer radius recessed track (`#eef2f6` / `#f1f5f9` light, `#263244` / `#1e2736` dark, `3px`/`3dp` inner padding) housing an elevated `4px`-radius (`6dp` Android) active pill (`#ffffff` in Light, `#171e29` on Desktop Dark or `#1e3a6e` `primaryContainer` on Android Dark) framed by a `1px` translucent accent rim (`24%`–`50%` alpha) and `700` active accent text.

### Navigation
- **Desktop Fluent 2 Rail (`Sidebar`):** Full-height `#ffffff` (Light), `#131923` (Dark), or `#161411` (Studio Amber) rail (`60px` collapsed, `196px` default expanded) bounded by a `1px` `#e2e8f0` / `#222c3c` right border. Contains the `22px` Nexus prism mark + `18px` `800` `Nexus` wordmark, eight `38px` `NavRailItem` tabs (`6px` radius), and three `36px` `RailUtilityButton` controls. Active tabs use Fluent 2 neutral `SubtleFill` (`nav-active-bg`) with a `3px × 16px` Electric Cobalt vertical indicator pill, Electric Cobalt icon, and high-contrast primary text (`rail-fg`), plus a `260ms` right-anchored tooltip when collapsed.
- **Android Adaptive Navigation:** `Compact` mounts a pinned `NexusTopAppBar` (with edge-to-edge `StatusBarProtection` gradient) and `CompactBottomChrome`; `Medium` mounts `MediumNavigationRail`; `Expanded` mounts `PermanentNavigationDrawer`.

### Dual-Track Throughput Waveform & Standby-Aware Server Switcher
- **Realtime Throughput Card (`DashboardTrafficCard` / `ThroughputSparklineCard`):** Pairs `22px` (`19sp` Android) `800` tabular monospace `RX` (`#2563eb` / `#60a5fa`) and `TX` (`#059669` / `#10b981`) speed KPIs with a borderless `8px`-radius `well-bg` plot (`min-height: 112px` Desktop, `98dp`–`110dp` Android) featuring `25%`/`50%`/`75%` hairline gridlines, a `2.2px` solid cobalt `RX` Bezier curve with `12%`–`22%` area fill, a `1.7px`–`1.8px` dashed emerald `TX` curve, amber node-switch onset markers, and a clean Standby baseline prompt.
- **Standby-Aware Server & Subscription Card (`DashboardServersCard` / `QuickNodesCarouselCard`):** Combines a `36px` borderless `well-bg` subscription quota summary (`ProportionBar` + tabular usage bytes) and 1-click Clipboard URI Import with scrollable server rows (`38px` `well-bg` rows on Desktop, `48dp` divider-separated rows on Android). Automatically displays live policy-group members when Connected and persisted SQLite `WorkspaceState.profiles` when in Standby so the dashboard never renders an empty shell.

## Do's and Don'ts

### Do:
- **Do** frame each top-level dashboard and workspace module as a single-level `12px`-radius (`12dp`) card (`#ffffff` light / `#171e29` dark) with a `1px` (`1dp`) hairline border (`#e2e8f0` / `#263142`) on the `#f4f6f9` / `#0f141c` canvas ground.
- **Do** use borderless interior `well-bg` fills (`#f8fafc` / `#f1f5f9` light, `#1e2736` dark) or `1px` flush dividers for switches, charts, subscription bars, and probe strips inside a card.
- **Do** pair Electric Cobalt (`#2563eb` / `#60a5fa`) for interactive focus, Standby primary CTA, and `RX` download telemetry with Signal Emerald (`#059669` / `#10b981`) for Connected state, `TX` upload telemetry, and fast RTT (`< 80ms`).
- **Do** populate the Dashboard Server Switcher from SQLite workspace profiles when in Standby and live policy-group members when Connected so all four console cards remain actionable in every state.
- **Do** enforce `tnum` tabular numerals and monospace (`mono-kpi`, `mono-data`) exclusively on endpoints, ports, latencies, byte rates, protocol codes, and clocks.
- **Do** preserve continuous user-adjustable surface translucency (`0.40..1.0` `window-opacity` on Desktop, `0.50..1.0` `surfaceAlpha` on Android) and `>= 48dp` interactive touch targets on Android.

### Don't:
- **Don't** nest `1px`-bordered cards inside other bordered cards or add drop shadows (`box-shadow`) to resting, hovered, or modal surfaces.
- **Don't** revert to borderless `0px–4px` monograph ledger sheets or dark-only navigation spines in Light mode (`Sidebar` in Light mode stays crisp `#ffffff` on `#f4f6f9`).
- **Don't** place kickers, uppercase eyebrows, or numbered `01 / 02` decorative labels above card or section titles.
- **Don't** render neutral gray secondary text inside the filled Electric Cobalt or Signal Emerald primary tunnel CTA.
- **Don't** introduce multi-hue neon rainbows into throughput charts or set prose, card titles, and UI action verbs in monospace.
- **Don't** add an app-level Reduced Motion toggle to Desktop or Android appearance settings.
