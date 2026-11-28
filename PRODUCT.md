# Product

<!-- impeccable:product-schema 1 -->

## Platform

adaptive

## Users

Primary users are technical practitioners and power users across Desktop (Linux, Windows, macOS) and Android who rely on a local proxy/tunnel daily. Their usage splits into two distinct rhythms:
- **Fast daily operation (90% of sessions):** Open or wake the client, toggle the tunnel or system proxy in one second, switch policy groups or outbound mode (`rule` / `global` / `direct`), import a share link or subscription, and dismiss the app back to the system tray or background.
- **Focused inspection and troubleshooting (10% of sessions):** Inspect live active connections and process/package ownership, explain or author routing and DNS rules, probe group/node latency and UDP readiness, configure per-app split tunneling or TUN privileges, and inspect real-time logs.

## Product Purpose

Nexus provides a unified, high-performance proxy and tunnel platform with lightweight native client shells that give users immediate, trustworthy control over network traffic without runtime bloat. Success means routine tunnel control feels instantaneous inside a responsive multi-column Bento card dashboard (never hollow borderless sheets, never ugly full-width horizontal strips, and never nested cards-inside-cards), while structured server, subscription-group, routing, DNS, and inbound configuration exposes 100% of Nexus Core's protocols, policy groups, proxy chains, rule-set routing, DNS, and inbound capabilities.

## Positioning

Nexus is built from scratch in C++26 Modules (`corosio` + `ngcpp/proxy`, custom user-space TUN/TCP/IP stack, BoringSSL-backed custom TLS 1.2/1.3 & browser fingerprint orchestration, ordered declarative / BEVE rule-set and FakeIP DNS engines, and `epoll` / `io_uring` + `splice` / kTLS fast paths), paired with native OS shells (Slint v1.19 + C++26 on Desktop, Kotlin 2.x + Jetpack Compose `VpnService` on Android, Swift 6 + SwiftUI on Apple) over a 4-pillar configuration boundary (`nexus-client.db` SQLite 3 WAL + isolated `0600` / Keystore credentials + single-source `nexus workspace compose`).

## Operating Context

- **Desktop (`desktop/`):** Runs on Linux, Windows, and macOS as a resident native window + system tray utility. Communicates with the `nexus` core process over loopback HTTP `/v1/*` and multiplexed RFC 6455 WebSocket `/v1/ws` (with SSE fallback), managing OS system proxy snapshots, Mixed/SOCKS/HTTP listeners, LAN sharing, and privileged TUN helpers.
- **Android (`android/`):** Runs non-root via `VpnService` (or proxy-only mode) with process isolation between Compose UI, `:bg` foreground tunnel service, and native `libnexus.so`, supporting Quick Settings `TileService`, per-app allow/disallow routing, underlying physical network tracking, Private DNS compatibility, and E2EE WebDAV / `nexus://share/v1/` sync.

## Capabilities and Constraints

- **Confirmed redesign boundary:** Redesign focuses on UI interaction, visual system, and information architecture across Desktop (`desktop/ui/` Slint v1.19 + UI state wiring) and Android (`android/app/` Jetpack Compose Material 3 Adaptive), preserving the existing C++26 bridge (`nexus-desktop-bridge`) and Kotlin `:core-bridge`, unified SQLite 3 WAL storage (`nexus-client.db`), 4-pillar `workspace.json` / `host.json` composition, and `/v1/*` + `/v1/ws` control plane capabilities.
- **Desktop technical constraints:** Slint v1.19.0 (`COMPILATION_UNITS 16`), GPLv3 / Royalty-Free Desktop compliance (`AboutSlint` attribution retained), low idle/tray memory footprint (avoiding unbounded Skia blur texture cache bloat), full keyboard shortcut and Command Palette (`Ctrl+K`) operability, bilingual ZH/EN (`I18n`) support, and responsive window sizing down to `780x560`.
- **Android technical constraints:** Kotlin 2.x + Jetpack Compose Material 3 Adaptive across compact phones, medium foldables, and expanded tablets/desktop windows, full edge-to-edge window insets, predictive system Back handling, `rememberSaveable` configuration-change resilience, 48dp touch targets, font-scale (`sp`) resilience, and non-root `VpnService` lifecycle states (`STANDBY`, `STARTING`, `CONNECTED`, `DEGRADED`, `ERROR`).
- **Security & credential invariants:** Credentials, bearer tokens, WebDAV passwords, and E2EE sync passphrases remain strictly in `0600` secret files or Android Keystore storage and never surface in plain UI state exports or SQLite tables.

## Brand Commitments

- **Product name:** Nexus
- **Existing brand mark:** `desktop/ui/icons/nexus-prism.svg` and Android adaptive launcher / notification icons (`android/app/src/main/res/drawable/ic_launcher_foreground.xml`, `android/core-bridge/src/main/res/drawable/ic_nexus_notification.xml`).
- **Standing category-canon commitment:** Modern flagship proxy-client Bento card console calibrated to the craft bar of `Clash Verge Rev` and `FlClash` — crisp single-level proportional cards (`10px–12px`) on a distinct cool-slate/obsidian canvas ground, continuous user-adjustable window/surface transparency (`Theme.window-opacity` / `surfaceAlpha`), and full-capability server, subscription group, routing, DNS, and inbound configuration workflows.

## Evidence on Hand

- Core Linux x86-64 benchmark baseline documented in `README.md`: `epoll + splice` 19.2–19.6 Gbps, 46.7 ms/GiB CPU, 13.2 MiB RSS; `io_uring + splice` 19.4–20.2 Gbps.
- Existing Desktop Slint implementation (`desktop/ui/`, `desktop/src/`) and C++26 bridge test suite (`desktop/tests/`).
- Existing Android Compose & `:core-bridge` implementation (`android/app/`, `android/core-bridge/`) and unit/preview suites.
- Absences that future work must not fabricate: no commercial pricing tiers, no hosted VPN server network claims, no customer testimonials, and no third-party security audit certifications.

## Product Principles

1. **One-second routine, zero-maze depth:** Primary tunnel toggle, active exit selection, and routing mode switching must be immediate on the first screen, while live connections, rule explanation, and logs remain one clean transition away rather than buried in stacked modals or scattered cards.
2. **Signal over telemetry noise:** Surface only actionable state on primary views; process internals, secondary counters, and low-frequency host parameters belong in dedicated inspection or settings views rather than competing with tunnel status.
3. **Shared mental model, native OS grammar:** Desktop and Android share core concepts (tunnel state, outbound mode, policy groups, live connections, portable profiles/rules, logs) while honoring desktop pointer/keyboard density on Slint and Material 3 touch/adaptive ergonomics on Android.
4. **Zero-compromise resource discipline:** Every visual and interactive choice must respect Nexus's low-memory, zero-bloat engineering ethos across resident tray and mobile background lifecycles.
