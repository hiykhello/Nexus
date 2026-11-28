---
version: 1
slug: "desktop-ui-app-window-slint"
primary_target: "desktop/ui/app_window.slint"
related_targets: ["android/app/src/main/kotlin/org/nexus/android/ui/NexusRootScreen.kt"]
---

# Nexus Desktop & Android Operate Surface Brief

Scope: Native Desktop (`desktop/ui/app_window.slint`) and Native Android (`android/app/src/main/kotlin/org/nexus/android/ui/NexusRootScreen.kt`) client shells.
Visitor mode: Operate.
Audience & job: Technical practitioners and power users toggling tunnels/system proxies in one second from a responsive multi-column Bento card Dashboard, managing subscription-grouped multi-protocol profiles (`VLESS`, `Trojan`, `Hysteria2`, `TUIC`, `WireGuard`, `MASQUE`, `Shadowsocks-2022`, `AnyTLS`, `Naive`, `Snell`, `SSH`, `SOCKS5/HTTP`, Policy Groups, Proxy Chains, Advanced Custom Configurations), and authoring routing rule-sets, DNS, and local inbound parameters.
Constraints: Preserve C++26 (`nexus-desktop-bridge`) and Kotlin (`:core-bridge`) storage/IPC invariants, continuous window/surface transparency (`window-opacity` / `surfaceAlpha`) with no Reduced Motion toggle, zero internal format or third-party client names exposed in UI copy, `<= 500` lines per source file, Slint v1.19 zero-shadow/zero-nested-card discipline, and Android Material 3 Adaptive (`compact` / `medium` / `expanded`) ergonomics.

## Direction contract

THESIS: Nexus delivers a flagship modern proxy-client Bento card console calibrated to Clash Verge Rev and FlClash — replacing austere borderless sheets and full-width horizontal strips with proportional, multi-column single-level Bento cards on a layered canvas ground and unifying subscription-grouped server management with full Nexus protocol coverage.

OWN-WORLD: Cool mist-slate canvas ground (`#F4F6F9`) with pure white (`#FFFFFF`) `12px`-radius `1px`-bordered (`#E2E8F0`) cards in light mode, and deep slate-obsidian ground (`#0F141C`) with elevated `#171E29` cards (`#263142` border) in dark mode; electric cobalt (`#2563EB` / `#60A5FA`) interactive primary, signal emerald (`#10B981` / `#059669`) live tunnel & fast-RTT state, warm amber (`#D97706` / `#F59E0B`) caution/upload accent, crisp system sans-serif UI prose, and tabular monospace strictly for endpoints, ports, latencies, and byte rates.

STORY: Opening Nexus in either Standby or Connected state reveals a complete, proportional multi-column Bento card dashboard with zero dead space and zero stretched horizontal strips across compact, standard, and wide viewports: the user toggles core/TUN/system proxy/LAN via 4 compact Quick-Control Tiles, switches `Rule / Global / Direct` mode and reads live dual-track RX/TX throughput, switches subscription groups or servers from a multi-column Node Tile Grid, verifies Mixed/SOCKS5/LAN/TUN inbounds and `2×2` target RTT tiles, and steps into a structured Profiles & Subscriptions console with full visual editors for every Nexus capability.

FIRST VIEWPORT: Desktop pairs a clean left navigation rail (`仪表盘`, `配置文件`, `代理组`, `路由与规则`, `DNS 与入站`, `连接`, `日志`, `设置`) with a responsive multi-column Bento card grid (`4-col` / `3-col` / `2-col`) on `#F4F6F9` / `#0F141C` capped cleanly on ultrawide screens. Android (`compact` / `medium` / `expanded`) renders the same proportional Bento tiles, 2-column node cards, and `2×2` connectivity matrix above the navigation bar/rail.

FORM: Category-standard flagship Bento card console (`canon`, calibrated to Clash Verge Rev + FlClash), chosen over the dealt hand from `seed:475806324cbdb2ec`.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
