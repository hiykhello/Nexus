# Nexus Web Console

Lightweight control-plane dashboard built with **pnpm + TypeScript 7 + Vite 8 + Lit + `@elelcode/lit-router`**.
Static build artifacts (`web/dist/`) can be embedded directly into the Nexus Core binary (default when `control http-listen` is enabled) or served from a custom directory via `control dashboard-root="..."` with zero runtime Node dependency.

## Features

- **Multiplexed RFC 6455 WebSocket + SSE fallback**: prefers single-connection `/v1/ws` (`metrics`, `connections`, `logs`) with browser first-frame auth (`{"type":"auth","token":"..."}`, never `?token=` in URL), and transparently falls back to `fetch` `ReadableStream` SSE (`/v1/status?stream=1`, `/v1/connections?stream=1`, `/v1/logs?stream=1`) + polling.
- **Matte Bento design system** with persisted Dark / Light / Auto themes and bilingual **EN / 中文** switching.
- **Full control-plane coverage**: route mode switching (`PUT /v1/mode`), single-outbound and group probes (`POST /v1/outbounds/{tag}/probe`, `POST /v1/groups/{tag}/probe`), live searchable routing rules (`GET /v1/rules`), interactive live DNS query (`GET /v1/dns/query`), FakeIP/DNS/ruleset cache flushing (`POST /v1/cache/fakeip/flush`, `POST /v1/state/clear-cache`), live log level control (`POST /v1/log-level`), OpenMetrics telemetry (`/metrics`), and `ssmapi` metering.
- **Keyboard shortcuts**: `1`–`6` switch pages, `/` focuses page search, `R` refreshes active view.

## Development & Build

```bash
cd web
pnpm install
pnpm run typecheck
pnpm test
pnpm run build   # Outputs static assets to web/dist/
pnpm dev         # Local dev server proxying /v1, /metrics, /ssmapi -> http://127.0.0.1:9090
```

## Syncing Embedded Core Assets

After rebuilding `web/dist/`, refresh the built-in Core dashboard bundle with:

```bash
python3 scripts/embed-web-dashboard.py
```

## Serving from Nexus Control Plane

When `http-listen` is enabled without `dashboard-root` (or with `dashboard-root="embedded"`), Nexus automatically serves the built-in embedded Web Console. Pre-compressed embedded assets (such as the JavaScript bundle) are served with `Content-Encoding: gzip` and `Vary: Accept-Encoding` (compatible with all modern browsers and `curl --compressed`, with zero runtime `zlib` dependency in Core); requests whose `Accept-Encoding` header explicitly excludes `gzip` (e.g. `identity` or `gzip;q=0`) receive `406 Not Acceptable`. Specifying a custom directory path in `dashboard-root` overrides the embedded assets:

```kdl
control http-listen="127.0.0.1:9090" bearer-token-file="/path/to/token" metrics=#true
# Optional override with external static build directory:
# control http-listen="127.0.0.1:9090" bearer-token-file="/path/to/token" dashboard-root="/path/to/web/dist" metrics=#true
```

Bearer tokens are sent strictly via the `Authorization: Bearer` HTTP header and stored only in the current tab's `sessionStorage` (never passed in URL query strings).
