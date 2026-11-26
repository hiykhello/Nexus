# Nexus Web Console

Lightweight control-plane dashboard built with **pnpm + TypeScript 7 + Vite 8 + Lit + `@elelcode/lit-router`**.
Static build artifacts (`web/dist/`) are served directly by Nexus `control dashboard-root="..."` with zero runtime Node dependency.

## Features

- **Real-time SSE streaming** (`/v1/status?stream=1`, `/v1/connections?stream=1`, `/v1/logs?stream=1`) over `fetch` `ReadableStream` with `Authorization: Bearer` header, exponential backoff reconnect, and automatic polling fallback.
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

## Serving from Nexus Control Plane

```kdl
control http-listen="127.0.0.1:9090" bearer-token-file="/path/to/token" dashboard-root="/path/to/web/dist" metrics=#true
```

Bearer tokens are sent strictly via the `Authorization: Bearer` HTTP header and stored only in the current tab's `sessionStorage` (never passed in URL query strings).
