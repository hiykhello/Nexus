# Nexus 4-Pillar Configuration Boundary

Nexus separates user-portable proxy configuration from platform-specific host runtime bindings so Desktop, Mobile, and headless CLI deployments can share one library format without mutating user profiles in place.

## 1. The Four Portable Pillars + Host Layer

| Layer | Responsibility | Portability | On-Disk Unit |
|---|---|---|---|
| **1. Nodes & Subscriptions** | Individual outbound proxy definitions and subscription metadata | 100% portable | `nodes/<id>.kdl`, `secrets/<id>.secret` (`0600`) |
| **2. Routing Presets** | Traffic matching rules, rule-set references, default outbound | 100% portable | `routings/<id>.kdl` (`bypass-lan-cn`, `global`, `direct`) |
| **3. DNS Presets** | Upstream DNS servers, DNS rules, FakeIP / cache policy | 100% portable | `dns/<id>.kdl` (`balanced`, `direct`, `fakeip`) |
| **4. Custom Profiles** | Complete hand-authored full KDL configurations | 100% portable | `custom/<id>.kdl` (read-only to host runtime) |
| **Host Layer** | Platform inbounds (`mixed`/`socks5`/`http`/`tun`), `state`, `control` (`socket` / `http-listen`), `log`, `workers`, `memory-watchdog`, `shutdown-grace-ms`, `sessions-per-listener`, `tcp-splice-pipes`, `ntp` | Host-specific | Ephemeral `runtime/` fragments or `runtime/host-override.kdl` |

Key architectural invariants:
- Refreshing a subscription updates only nodes belonging to that `subscription_id`; routing presets, DNS presets, and host settings are never altered.
- Custom profiles under `custom/<id>.kdl` are never mutated on disk to inject `device-fd`, control sockets, or runtime outbound modes.
- Live `rule` / `global` / `direct` outbound-mode switching uses the Control API (`mode` command) rather than rewriting KDL files.

## 2. Core CLI Primitives

### 2.1 Directory Composition (`--config-dir` / `-C`)
`nexus run` and `nexus check` load all non-hidden `*.kdl` files from a directory in lexicographical order and validate that top-level singletons and named inbound/outbound tags are not duplicated across fragments.

Standard Pillars composition layout inside the ephemeral `runtime/` directory:
- `00-host.kdl` — `schema-version`, `role`, `workers`, `state`, `control` (`socket` / `http-listen`), `log`, process singletons (`memory-watchdog`, `shutdown-grace-ms`, `sessions-per-listener`, `tcp-splice-pipes`, `ntp`)
- `10-inbounds.kdl` — host-managed listeners (`mixed`/`socks5`/`http` and/or platform `tun`)
- `20-dns.kdl` — selected DNS preset
- `30-outbounds.kdl` — `direct`, `block`, active subscription/group nodes, and `outbound "proxy" type="selector"` with `selected "<active_node_id>"`
- `40-routing.kdl` — selected Routing preset

### 2.2 AST Host Override (`--host-override <file>`)
Custom profiles (and optionally `--config-dir` trees) compose with a host-generated `host-override.kdl` via `cli::read_config_source(path, is_directory, host_override_path)` using the KDL 2.0 AST (`glaze::read_kdl` / `glaze::write_kdl`):

```kdl
host-override {
    strip-tun #true
    strip-inbounds #false
}
state { directory "/var/lib/nexus"; }
control socket="/run/nexus/control.sock"
inbound "android-tun" type="tun" {
    device-fd 3
    mtu 1500
}
```

Merge semantics (strictly AST-level, zero regex rewriting):
1. **`host-override { ... }` directives** (stripped from the merged output):
   - `strip-tun #true`: removes all `type="tun"` inbounds from the base document (both top-level `inbound` and inside `inbounds { ... }`, including ergonomic `tun "..."` shorthand).
   - `strip-inbounds #true`: removes all base inbounds (top-level `inbound` and `inbounds { ... }`).
   - Unknown directives or non-boolean arguments fail validation.
2. **Top-level singletons**: `schema-version`, `role`, `workers`, `state`, `control`, `log`, `certificate`, `memory-watchdog`, `shutdown-grace-ms`, `sessions-per-listener`, `tcp-splice-pipes`, and `ntp` in `host-override.kdl` replace matching base singletons in place (or append if absent; `schema-version` inserts at document start if absent).
3. **Inbound merging**:
   - Any `type="tun"` inbound in `host-override.kdl` automatically strips pre-existing base TUN inbounds before insertion (regardless of `host-override { strip-tun ... }` directive order).
   - An override inbound whose name matches a base inbound replaces it in place; otherwise it appends into the base `inbounds { ... }` container if present (or as a canonical top-level `inbound` otherwise), preserving Nexus's rule against mixing `inbounds { ... }` with top-level `inbound`.
   - Empty `inbounds { }` blocks left after stripping are removed cleanly.
4. **Hot reload persistence**: `nexus run [--traffic-stats] [--host-override <file>] (--config|-c <file> | --config-dir|-C <dir>)` accepts `--host-override` before or after `--config`/`--config-dir` and re-applies `host-override.kdl` on every `SIGHUP` / Control API / provider / remote rule-set reload.

### 2.3 Validation & Staged Effective KDL (`nexus check --print-merged`)
```sh
nexus check [--config|-c <file> | --config-dir|-C <dir>] [--host-override <file>] [--print-merged]
```
Runs full config validation (base read + `--host-override` AST merge + proxy-provider expansion + KDL schema parsing + route-file loading + per-inbound route compilation).
- Without `--print-merged`: prints `configuration valid` on exit `0`.
- With `--print-merged`: writes ONLY the validated merged KDL to `stdout` on exit `0` (enabling privileged TUN helpers with pinned runtime directories to stage `00-effective.kdl` without re-prompting for elevation).

### 2.4 Structured Node Import (`nexus convert-config --emit-nodes-json`)
```sh
nexus convert-config --emit-nodes-json \
  [--from <format>] \
  [--secrets-dir <dir>] [--include <re>] [--exclude <re>] [--tag-prefix <p>] \
  [-o <output>] <input|->
```
Parses share URIs, base64 lists, or external subscription documents through `provider::parse_subscription` + `provider::apply_filter` + `provider::emit_outbound_kdl`, writes credentials atomically with mode `0600` inside `--secrets-dir` when specified, emits warnings exclusively to `stderr`, and writes strict RFC 8259 JSON to `stdout`:

```json
{
  "nodes": [
    {
      "tag": "hk-edge-1",
      "protocol": "vless",
      "host": "198.51.100.10",
      "port": 443,
      "secret_file": "/path/to/secrets/hk-edge-1-uuid.secret",
      "secret_files": ["/path/to/secrets/hk-edge-1-uuid.secret"],
      "kdl": "outbound \"hk-edge-1\" type=\"vless\" {\n  server host=\"198.51.100.10\" port=443\n...\n}\n"
    }
  ]
}
```

Each node's `kdl` is dedented to a standalone top-level `outbound` block ready to save directly into `nodes/<id>.kdl`. Multi-secret protocols (`tuic`, `wireguard`, `hysteria2` with salamander) populate all written `0600` credential paths in `secret_files` (with `secret_file` retaining the first path), and any node that fails validation removes partially written secrets before returning.

## 3. Shared Portable On-Disk Library Schema

Both Desktop and Android store portable user libraries using the same `library.json` v1 index and directory layout:

```text
<library-root>/
  library.json          # v1 metadata index (active mode/ids, subscriptions, nodes)
  nodes/<id>.kdl        # single standalone outbound block per node
  routings/<id>.kdl     # single routing block (builtins: bypass-lan-cn, global, direct)
  dns/<id>.kdl          # single dns block (builtins: balanced, direct, fakeip)
  custom/<id>.kdl       # untouched full KDL profiles
  secrets/<id>.secret   # 0600 credential files referenced by nodes/<id>.kdl
```

`library.json` schema (version `1`):
```json
{
  "version": 1,
  "active_mode": "pillars",
  "active_subscription_id": "manual",
  "active_node_id": "",
  "active_routing_id": "bypass-lan-cn",
  "active_dns_id": "balanced",
  "active_custom_id": "",
  "subscriptions": [
    {
      "id": "manual",
      "name": "Manual",
      "url": "",
      "auto_update_min": 0,
      "filter_include": "",
      "filter_exclude": "",
      "updated_epoch_s": 0
    }
  ],
  "nodes": [
    {
      "id": "node-1",
      "subscription_id": "manual",
      "name": "HK Edge",
      "protocol": "vless",
      "host": "198.51.100.10",
      "port": 443,
      "latency_ms": -1,
      "pinned": false,
      "secret_file": "",
      "updated_epoch_s": 0
    }
  ]
}
```

## 4. Unified Single-Source Core Workspace Compiler (`v1`)

Desktop and Mobile clients persist canonical **Layer 1** `workspace.json` (`0600`) and **Layer 3** `host.json` independently (keeping **Layer 4** telemetry out of both) and invoke one shared C++26 compiler inside Nexus Core so every platform gets identical DAG/chain resolution, `0600` content-hashed secrets, routing-to-DNS coupling, and full `config::parse_kdl` validation.

### 4.1 CLI & C API Entrypoints
- **CLI**:
  ```sh
  nexus workspace compose \
    --workspace <workspace.json> --host <host.json> --secrets-dir <dir> \
    [--active <profile-id>] [--emit-kdl <out.kdl>] [--json-result]
  ```
  Writes strict RFC 8259 UTF-8 JSON to `stdout` when `--json-result` is set:
  ```json
  {"ok":true,"active_tag":"HK-Edge","selector_tag":"proxy","selector_members":["HK-Edge","JP-Edge"],"warnings":[],"errors":[],"secret_files":["/path/to/secrets/vless-uuid-....secret"],"kdl":"..."}
  ```
- **C API** (`include/nexus/core_c_api.h`):
  ```c
  int nexus_core_compose_workspace(
      const char* workspace_json, const char* host_json,
      const char* secrets_dir, const char* active_profile_id,
      char* out_buf, size_t out_cap, size_t* out_len,
      char* err_buf, size_t err_cap);
  ```
  Follows the `-4` buffer-size query convention (`*out_len` receives exact JSON byte length), returning `0` on `ok: true`, `-2` on validation/compilation errors (structured JSON still populated), and `-1` on invalid null pointers.

### 4.2 Layer 1 (`workspace.json`, `schema_version: 1`) & Layer 3 (`host.json`, `schema_version: 1`)
- **`workspace.json`** (100% portable; zero host ports, OS proxy settings, per-app split-tunnel host flags, or telemetry):
  - `profiles[]`: polymorphic 5-kind entries (`node`, `custom_outbound`, `policy_group`, `proxy_chain`, `full_custom_kdl`).
  - `subscriptions[]`: subscription metadata, regex filters, optional `prev_profile_id` / `next_profile_id` sub-chaining, and `usage` quota fields.
  - `routing_profiles[]`: ordered rules with `scope` (`both`/`routing_only`/`dns_only`), `target_type` (`proxy`/`direct`/`block`/`profile_id`), domain/IP/rule-set/port/network/protocol predicates, platform-scoped `desktop_process[]` and `android_packages[]`, and `tls_fragment`.
  - `dns`: `simple` (auto-derived bootstrap/direct/remote servers, FakeIP IPv4 `/16..30`, `block_aaaa`, `block_svcb_https`, underscore `strategy`, `ProtectDomainList` loop prevention, routing-to-DNS split coupling) or `raw_kdl`.
  - `rule_set_assets[]`: local or remote rule-set registry (emitted only when referenced).
  - `full_template`: optional KDL overlay (`append_proxies_only`, `proxy_detour`).
- **`host.json`** (host-only, never synced; unknown UI-only keys ignored by Core):
  - Common: `platform` (`desktop-linux`, `desktop-windows`, `desktop-macos`, `android`, `ios`), `log_level`, `log_file`, `workers`, `state_dir`, `cache_dir`, `control_socket`, `control_http_listen`, `control_bearer_file`, `ca_file`, `include_sibling_nodes_in_selector`, `max_selector_members`.
  - `desktop`: mixed/second-local/LAN listeners (with `0600` password auth), TUN (`stack "system"`, MTU, CIDRs, `auto-route`, `strict-route` with Linux single-inbound mixed suppression), and physical bind options.
  - `android`: `run_mode` (`vpn` vs `proxy_only`), optional local mixed listener, TUN (`stack "system"`, MTU, `endpoint-independent-nat #false`, omitting `auto-route`/`inet4-address` for external `tun-fd`), `protect_socket_path` (propagated to `direct`, non-detoured physical outbounds, and explicit `detour="direct"` on direct encrypted DNS), and `dns_listen`.

### 4.3 7-Stage Compiler Guarantees
1. **Fail-Closed `proxy_chain`**: missing/deleted/cyclic hops, `full_custom_kdl` hops, `vless+xhttp` hops, and non-`selector` policy groups (`url-test`/`fallback`/`load-balance`) fail compilation cleanly with zero newly created secret files left behind.
2. **Zero-Compromise TLS**: never emits `verify #false`; supports system CA store, `host.ca_file`, per-node `0600` `ca_pem`, `cert_sha256` pins, Reality base64url/hex public keys, and QUIC ECH; skips/rejects unsupported legacy ciphers and protocols with explicit diagnostics.
3. **Sibling Selector & Live Switch**: populates top-level `selector "proxy"` with up to `min(max_selector_members, 240)` sibling nodes so Desktop and Android can switch nodes live via `PUT /v1/groups/proxy` without restarting TUN.
4. **Platform Isolation**: `desktop_process` predicates are emitted only on `desktop-*` hosts; `android_packages` predicates are emitted only on `android` hosts.
5. **In-Memory Verification**: every compiled KDL document passes full `config::parse_kdl` before returning `ok: true`; any failure triggers rollback of newly created secrets.

## 5. Platform Host Settings Isolation

- **Desktop**: stores host preferences (`inbound_mixed/socks/http` enablement & ports, `allow_lan`, `tun_enabled`, `tun_mtu`, `tun_elevate_persistent`, `outbound_mode`) outside the portable library and composes `<config-dir>/runtime/`.
- **Android**: stores host preferences (`runMode` VPN vs Proxy-Only, `splitTunnelMode` Exclude vs Include, `splitTunnelPackages`, `allowBypass`, `excludeSelfFromVpn`, `mtu`, `memoryBudgetMiB`, `localSocksPort`) outside the portable library and composes `<noBackupFilesDir>/runtime/`.
