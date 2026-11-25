module;

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

module desktop.workspace_sync;

import std;
import desktop.mini_json;

#include "workspace_sync_proc.hpp"

namespace desktop {
    auto parse_share_export_json(std::string_view json_text) -> ShareExportResult {
        ShareExportResult res{};
        auto parsed = json_parse(json_text);
        if (!parsed || !parsed->is_object()) {
            res.errors.push_back(parsed ? "share export JSON root must be object" : parsed.error());
            return res;
        }
        auto const& o = std::get<JsonObject>(parsed->data);
        res.ok = json_get_bool(o, "ok", false);
        res.uri = json_get_string(o, "uri");
        res.exported_count = json_get_i64(o, "exported_count", 0);
        res.warnings = json_get_string_vec(o, "warnings");
        res.errors = json_get_string_vec(o, "errors");
        if (!res.ok && res.errors.empty()) res.errors.push_back("export-share failed");
        return res;
    }

    auto parse_share_import_json(std::string_view json_text) -> ShareImportResult {
        ShareImportResult res{};
        auto parsed = json_parse(json_text);
        if (!parsed || !parsed->is_object()) {
            res.errors.push_back(parsed ? "share import JSON root must be object" : parsed.error());
            return res;
        }
        auto const& o = std::get<JsonObject>(parsed->data);
        res.ok = json_get_bool(o, "ok", false);
        res.imported_ids = json_get_string_vec(o, "imported_ids");
        res.warnings = json_get_string_vec(o, "warnings");
        res.errors = json_get_string_vec(o, "errors");
        res.workspace_json = json_get_string(o, "workspace_json");
        if (!res.ok && res.errors.empty()) res.errors.push_back("import-share failed");
        return res;
    }

    auto parse_sync_seal_json(std::string_view json_text) -> SyncSealResult {
        SyncSealResult res{};
        auto parsed = json_parse(json_text);
        if (!parsed || !parsed->is_object()) {
            res.errors.push_back(parsed ? "seal-sync JSON root must be object" : parsed.error());
            return res;
        }
        auto const& o = std::get<JsonObject>(parsed->data);
        res.ok = json_get_bool(o, "ok", false);
        res.revision = json_get_i64(o, "revision", 0);
        res.updated_at_ms = json_get_i64(o, "updated_at_ms", 0);
        res.envelope_sha256 = json_get_string(o, "envelope_sha256");
        res.warnings = json_get_string_vec(o, "warnings");
        res.errors = json_get_string_vec(o, "errors");
        res.envelope_json = json_get_string(o, "envelope_json");
        if (!res.ok && res.errors.empty()) res.errors.push_back("seal-sync failed");
        return res;
    }

    auto parse_sync_open_json(std::string_view json_text) -> SyncOpenResult {
        SyncOpenResult res{};
        auto parsed = json_parse(json_text);
        if (!parsed || !parsed->is_object()) {
            res.errors.push_back(parsed ? "open-sync JSON root must be object" : parsed.error());
            return res;
        }
        auto const& o = std::get<JsonObject>(parsed->data);
        res.ok = json_get_bool(o, "ok", false);
        res.revision = json_get_i64(o, "revision", 0);
        res.updated_at_ms = json_get_i64(o, "updated_at_ms", 0);
        res.device_label = json_get_string(o, "device_label");
        res.warnings = json_get_string_vec(o, "warnings");
        res.errors = json_get_string_vec(o, "errors");
        res.workspace_json = json_get_string(o, "workspace_json");
        if (!res.ok && res.errors.empty()) res.errors.push_back("open-sync failed");
        return res;
    }

    auto parse_sync_envelope_meta(std::string_view json_text) -> SyncEnvelopeMeta {
        SyncEnvelopeMeta m{};
        auto parsed = json_parse(json_text);
        if (!parsed || !parsed->is_object()) return m;
        auto const& o = std::get<JsonObject>(parsed->data);
        m.format = json_get_string(o, "format");
        m.revision = json_get_i64(o, "revision", 0);
        m.updated_at_ms = json_get_i64(o, "updated_at_ms", 0);
        m.device_label = json_get_string(o, "device_label");
        m.valid = (m.format == "nexus-sync-v1" && !json_get_string(o, "ciphertext_b64").empty());
        return m;
    }

    auto parse_udp_probe_json(std::string_view json_text) -> UdpProbeResult {
        UdpProbeResult res{};
        auto parsed = json_parse(json_text);
        if (!parsed || !parsed->is_object()) {
            res.error = parsed ? "udp-probe JSON root must be object" : parsed.error();
            return res;
        }
        auto const& o = std::get<JsonObject>(parsed->data);
        res.ok = json_get_bool(o, "ok", false);
        res.kind = json_get_string(o, "kind");
        res.via_socks5 = json_get_bool(o, "via_socks5", false);
        res.rtt_ms = json_get_i64(o, "rtt_ms", 0);
        res.attempts = json_get_i64(o, "attempts", 0);
        res.detail = json_get_string(o, "detail");
        res.error = json_get_string(o, "error");
        return res;
    }

    auto build_export_share_argv(
        std::filesystem::path const& core_binary,
        std::filesystem::path const& workspace_file,
        std::span<std::string const> profile_ids) -> std::vector<std::string> {
        if (core_binary.empty() || workspace_file.empty() || profile_ids.empty()) return {};
        std::vector<std::string> argv{
            ws_sync_detail::path_to_utf8(core_binary), "workspace", "export-share",
            "--workspace", ws_sync_detail::path_to_utf8(workspace_file),
        };
        for (auto const& id : profile_ids) {
            if (!id.empty()) { argv.push_back("--id"); argv.push_back(id); }
        }
        argv.push_back("--json-result");
        return argv;
    }

    auto build_import_share_argv(
        std::filesystem::path const& core_binary,
        std::filesystem::path const& workspace_file,
        std::filesystem::path const& uri_file,
        std::string_view subscription_id,
        std::filesystem::path const& out_workspace) -> std::vector<std::string> {
        if (core_binary.empty() || workspace_file.empty() || uri_file.empty()) return {};
        std::vector<std::string> argv{
            ws_sync_detail::path_to_utf8(core_binary), "workspace", "import-share",
            "--workspace", ws_sync_detail::path_to_utf8(workspace_file),
            "--uri-file", ws_sync_detail::path_to_utf8(uri_file),
        };
        if (!subscription_id.empty()) { argv.push_back("--subscription-id"); argv.emplace_back(subscription_id); }
        if (!out_workspace.empty()) { argv.push_back("--out-workspace"); argv.push_back(ws_sync_detail::path_to_utf8(out_workspace)); }
        argv.push_back("--json-result");
        return argv;
    }

    auto build_udp_probe_argv(
        std::filesystem::path const& core_binary,
        std::string_view kind,
        std::string_view target,
        std::string_view socks5,
        int timeout_ms,
        int attempts) -> std::vector<std::string> {
        if (core_binary.empty() || kind.empty()) return {};
        std::vector<std::string> argv{
            ws_sync_detail::path_to_utf8(core_binary), "tools", "udp-probe",
            "--kind", std::string(kind),
        };
        if (!target.empty()) { argv.push_back("--target"); argv.emplace_back(target); }
        if (!socks5.empty()) { argv.push_back("--socks5"); argv.emplace_back(socks5); }
        if (timeout_ms > 0) { argv.push_back("--timeout-ms"); argv.push_back(std::to_string(timeout_ms)); }
        if (attempts > 0) { argv.push_back("--attempts"); argv.push_back(std::to_string(attempts)); }
        argv.push_back("--json");
        return argv;
    }

    auto export_share_via_core(
        std::filesystem::path const& core_binary,
        std::filesystem::path const& workspace_file,
        std::span<std::string const> profile_ids) -> ShareExportResult {
        ShareExportResult err{};
        std::error_code ec;
        if (!std::filesystem::is_regular_file(core_binary, ec)) { err.errors.push_back("core binary not found"); return err; }
        auto argv = build_export_share_argv(core_binary, workspace_file, profile_ids);
        if (argv.empty()) { err.errors.push_back("missing export-share arguments"); return err; }
        auto [launched, code, out] = ws_sync_detail::run_core_sync_proc(argv);
        if (!launched) { err.errors.push_back(out); return err; }
        auto res = parse_share_export_json(out);
        if (code != 0) res.ok = false;
        return res;
    }

    auto import_share_via_core(
        std::filesystem::path const& core_binary,
        std::filesystem::path const& workspace_file,
        std::string_view uri,
        std::string_view subscription_id,
        std::filesystem::path const& out_workspace,
        std::filesystem::path const& secrets_dir) -> ShareImportResult {
        ShareImportResult err{};
        std::error_code ec;
        if (!std::filesystem::is_regular_file(core_binary, ec)) { err.errors.push_back("core binary not found"); return err; }
        if (uri.empty()) { err.errors.push_back("share URI is required"); return err; }
        ws_sync_detail::ScopedSecretTempFile uri_file;
        if (!uri_file.create(secrets_dir, "nexus-share-uri", uri)) {
            err.errors.push_back("failed to stage transient 0600 share URI file");
            return err;
        }
        auto argv = build_import_share_argv(core_binary, workspace_file, uri_file.path(), subscription_id, out_workspace);
        if (argv.empty()) { uri_file.wipe_and_remove(); err.errors.push_back("missing import-share arguments"); return err; }
        auto [launched, code, out] = ws_sync_detail::run_core_sync_proc(argv);
        uri_file.wipe_and_remove();
        if (!launched) { err.errors.push_back(out); return err; }
        auto res = parse_share_import_json(out);
        if (code != 0) res.ok = false;
        return res;
    }

    auto seal_sync_via_core(
        std::filesystem::path const& core_binary,
        std::filesystem::path const& workspace_file,
        std::string_view passphrase,
        std::string_view device_label,
        std::filesystem::path const& secrets_dir) -> SyncSealResult {
        SyncSealResult err{};
        std::error_code ec;
        if (!std::filesystem::is_regular_file(core_binary, ec)) { err.errors.push_back("core binary not found"); return err; }
        if (passphrase.empty()) { err.errors.push_back("sync passphrase is required"); return err; }
        ws_sync_detail::ScopedSecretTempFile pass_file;
        if (!pass_file.create(secrets_dir, "nexus-sync-pass", passphrase)) {
            err.errors.push_back("failed to create transient 0600 passphrase file");
            return err;
        }
        std::vector<std::string> argv{
            ws_sync_detail::path_to_utf8(core_binary), "workspace", "seal-sync",
            "--workspace", ws_sync_detail::path_to_utf8(workspace_file),
            "--passphrase-file", ws_sync_detail::path_to_utf8(pass_file.path()),
        };
        if (!device_label.empty()) { argv.push_back("--device-label"); argv.emplace_back(device_label); }
        argv.push_back("--json-result");
        auto [launched, code, out] = ws_sync_detail::run_core_sync_proc(argv);
        pass_file.wipe_and_remove();
        if (!launched) { err.errors.push_back(out); return err; }
        auto res = parse_sync_seal_json(out);
        if (code != 0) res.ok = false;
        return res;
    }

    auto open_sync_via_core(
        std::filesystem::path const& core_binary,
        std::string_view envelope_json,
        std::string_view passphrase,
        std::filesystem::path const& secrets_dir) -> SyncOpenResult {
        SyncOpenResult err{};
        std::error_code ec;
        if (!std::filesystem::is_regular_file(core_binary, ec)) { err.errors.push_back("core binary not found"); return err; }
        if (passphrase.empty() || envelope_json.empty()) { err.errors.push_back("envelope and sync passphrase are required"); return err; }
        ws_sync_detail::ScopedSecretTempFile pass_file, env_file;
        if (!pass_file.create(secrets_dir, "nexus-sync-pass", passphrase) ||
            !env_file.create(secrets_dir, "nexus-sync-env", envelope_json)) {
            err.errors.push_back("failed to create transient 0600 sync files");
            return err;
        }
        std::vector<std::string> argv{
            ws_sync_detail::path_to_utf8(core_binary), "workspace", "open-sync",
            "--envelope", ws_sync_detail::path_to_utf8(env_file.path()),
            "--passphrase-file", ws_sync_detail::path_to_utf8(pass_file.path()),
            "--json-result",
        };
        auto [launched, code, out] = ws_sync_detail::run_core_sync_proc(argv);
        pass_file.wipe_and_remove();
        env_file.wipe_and_remove();
        if (!launched) { err.errors.push_back(out); return err; }
        auto res = parse_sync_open_json(out);
        if (code != 0) res.ok = false;
        return res;
    }

    auto run_udp_probe_via_core(
        std::filesystem::path const& core_binary,
        std::string_view kind,
        std::string_view target,
        std::string_view socks5,
        int timeout_ms,
        int attempts) -> UdpProbeResult {
        UdpProbeResult err{};
        err.kind = std::string(kind);
        std::error_code ec;
        if (!std::filesystem::is_regular_file(core_binary, ec)) { err.error = "core binary not found"; return err; }
        auto argv = build_udp_probe_argv(core_binary, kind, target, socks5, timeout_ms, attempts);
        if (argv.empty()) { err.error = "missing udp-probe arguments"; return err; }
        auto [launched, code, out] = ws_sync_detail::run_core_sync_proc(argv);
        if (!launched) { err.error = out; return err; }
        auto res = parse_udp_probe_json(out);
        if (code != 0) res.ok = false;
        if (!res.ok && res.error.empty()) res.error = std::format("udp-probe exited with code {}", code);
        return res;
    }
}
