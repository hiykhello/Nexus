// CLI subcommands: `nexus workspace {compose|export-share|import-share|seal-sync|open-sync}`.
#if !defined(_WIN32)
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

import std;
import cli.route_files;
import crypto;
import provider.workspace_compose;
import rulefile;

namespace {
    constexpr std::string_view workspace_usage =
        "usage:\n"
        "  nexus workspace compose --workspace <ws.json> --host <host.json> --secrets-dir <dir> [--active <id>] [--emit-kdl <out.kdl>] [--json-result]\n"
        "  nexus workspace export-share --workspace <ws.json> --id <profile-id> [--id <id2>...] [--json-result]\n"
        "  nexus workspace import-share --workspace <ws.json> --uri <nexus://...> [--subscription-id <sub-id>] [--out-workspace <out.json>] [--json-result]\n"
        "  nexus workspace seal-sync --workspace <ws.json> (--passphrase-file <file> | --passphrase-env <VAR>) [--device-label <lbl>] [--out <env.enc>] [--json-result]\n"
        "  nexus workspace open-sync --envelope <env.enc> (--passphrase-file <file> | --passphrase-env <VAR>) [--out-workspace <ws.json>] [--json-result]\n";

    struct StringCleaner {
        std::string& s;
        ~StringCleaner() {
            if (!s.empty()) crypto::cleanse({reinterpret_cast<std::uint8_t*>(s.data()), s.size()});
        }
    };

    auto resolve_path(std::string_view raw) -> std::filesystem::path {
        std::filesystem::path p(raw);
        if (p.is_relative()) if (auto wd = cli::working_directory()) p = *wd / p;
        return p;
    }

    auto write_file_atomic(std::filesystem::path const& target, std::string_view content) -> std::expected<void, std::string> {
        std::error_code ec;
        auto parent = target.has_parent_path() ? target.parent_path() : std::filesystem::current_path(ec);
        if (ec) return std::unexpected("cannot resolve output directory: " + ec.message());
        std::filesystem::create_directories(parent, ec);
        if (ec) return std::unexpected("cannot create output directory: " + ec.message());
#if !defined(_WIN32)
        auto canon_parent = std::filesystem::weakly_canonical(parent, ec);
        if (ec) return std::unexpected("cannot canonicalize output directory: " + ec.message());
        int dfd = ::open(canon_parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (dfd < 0) return std::unexpected("cannot open output directory safely: " + canon_parent.string());
        struct DirFd { int fd; ~DirFd() { if (fd >= 0) ::close(fd); } } d{dfd};
        struct stat st{};
        if (::fstat(dfd, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != ::geteuid())
            return std::unexpected("output directory ownership check failed: " + canon_parent.string());
        auto base = target.filename().string();
        if (base.empty() || base == "." || base == "..") return std::unexpected("invalid output filename");
        static std::atomic<std::uint64_t> seq{0};
        auto tmp = std::format(".{}.tmp.{}.{}", base, ::getpid(), seq.fetch_add(1, std::memory_order_relaxed));
        int fd = ::openat(dfd, tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) return std::unexpected("cannot create output file: " + target.string());
        auto drop = [&] { ::close(fd); (void)::unlinkat(dfd, tmp.c_str(), 0); };
        if (::fchmod(fd, 0600) != 0) { drop(); return std::unexpected("cannot chmod output file: " + target.string()); }
        for (std::size_t off = 0; off < content.size();) {
            auto n = ::write(fd, content.data() + off, content.size() - off);
            if (n <= 0) { if (n < 0 && errno == EINTR) continue; drop(); return std::unexpected("write failed: " + target.string()); }
            off += static_cast<std::size_t>(n);
        }
        if (::close(fd) != 0 || ::renameat(dfd, tmp.c_str(), dfd, base.c_str()) != 0) {
            (void)::unlinkat(dfd, tmp.c_str(), 0);
            return std::unexpected("cannot replace output file: " + target.string());
        }
        return {};
#else
        std::ofstream out(target, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!out) return std::unexpected("cannot write " + target.string());
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
        out.close();
        if (!out) return std::unexpected("write failed for " + target.string());
        return {};
#endif
    }

    auto read_passphrase(std::string const& file, std::string const& env_var) -> std::expected<std::string, std::string> {
        if (!file.empty()) {
            auto raw = ::rulefile::read_regular_file(resolve_path(file).string());
            if (!raw) return std::unexpected("passphrase file: " + raw.error());
            StringCleaner clean_raw{*raw};
            std::string p = *raw;
            while (!p.empty() && (p.back() == '\n' || p.back() == '\r')) p.pop_back();
            if (p.empty()) return std::unexpected("passphrase file is empty");
            return p;
        }
        char const* v = std::getenv(env_var.c_str());
        if (!v || !v[0]) return std::unexpected("passphrase environment variable is unset or empty: " + env_var);
        std::string p(v);
        while (!p.empty() && (p.back() == '\n' || p.back() == '\r')) p.pop_back();
        if (p.empty()) return std::unexpected("passphrase environment variable is empty");
        return p;
    }

    auto next_arg(int argc, char** argv, int& i, std::string_view flag) -> std::expected<std::string_view, int> {
        if (i + 1 >= argc || std::string_view(argv[i + 1]).empty()) {
            std::cerr << "missing or empty value for " << flag << '\n';
            return std::unexpected(2);
        }
        return std::string_view(argv[++i]);
    }

    auto set_once_arg(int argc, char** argv, int& i, std::string_view flag, std::string& dst) -> std::expected<void, int> {
        if (!dst.empty()) { std::cerr << "duplicate option: " << flag << '\n'; return std::unexpected(2); }
        auto v = next_arg(argc, argv, i, flag);
        if (!v) return std::unexpected(v.error());
        dst = *v;
        return {};
    }

    auto cmd_compose(int argc, char** argv) -> int {
        std::string ws_p, host_p, sec_d, active_id, emit_p;
        bool json_result = false;
        for (int i = 2; i < argc; ++i) {
            std::string_view a(argv[i]);
            if (a == "--json-result") json_result = true;
            else if (a == "--workspace") { if (auto r = set_once_arg(argc, argv, i, a, ws_p); !r) return r.error(); }
            else if (a == "--host") { if (auto r = set_once_arg(argc, argv, i, a, host_p); !r) return r.error(); }
            else if (a == "--secrets-dir") { if (auto r = set_once_arg(argc, argv, i, a, sec_d); !r) return r.error(); }
            else if (a == "--active") { if (auto r = set_once_arg(argc, argv, i, a, active_id); !r) return r.error(); }
            else if (a == "--emit-kdl") { if (auto r = set_once_arg(argc, argv, i, a, emit_p); !r) return r.error(); }
            else { std::cerr << "unknown option: " << a << '\n' << workspace_usage; return 2; }
        }
        if (ws_p.empty() || host_p.empty() || sec_d.empty()) { std::cerr << workspace_usage; return 2; }
        auto emit_err = [&](std::string msg) -> int {
            if (json_result) {
                provider::WorkspaceComposeResult r{}; r.errors.push_back(std::move(msg));
                std::cout << provider::serialize_compose_result_json(r);
            } else std::cerr << "workspace compose: " << msg << '\n';
            return 1;
        };
        auto ws_t = ::rulefile::read_regular_file(resolve_path(ws_p).string());
        if (!ws_t) return emit_err("workspace file: " + ws_t.error());
        auto host_t = ::rulefile::read_regular_file(resolve_path(host_p).string());
        if (!host_t) return emit_err("host file: " + host_t.error());
        auto res = provider::compose_workspace(*ws_t, *host_t, {resolve_path(sec_d).string(), active_id});
        if (res.ok && !emit_p.empty()) {
            if (auto ok = write_file_atomic(resolve_path(emit_p), res.kdl); !ok) { res.ok = false; res.errors.push_back(ok.error()); }
        }
        if (json_result) { std::cout << provider::serialize_compose_result_json(res); return res.ok ? 0 : 1; }
        for (auto const& w : res.warnings) std::cerr << "warning: " << w << '\n';
        if (!res.ok) { for (auto const& e : res.errors) std::cerr << "workspace compose: " << e << '\n'; return 1; }
        if (emit_p.empty()) std::cout << res.kdl;
        return 0;
    }

    auto cmd_export_share(int argc, char** argv) -> int {
        std::string ws_p;
        std::vector<std::string> ids;
        bool json_result = false;
        for (int i = 2; i < argc; ++i) {
            std::string_view a(argv[i]);
            if (a == "--json-result") json_result = true;
            else if (a == "--workspace") { if (auto r = set_once_arg(argc, argv, i, a, ws_p); !r) return r.error(); }
            else if (a == "--id") { auto v = next_arg(argc, argv, i, a); if (!v) return v.error(); ids.emplace_back(*v); }
            else { std::cerr << "unknown option: " << a << '\n' << workspace_usage; return 2; }
        }
        if (ws_p.empty() || ids.empty()) { std::cerr << workspace_usage; return 2; }
        auto emit_err = [&](std::string msg) -> int {
            if (json_result) {
                provider::WorkspaceShareExportResult r{}; r.errors.push_back(std::move(msg));
                std::cout << provider::serialize_share_export_result_json(r);
            } else std::cerr << "workspace export-share: " << msg << '\n';
            return 1;
        };
        auto ws_t = ::rulefile::read_regular_file(resolve_path(ws_p).string());
        if (!ws_t) return emit_err("workspace file: " + ws_t.error());
        auto res = provider::export_workspace_share(*ws_t, ids);
        if (json_result) { std::cout << provider::serialize_share_export_result_json(res); return res.ok ? 0 : 1; }
        if (!res.ok) { for (auto const& e : res.errors) std::cerr << "workspace export-share: " << e << '\n'; return 1; }
        std::cout << res.uri << '\n';
        return 0;
    }

    auto cmd_import_share(int argc, char** argv) -> int {
        std::string ws_p, uri, uri_file, sub_id, out_ws;
        bool json_result = false;
        for (int i = 2; i < argc; ++i) {
            std::string_view a(argv[i]);
            if (a == "--json-result") json_result = true;
            else if (a == "--workspace") { if (auto r = set_once_arg(argc, argv, i, a, ws_p); !r) return r.error(); }
            else if (a == "--uri") { if (auto r = set_once_arg(argc, argv, i, a, uri); !r) return r.error(); }
            else if (a == "--uri-file") { if (auto r = set_once_arg(argc, argv, i, a, uri_file); !r) return r.error(); }
            else if (a == "--subscription-id") { if (auto r = set_once_arg(argc, argv, i, a, sub_id); !r) return r.error(); }
            else if (a == "--out-workspace") { if (auto r = set_once_arg(argc, argv, i, a, out_ws); !r) return r.error(); }
            else { std::cerr << "unknown option: " << a << '\n' << workspace_usage; return 2; }
        }
        if (ws_p.empty() || (uri.empty() == uri_file.empty())) { std::cerr << workspace_usage; return 2; }
        auto emit_err = [&](std::string msg) -> int {
            if (json_result) {
                provider::WorkspaceShareImportResult r{}; r.errors.push_back(std::move(msg));
                std::cout << provider::serialize_share_import_result_json(r);
            } else std::cerr << "workspace import-share: " << msg << '\n';
            return 1;
        };
        auto ws_t = ::rulefile::read_regular_file(resolve_path(ws_p).string());
        if (!ws_t) return emit_err("workspace file: " + ws_t.error());
        if (!uri_file.empty()) {
            auto uf = ::rulefile::read_regular_file(resolve_path(uri_file).string());
            if (!uf) return emit_err("uri file: " + uf.error());
            uri = std::move(*uf);
        }
        auto res = provider::import_workspace_share(*ws_t, uri, sub_id);
        if (res.ok && !out_ws.empty()) {
            if (auto ok = write_file_atomic(resolve_path(out_ws), res.workspace_json); !ok) { res.ok = false; res.errors.push_back(ok.error()); }
        }
        if (json_result) { std::cout << provider::serialize_share_import_result_json(res); return res.ok ? 0 : 1; }
        if (!res.ok) { for (auto const& e : res.errors) std::cerr << "workspace import-share: " << e << '\n'; return 1; }
        if (out_ws.empty()) std::cout << res.workspace_json << '\n';
        return 0;
    }

    auto cmd_seal_sync(int argc, char** argv) -> int {
        std::string ws_p, pass_file, pass_env, label, out_p;
        bool json_result = false;
        for (int i = 2; i < argc; ++i) {
            std::string_view a(argv[i]);
            if (a == "--passphrase" || a.starts_with("--passphrase=")) { std::cerr << "--passphrase on command line is forbidden; use --passphrase-file or --passphrase-env\n"; return 2; }
            if (a == "--json-result") json_result = true;
            else if (a == "--workspace") { if (auto r = set_once_arg(argc, argv, i, a, ws_p); !r) return r.error(); }
            else if (a == "--passphrase-file") { if (auto r = set_once_arg(argc, argv, i, a, pass_file); !r) return r.error(); }
            else if (a == "--passphrase-env") { if (auto r = set_once_arg(argc, argv, i, a, pass_env); !r) return r.error(); }
            else if (a == "--device-label") { if (auto r = set_once_arg(argc, argv, i, a, label); !r) return r.error(); }
            else if (a == "--out") { if (auto r = set_once_arg(argc, argv, i, a, out_p); !r) return r.error(); }
            else { std::cerr << "unknown option: " << a << '\n' << workspace_usage; return 2; }
        }
        if (ws_p.empty() || (pass_file.empty() == pass_env.empty())) { std::cerr << workspace_usage; return 2; }
        auto emit_err = [&](std::string msg) -> int {
            if (json_result) {
                provider::WorkspaceSyncSealResult r{}; r.errors.push_back(std::move(msg));
                std::cout << provider::serialize_sync_seal_result_json(r);
            } else std::cerr << "workspace seal-sync: " << msg << '\n';
            return 1;
        };
        auto ws_t = ::rulefile::read_regular_file(resolve_path(ws_p).string());
        if (!ws_t) return emit_err("workspace file: " + ws_t.error());
        auto pass = read_passphrase(pass_file, pass_env);
        if (!pass) return emit_err(pass.error());
        StringCleaner clean_pass{*pass};
        auto res = provider::seal_workspace_sync(*ws_t, *pass, label);
        if (res.ok && !out_p.empty()) {
            if (auto ok = write_file_atomic(resolve_path(out_p), res.envelope_json); !ok) { res.ok = false; res.errors.push_back(ok.error()); }
        }
        if (json_result) { std::cout << provider::serialize_sync_seal_result_json(res); return res.ok ? 0 : 1; }
        if (!res.ok) { for (auto const& e : res.errors) std::cerr << "workspace seal-sync: " << e << '\n'; return 1; }
        if (out_p.empty()) std::cout << res.envelope_json << '\n';
        return 0;
    }

    auto cmd_open_sync(int argc, char** argv) -> int {
        std::string env_p, pass_file, pass_env, out_ws;
        bool json_result = false;
        for (int i = 2; i < argc; ++i) {
            std::string_view a(argv[i]);
            if (a == "--passphrase" || a.starts_with("--passphrase=")) { std::cerr << "--passphrase on command line is forbidden; use --passphrase-file or --passphrase-env\n"; return 2; }
            if (a == "--json-result") json_result = true;
            else if (a == "--envelope") { if (auto r = set_once_arg(argc, argv, i, a, env_p); !r) return r.error(); }
            else if (a == "--passphrase-file") { if (auto r = set_once_arg(argc, argv, i, a, pass_file); !r) return r.error(); }
            else if (a == "--passphrase-env") { if (auto r = set_once_arg(argc, argv, i, a, pass_env); !r) return r.error(); }
            else if (a == "--out-workspace") { if (auto r = set_once_arg(argc, argv, i, a, out_ws); !r) return r.error(); }
            else { std::cerr << "unknown option: " << a << '\n' << workspace_usage; return 2; }
        }
        if (env_p.empty() || (pass_file.empty() == pass_env.empty())) { std::cerr << workspace_usage; return 2; }
        auto emit_err = [&](std::string msg) -> int {
            if (json_result) {
                provider::WorkspaceSyncOpenResult r{}; r.errors.push_back(std::move(msg));
                std::cout << provider::serialize_sync_open_result_json(r);
            } else std::cerr << "workspace open-sync: " << msg << '\n';
            return 1;
        };
        auto env_t = ::rulefile::read_regular_file(resolve_path(env_p).string());
        if (!env_t) return emit_err("envelope file: " + env_t.error());
        auto pass = read_passphrase(pass_file, pass_env);
        if (!pass) return emit_err(pass.error());
        StringCleaner clean_pass{*pass};
        auto res = provider::open_workspace_sync(*env_t, *pass);
        if (res.ok && !out_ws.empty()) {
            if (auto ok = write_file_atomic(resolve_path(out_ws), res.workspace_json); !ok) { res.ok = false; res.errors.push_back(ok.error()); }
        }
        if (json_result) { std::cout << provider::serialize_sync_open_result_json(res); return res.ok ? 0 : 1; }
        if (!res.ok) { for (auto const& e : res.errors) std::cerr << "workspace open-sync: " << e << '\n'; return 1; }
        if (out_ws.empty()) std::cout << res.workspace_json << '\n';
        return 0;
    }
}

auto nexus_workspace(int argc, char** argv) -> int {
    if (argc == 1 || (argc == 2 && std::string_view(argv[1]) == "--help")) {
        (argc == 1 ? std::cerr : std::cout) << workspace_usage;
        return argc == 1 ? 2 : 0;
    }
    std::string_view sub(argv[1]);
    if (argc == 3 && std::string_view(argv[2]) == "--help") { std::cout << workspace_usage; return 0; }
    if (sub == "compose") return cmd_compose(argc, argv);
    if (sub == "export-share") return cmd_export_share(argc, argv);
    if (sub == "import-share") return cmd_import_share(argc, argv);
    if (sub == "seal-sync") return cmd_seal_sync(argc, argv);
    if (sub == "open-sync") return cmd_open_sync(argc, argv);
    std::cerr << "unknown workspace command: " << sub << '\n' << workspace_usage;
    return 2;
}
