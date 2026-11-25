// CLI subcommand: `nexus workspace compose` for unified 4-layer config compilation.
#if !defined(_WIN32)
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

import std;
import cli.route_files;
import provider.workspace_compose;
import rulefile;

namespace {
    constexpr std::string_view workspace_usage =
        "usage: nexus workspace compose --workspace <workspace.json> --host <host.json> --secrets-dir <dir> "
        "[--active <profile-id>] [--emit-kdl <out.kdl>] [--json-result]\n";

    auto resolve_path(std::string_view raw) -> std::filesystem::path {
        std::filesystem::path p(raw);
        if (p.is_relative()) if (auto wd = cli::working_directory()) p = *wd / p;
        return p;
    }

    auto write_kdl_atomic(std::filesystem::path const& target, std::string_view content) -> std::expected<void, std::string> {
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
        if (base.empty() || base == "." || base == "..") return std::unexpected("invalid --emit-kdl filename");
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
}

auto nexus_workspace(int argc, char** argv) -> int {
    if (argc == 1 || (argc == 2 && std::string_view(argv[1]) == "--help")) {
        (argc == 1 ? std::cerr : std::cout) << workspace_usage;
        return argc == 1 ? 2 : 0;
    }
    if (std::string_view(argv[1]) != "compose") {
        std::cerr << "unknown workspace command: " << argv[1] << '\n' << workspace_usage;
        return 2;
    }
    if (argc == 3 && std::string_view(argv[2]) == "--help") {
        std::cout << workspace_usage;
        return 0;
    }
    std::string workspace_path, host_path, secrets_dir, active_id, emit_kdl_path;
    bool json_result = false;
    for (int i = 2; i < argc; ++i) {
        std::string_view arg(argv[i]);
        auto next = [&]() -> std::expected<std::string_view, int> {
            if (i + 1 >= argc || std::string_view(argv[i + 1]).empty()) {
                std::cerr << "missing or empty value for " << arg << '\n';
                return std::unexpected(2);
            }
            return std::string_view(argv[++i]);
        };
        auto set_once = [&](std::string& dst) -> std::expected<void, int> {
            if (!dst.empty()) { std::cerr << "duplicate option: " << arg << '\n'; return std::unexpected(2); }
            auto v = next();
            if (!v) return std::unexpected(v.error());
            dst = *v;
            return {};
        };
        if (arg == "--json-result") json_result = true;
        else if (arg == "--workspace") { if (auto r = set_once(workspace_path); !r) return r.error(); }
        else if (arg == "--host") { if (auto r = set_once(host_path); !r) return r.error(); }
        else if (arg == "--secrets-dir") { if (auto r = set_once(secrets_dir); !r) return r.error(); }
        else if (arg == "--active") { if (auto r = set_once(active_id); !r) return r.error(); }
        else if (arg == "--emit-kdl") { if (auto r = set_once(emit_kdl_path); !r) return r.error(); }
        else { std::cerr << "unknown option: " << arg << '\n' << workspace_usage; return 2; }
    }
    if (workspace_path.empty() || host_path.empty() || secrets_dir.empty()) {
        std::cerr << workspace_usage;
        return 2;
    }

    auto emit_err = [&](std::string msg) -> int {
        if (json_result) {
            provider::WorkspaceComposeResult r{};
            r.errors.push_back(std::move(msg));
            std::cout << provider::serialize_compose_result_json(r);
        } else {
            std::cerr << "workspace compose: " << msg << '\n';
        }
        return 1;
    };

    auto ws_text = ::rulefile::read_regular_file(resolve_path(workspace_path).string());
    if (!ws_text) return emit_err("workspace file: " + ws_text.error());
    auto host_text = ::rulefile::read_regular_file(resolve_path(host_path).string());
    if (!host_text) return emit_err("host file: " + host_text.error());

    provider::WorkspaceComposeOptions opts{
        .secrets_dir = resolve_path(secrets_dir).string(),
        .active_profile_id = active_id,
    };
    auto res = provider::compose_workspace(*ws_text, *host_text, opts);
    if (res.ok && !emit_kdl_path.empty()) {
        if (auto ok = write_kdl_atomic(resolve_path(emit_kdl_path), res.kdl); !ok) {
            res.ok = false;
            res.errors.push_back(ok.error());
        }
    }
    if (json_result) {
        std::cout << provider::serialize_compose_result_json(res);
        return res.ok ? 0 : 1;
    }
    for (auto const& w : res.warnings) std::cerr << "warning: " << w << '\n';
    if (!res.ok) {
        for (auto const& e : res.errors) std::cerr << "workspace compose: " << e << '\n';
        return 1;
    }
    if (emit_kdl_path.empty()) std::cout << res.kdl;
    return 0;
}
