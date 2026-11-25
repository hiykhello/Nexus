#ifdef __APPLE__
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

import std;
import desktop.tun_helper_protocol;

namespace {
    using desktop::TunHelperCommand;
    using desktop::TunHelperPinnedConfig;
    using desktop::TunHelperReply;

    volatile std::sig_atomic_t g_stop_requested = 0;

    auto on_stop_signal(int) -> void { g_stop_requested = 1; }

    auto canonical_path(std::filesystem::path const& p) -> std::filesystem::path {
        std::error_code ec;
        auto c = std::filesystem::weakly_canonical(p, ec);
        return (!ec && !c.empty()) ? c : p;
    }

    auto resolve_self_executable() -> std::optional<std::filesystem::path> {
        std::uint32_t sz = 0;
        (void)::_NSGetExecutablePath(nullptr, &sz);
        if (sz == 0 || sz > 4096) return std::nullopt;
        std::string buf(sz, '\0');
        if (::_NSGetExecutablePath(buf.data(), &sz) != 0) return std::nullopt;
        return canonical_path(std::filesystem::path(buf.c_str()));
    }

    auto run_execv_sync(std::vector<std::string> const& args) -> int {
        if (args.empty()) return -1;
        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (auto const& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        pid_t pid = ::fork();
        if (pid < 0) return -1;
        if (pid == 0) {
            int devnull = ::open("/dev/null", O_RDWR);
            if (devnull >= 0) {
                (void)::dup2(devnull, STDIN_FILENO);
                (void)::dup2(devnull, STDOUT_FILENO);
                (void)::dup2(devnull, STDERR_FILENO);
                if (devnull > STDERR_FILENO) ::close(devnull);
            }
            ::execv(args[0].c_str(), argv.data());
            ::_exit(127);
        }
        int status = 0;
        while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }

    auto ensure_root_dir(std::filesystem::path const& dir) -> bool {
        struct stat st{};
        if (::lstat(dir.c_str(), &st) == 0) {
            if (!S_ISDIR(st.st_mode)) return false;
        } else {
            if (::mkdir(dir.c_str(), 0755) != 0 && errno != EEXIST) return false;
            if (::lstat(dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) return false;
        }
        return ::chown(dir.c_str(), 0, 0) == 0 && ::chmod(dir.c_str(), 0755) == 0;
    }

    auto write_root_file_atomic(std::filesystem::path const& dest, std::string_view content, mode_t mode) -> bool {
        auto tmp = dest;
        tmp += ".tmp." + std::to_string(static_cast<long>(::getpid()));
        (void)::unlink(tmp.c_str());
        int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
        if (fd < 0) return false;
        std::size_t off = 0;
        while (off < content.size()) {
            auto n = ::write(fd, content.data() + off, content.size() - off);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { ::close(fd); ::unlink(tmp.c_str()); return false; }
            off += static_cast<std::size_t>(n);
        }
        bool ok = (::fchmod(fd, mode) == 0 && ::fchown(fd, 0, 0) == 0 && ::fsync(fd) == 0);
        ::close(fd);
        if (!ok || ::rename(tmp.c_str(), dest.c_str()) != 0) { ::unlink(tmp.c_str()); return false; }
        return true;
    }

    auto stage_root_binary(std::filesystem::path const& src, std::filesystem::path const& dest) -> bool {
        int in_fd = ::open(src.c_str(), O_RDONLY | O_CLOEXEC);
        if (in_fd < 0) return false;
        struct stat st{};
        if (::fstat(in_fd, &st) != 0 || !S_ISREG(st.st_mode)) { ::close(in_fd); return false; }

        auto tmp = dest;
        tmp += ".tmp." + std::to_string(static_cast<long>(::getpid()));
        (void)::unlink(tmp.c_str());
        int out_fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0755);
        if (out_fd < 0) { ::close(in_fd); return false; }

        char buf[65536];
        bool ok = true;
        for (;;) {
            auto r = ::read(in_fd, buf, sizeof(buf));
            if (r < 0 && errno == EINTR) continue;
            if (r < 0) { ok = false; break; }
            if (r == 0) break;
            std::size_t off = 0;
            while (off < static_cast<std::size_t>(r)) {
                auto w = ::write(out_fd, buf + off, static_cast<std::size_t>(r) - off);
                if (w < 0 && errno == EINTR) continue;
                if (w <= 0) { ok = false; break; }
                off += static_cast<std::size_t>(w);
            }
            if (!ok) break;
        }
        ::close(in_fd);
        if (ok) ok = (::fchown(out_fd, 0, 0) == 0 && ::fchmod(out_fd, 0755) == 0 && ::fsync(out_fd) == 0);
        ::close(out_fd);
        if (!ok || ::rename(tmp.c_str(), dest.c_str()) != 0) { ::unlink(tmp.c_str()); return false; }
        return true;
    }

    auto parse_uid_str(std::string_view sv) noexcept -> std::optional<uid_t> {
        if (sv.empty() || sv.size() > 10) return std::nullopt;
        std::uint32_t v = 0;
        auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), v, 10);
        if (ec != std::errc{} || ptr != sv.data() + sv.size()) return std::nullopt;
        return static_cast<uid_t>(v);
    }

    auto load_verified_root_config() -> std::expected<TunHelperPinnedConfig, std::string> {
        struct stat st{};
        std::string const path(desktop::kMacTunHelperConfigPath);
        if (::lstat(path.c_str(), &st) != 0) return std::unexpected("pinned config missing");
        if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0022) != 0) {
            return std::unexpected("pinned config failed root ownership/mode check");
        }
        std::ifstream in(path, std::ios::binary);
        if (!in) return std::unexpected("failed to open pinned config");
        std::ostringstream ss;
        ss << in.rdbuf();
        auto parsed = desktop::parse_tun_helper_config(ss.str());
        if (!parsed) return parsed;
        if (parsed->staged_binary.empty()) return std::unexpected("staged_binary missing in pinned config");
        return parsed;
    }

    auto cmd_install(int argc, char** argv) -> int {
        if (::geteuid() != 0) return 1;
        std::filesystem::path bin, cfg, wd;
        std::string owner_uid_str;
        for (int i = 2; i + 1 < argc; i += 2) {
            std::string_view k(argv[i]);
            if (k == "--binary") bin = argv[i + 1];
            else if (k == "--config") cfg = argv[i + 1];
            else if (k == "--workdir") wd = argv[i + 1];
            else if (k == "--owner-uid") owner_uid_str = argv[i + 1];
        }
        auto owner_uid = parse_uid_str(owner_uid_str);
        if (bin.empty() || cfg.empty() || !owner_uid) return 2;
        bin = canonical_path(bin);
        cfg = canonical_path(cfg);
        wd = wd.empty() ? cfg.parent_path() : canonical_path(wd);

        auto digest = desktop::sha256_file(bin);
        if (!digest) return 3;
        auto self_bin = resolve_self_executable();
        if (!self_bin) return 6;

        std::filesystem::path const bin_dir(desktop::kMacTunHelperBinDir);
        if (!ensure_root_dir(bin_dir.parent_path()) || !ensure_root_dir(bin_dir)) return 10;
        auto const staged_helper = bin_dir / "nexus-tun-helper";
        auto const staged_core = bin_dir / "nexus";
        if (!stage_root_binary(*self_bin, staged_helper) || !stage_root_binary(bin, staged_core)) return 11;
        auto staged_sha = desktop::sha256_file(staged_core);
        if (!staged_sha || *staged_sha != *digest) return 12;

        auto serialized = desktop::serialize_tun_helper_config({
            bin.string(), *digest, cfg.string(), wd.string(), owner_uid_str, staged_core.string(),
        });
        if (!serialized) return 4;
        if (!write_root_file_atomic(desktop::kMacTunHelperConfigPath, *serialized, 0644)) return 5;

        auto plist = desktop::render_macos_tun_helper_plist(staged_helper.string());
        if (!plist) return 7;
        if (!write_root_file_atomic(desktop::kMacTunHelperPlistPath, *plist, 0644)) return 8;

        auto svc_target = std::string("system/") + std::string(desktop::kMacTunHelperLabel);
        (void)run_execv_sync({"/bin/launchctl", "bootout", svc_target});
        if (run_execv_sync({"/bin/launchctl", "bootstrap", "system", std::string(desktop::kMacTunHelperPlistPath)}) != 0) {
            return 9;
        }
        return 0;
    }

    auto cmd_uninstall() -> int {
        if (::geteuid() != 0) return 1;
        auto svc_target = std::string("system/") + std::string(desktop::kMacTunHelperLabel);
        (void)run_execv_sync({"/bin/launchctl", "bootout", svc_target});
        (void)::unlink(std::string(desktop::kMacTunHelperPlistPath).c_str());
        (void)::unlink(std::string(desktop::kMacTunHelperConfigPath).c_str());
        (void)::unlink(std::string(desktop::kMacTunHelperSocketPath).c_str());
        std::filesystem::path const bin_dir(desktop::kMacTunHelperBinDir);
        (void)::unlink((bin_dir / "nexus").c_str());
        (void)::unlink((bin_dir / "nexus-tun-helper").c_str());
        (void)::rmdir(bin_dir.c_str());
        return 0;
    }

    struct ChildProcess {
        pid_t pid = -1;

        auto refresh() -> bool {
            if (pid <= 0) return false;
            int status = 0;
            pid_t r = ::waitpid(pid, &status, WNOHANG);
            if (r == pid || (r < 0 && errno == ECHILD)) { pid = -1; return false; }
            return true;
        }

        auto status() -> TunHelperReply {
            return refresh() ? TunHelperReply{true, true, static_cast<std::uint64_t>(pid), "RUNNING"}
                             : TunHelperReply{true, false, 0, "STOPPED"};
        }

        auto stop() -> TunHelperReply {
            if (!refresh()) return {true, false, 0, "STOPPED"};
            (void)::kill(pid, SIGTERM);
            for (int i = 0; i < 30; ++i) {
                if (!refresh()) return {true, false, 0, "STOPPED"};
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            (void)::kill(pid, SIGKILL);
            int st = 0;
            while (::waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
            pid = -1;
            return {true, false, 0, "STOPPED"};
        }

        auto start(TunHelperPinnedConfig const& cfg) -> TunHelperReply {
            if (refresh()) return {true, true, static_cast<std::uint64_t>(pid), "RUNNING"};
            struct stat st{};
            if (::lstat(cfg.staged_binary.c_str(), &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0022) != 0) {
                return {false, false, 0, "staged core binary failed root ownership check"};
            }
            auto actual_sha = desktop::sha256_file(cfg.staged_binary);
            if (!actual_sha) return {false, false, 0, actual_sha.error()};
            if (*actual_sha != cfg.sha256) return {false, false, 0, "core binary SHA-256 mismatch; re-authorize TUN"};

            std::vector<std::string> args{cfg.staged_binary};
            if (!cfg.workdir.empty()) { args.push_back("-D"); args.push_back(cfg.workdir); }
            args.push_back("run"); args.push_back("--config"); args.push_back(cfg.config);
            std::vector<char*> argv;
            argv.reserve(args.size() + 1);
            for (auto& a : args) argv.push_back(a.data());
            argv.push_back(nullptr);

            int log_fd = ::open("/var/log/nexus-tun-core.log", O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
            int devnull = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
            pid_t child = ::fork();
            if (child < 0) {
                if (log_fd >= 0) ::close(log_fd);
                if (devnull >= 0) ::close(devnull);
                return {false, false, 0, "fork failed"};
            }
            if (child == 0) {
                if (devnull >= 0) { (void)::dup2(devnull, STDIN_FILENO); if (devnull > STDERR_FILENO) ::close(devnull); }
                if (log_fd >= 0) {
                    (void)::dup2(log_fd, STDOUT_FILENO);
                    (void)::dup2(log_fd, STDERR_FILENO);
                    if (log_fd > STDERR_FILENO) ::close(log_fd);
                }
                ::execv(args[0].c_str(), argv.data());
                ::_exit(127);
            }
            if (log_fd >= 0) ::close(log_fd);
            if (devnull >= 0) ::close(devnull);

            for (int i = 0; i < 10; ++i) {
                int cst = 0;
                pid_t r = ::waitpid(child, &cst, WNOHANG);
                if (r == child) return {false, false, 0, "core exited immediately after launch"};
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
            }
            pid = child;
            return {true, true, static_cast<std::uint64_t>(pid), "RUNNING"};
        }
    };

    auto cmd_daemon() -> int {
        if (::geteuid() != 0) return 1;
        std::signal(SIGPIPE, SIG_IGN);
        std::signal(SIGTERM, on_stop_signal);
        std::signal(SIGINT, on_stop_signal);

        auto cfg = load_verified_root_config();
        if (!cfg) return 2;
        auto owner_uid = parse_uid_str(cfg->owner);
        if (!owner_uid) return 3;

        int srv = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (srv < 0) return 4;
        (void)::fcntl(srv, F_SETFD, FD_CLOEXEC);
        std::string const sock_path(desktop::kMacTunHelperSocketPath);
        (void)::unlink(sock_path.c_str());

        struct sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        if (sock_path.size() >= sizeof(addr.sun_path)) { ::close(srv); return 5; }
        std::memcpy(addr.sun_path, sock_path.data(), sock_path.size());

        mode_t prev_umask = ::umask(0177);
        int bind_rc = ::bind(srv, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        ::umask(prev_umask);
        if (bind_rc != 0 || ::chown(sock_path.c_str(), *owner_uid, 0) != 0 ||
            ::chmod(sock_path.c_str(), 0600) != 0 || ::listen(srv, 8) != 0) {
            ::close(srv);
            (void)::unlink(sock_path.c_str());
            return 6;
        }

        ChildProcess child{};
        while (!g_stop_requested) {
            (void)child.refresh();
            struct pollfd pfd{srv, POLLIN, 0};
            int pr = ::poll(&pfd, 1, 250);
            if (pr <= 0 || !(pfd.revents & POLLIN)) continue;

            int cli = ::accept(srv, nullptr, nullptr);
            if (cli < 0) continue;
            (void)::fcntl(cli, F_SETFD, FD_CLOEXEC);
            struct timeval tv{2, 0};
            (void)::setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            (void)::setsockopt(cli, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

            uid_t peer_uid = static_cast<uid_t>(-1);
            gid_t peer_gid = static_cast<gid_t>(-1);
            if (::getpeereid(cli, &peer_uid, &peer_gid) != 0 || (peer_uid != *owner_uid && peer_uid != 0)) {
                ::close(cli);
                continue;
            }

            std::string req;
            char buf[desktop::kTunHelperMaxRequestBytes + 2]{};
            while (req.size() <= desktop::kTunHelperMaxRequestBytes) {
                auto n = ::recv(cli, buf, sizeof(buf) - 1, 0);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) break;
                req.append(buf, static_cast<std::size_t>(n));
                if (req.contains('\n')) break;
            }
            while (!req.empty() && (req.back() == '\n' || req.back() == '\r')) req.pop_back();

            TunHelperReply reply{};
            if (auto cmd = desktop::parse_tun_helper_request(req)) {
                switch (*cmd) {
                case TunHelperCommand::ping: reply = {true, false, 0, "PONG"}; break;
                case TunHelperCommand::status: reply = child.status(); break;
                case TunHelperCommand::start: reply = child.start(*cfg); break;
                case TunHelperCommand::stop: reply = child.stop(); break;
                }
            } else {
                reply = {false, false, 0, "invalid command"};
            }
            auto wire = desktop::format_tun_helper_reply(reply) + "\n";
            std::size_t sent = 0;
            while (sent < wire.size()) {
                auto wn = ::send(cli, wire.data() + sent, wire.size() - sent, 0);
                if (wn < 0 && errno == EINTR) continue;
                if (wn <= 0) break;
                sent += static_cast<std::size_t>(wn);
            }
            ::close(cli);
        }

        (void)child.stop();
        ::close(srv);
        (void)::unlink(sock_path.c_str());
        return 0;
    }
}

auto main(int argc, char** argv) -> int {
    if (argc < 2) return 1;
    std::string_view mode(argv[1]);
    if (mode == "--install") return cmd_install(argc, argv);
    if (mode == "--uninstall") return cmd_uninstall();
    if (mode == "--daemon") return cmd_daemon();
    return 1;
}
#endif
