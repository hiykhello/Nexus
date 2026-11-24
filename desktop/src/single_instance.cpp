module;

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#endif

module desktop.single_instance;

import std;

namespace desktop {
    struct SingleInstanceGuard::Impl {
#ifdef _WIN32
        HANDLE mutex = nullptr;
        ~Impl() { if (mutex) ::CloseHandle(mutex); }
#else
        int listen_fd = -1;
        int wake_pipe[2]{-1, -1};
        std::string sock_path;
        std::atomic<bool> stop{false};
        std::thread listener;

        ~Impl() {
            stop.store(true, std::memory_order_release);
            if (wake_pipe[1] >= 0) {
                char byte = 1;
                (void)::write(wake_pipe[1], &byte, 1);
            }
            if (listener.joinable()) listener.join();
            if (listen_fd >= 0) ::close(listen_fd);
            if (wake_pipe[0] >= 0) ::close(wake_pipe[0]);
            if (wake_pipe[1] >= 0) ::close(wake_pipe[1]);
            if (!sock_path.empty()) ::unlink(sock_path.c_str());
        }
#endif
    };

    SingleInstanceGuard::SingleInstanceGuard(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
    SingleInstanceGuard::~SingleInstanceGuard() = default;
    SingleInstanceGuard::SingleInstanceGuard(SingleInstanceGuard&&) noexcept = default;
    auto SingleInstanceGuard::operator=(SingleInstanceGuard&&) noexcept -> SingleInstanceGuard& = default;

    auto SingleInstanceGuard::acquire(std::string const& app_id, std::function<void()> on_wakeup)
        -> std::unique_ptr<SingleInstanceGuard> {
#ifdef _WIN32
        (void)on_wakeup;
        std::wstring name = L"Local\\" + std::wstring(app_id.begin(), app_id.end());
        HANDLE h = ::CreateMutexW(nullptr, FALSE, name.c_str());
        if (!h) return nullptr;
        if (::GetLastError() == ERROR_ALREADY_EXISTS) {
            ::CloseHandle(h);
            return nullptr;
        }
        auto impl = std::make_unique<Impl>();
        impl->mutex = h;
        return std::unique_ptr<SingleInstanceGuard>(new SingleInstanceGuard(std::move(impl)));
#else
        char const* xdg = std::getenv("XDG_RUNTIME_DIR");
        std::filesystem::path dir;
        if (xdg && *xdg) {
            dir = std::filesystem::path(xdg);
        } else {
            std::error_code ec;
            auto tmp = std::filesystem::temp_directory_path(ec);
            if (ec || tmp.empty()) tmp = "/tmp";
            dir = tmp / std::format("nexus-run-{}", ::geteuid());
            ec.clear();
            std::filesystem::create_directories(dir, ec);
            (void)::chmod(dir.c_str(), 0700);
        }
        std::string path = (dir / (app_id + ".sock")).string();

        sockaddr_un addr{};
        if (path.size() >= sizeof(addr.sun_path)) return nullptr;
        addr.sun_family = AF_UNIX;
        std::memcpy(addr.sun_path, path.data(), path.size());
        auto addr_len = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + path.size() + 1);

#ifdef SOCK_CLOEXEC
        int probe = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
        int probe = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (probe >= 0) (void)::fcntl(probe, F_SETFD, FD_CLOEXEC);
#endif
        if (probe >= 0) {
#ifdef SO_NOSIGPIPE
            int one = 1;
            (void)::setsockopt(probe, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
            if (::connect(probe, reinterpret_cast<sockaddr const*>(&addr), addr_len) == 0) {
#ifdef MSG_NOSIGNAL
                (void)::send(probe, "WAKEUP\n", 7, MSG_NOSIGNAL);
#else
                (void)::send(probe, "WAKEUP\n", 7, 0);
#endif
                ::close(probe);
                return nullptr;
            }
            ::close(probe);
        }

        ::unlink(path.c_str());
#ifdef SOCK_CLOEXEC
        int srv = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
        int srv = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (srv >= 0) (void)::fcntl(srv, F_SETFD, FD_CLOEXEC);
#endif
        if (srv < 0) return nullptr;
        if (::bind(srv, reinterpret_cast<sockaddr const*>(&addr), addr_len) != 0) {
            ::close(srv);
            return nullptr;
        }
        (void)::chmod(path.c_str(), 0600);
        if (::listen(srv, 8) != 0) {
            ::close(srv);
            ::unlink(path.c_str());
            return nullptr;
        }

        auto impl = std::make_unique<Impl>();
        if (::pipe(impl->wake_pipe) != 0) {
            ::close(srv);
            ::unlink(path.c_str());
            return nullptr;
        }
        (void)::fcntl(impl->wake_pipe[0], F_SETFD, FD_CLOEXEC);
        (void)::fcntl(impl->wake_pipe[1], F_SETFD, FD_CLOEXEC);
        impl->listen_fd = srv;
        impl->sock_path = std::move(path);
        uid_t expected_uid = ::geteuid();
        impl->listener = std::thread([raw = impl.get(), cb = std::move(on_wakeup), expected_uid] {
            while (!raw->stop.load(std::memory_order_acquire)) {
                pollfd fds[2]{
                    {raw->listen_fd, POLLIN, 0},
                    {raw->wake_pipe[0], POLLIN, 0},
                };
                int pr = ::poll(fds, 2, -1);
                if (pr < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                if (raw->stop.load(std::memory_order_acquire) || (fds[1].revents & POLLIN)) break;
                if (!(fds[0].revents & POLLIN)) continue;
#ifdef __linux__
                int c = ::accept4(raw->listen_fd, nullptr, nullptr, SOCK_CLOEXEC);
#else
                int c = ::accept(raw->listen_fd, nullptr, nullptr);
                if (c >= 0) (void)::fcntl(c, F_SETFD, FD_CLOEXEC);
#endif
                if (c < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                bool peer_ok = true;
#ifdef SO_PEERCRED
                ucred cred{};
                socklen_t clen = sizeof(cred);
                if (::getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cred, &clen) != 0 || cred.uid != expected_uid) {
                    peer_ok = false;
                }
#elif defined(__APPLE__)
                uid_t euid = 0;
                gid_t egid = 0;
                if (::getpeereid(c, &euid, &egid) != 0 || euid != expected_uid) peer_ok = false;
#endif
                if (!peer_ok) { ::close(c); continue; }
                timeval tv{0, 250000};
                ::setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                char buf[16]{};
                ssize_t n = 0;
                do { n = ::recv(c, buf, sizeof(buf), 0); } while (n < 0 && errno == EINTR);
                ::close(c);
                if (n > 0 && cb) cb();
            }
        });
        return std::unique_ptr<SingleInstanceGuard>(new SingleInstanceGuard(std::move(impl)));
#endif
    }
}
