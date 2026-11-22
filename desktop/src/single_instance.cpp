module;

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cstddef>
#include <cstring>
#include <sys/socket.h>
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
        std::string sock_path;
        std::atomic<bool> stop{false};
        std::thread listener;

        ~Impl() {
            stop.store(true);
            if (listen_fd >= 0) {
                ::shutdown(listen_fd, SHUT_RDWR);
                ::close(listen_fd);
            }
            if (listener.joinable()) listener.join();
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
        std::filesystem::path dir = xdg && *xdg ? std::filesystem::path(xdg) : std::filesystem::temp_directory_path();
        std::string path = (dir / (app_id + ".sock")).string();

        sockaddr_un addr{};
        if (path.size() >= sizeof(addr.sun_path)) return nullptr;
        addr.sun_family = AF_UNIX;
        std::memcpy(addr.sun_path, path.data(), path.size());
        auto addr_len = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + path.size() + 1);

        int probe = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (probe >= 0) {
            if (::connect(probe, reinterpret_cast<sockaddr const*>(&addr), addr_len) == 0) {
                (void)::send(probe, "WAKEUP\n", 7, MSG_NOSIGNAL);
                ::close(probe);
                return nullptr;
            }
            ::close(probe);
        }

        ::unlink(path.c_str());
        int srv = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (srv < 0) return nullptr;
        if (::bind(srv, reinterpret_cast<sockaddr const*>(&addr), addr_len) != 0 || ::listen(srv, 8) != 0) {
            ::close(srv);
            return nullptr;
        }

        auto impl = std::make_unique<Impl>();
        impl->listen_fd = srv;
        impl->sock_path = std::move(path);
        impl->listener = std::thread([raw = impl.get(), cb = std::move(on_wakeup)] {
            while (!raw->stop.load()) {
                int c = ::accept4(raw->listen_fd, nullptr, nullptr, SOCK_CLOEXEC);
                if (c < 0) break;
                char buf[16]{};
                auto n = ::recv(c, buf, sizeof(buf), 0);
                ::close(c);
                if (n > 0 && cb) cb();
            }
        });
        return std::unique_ptr<SingleInstanceGuard>(new SingleInstanceGuard(std::move(impl)));
#endif
    }
}
