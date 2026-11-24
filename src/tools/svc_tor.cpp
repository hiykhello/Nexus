module;
#ifndef _WIN32
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

module cli.proxy_services;
import std;
import config;
import logging;
import logging.cli;
import platform.socket_options;
import platform.unique_fd;
import relay.tor_outbound;

namespace cli {
    namespace {
        using Clock = std::chrono::steady_clock;

#ifndef _WIN32
        using FdGuard = platform::UniqueFd;

        auto wait_fd(int fd, short events, Clock::time_point dl) -> bool {
            for (;;) {
                auto now = Clock::now();
                if (now >= dl) return false;
                auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(dl - now).count();
                pollfd pfd{fd, events, 0};
                int r = ::poll(&pfd, 1, static_cast<int>(std::clamp<long long>(ms, 1, 500)));
                if (r < 0 && errno == EINTR) continue;
                return r > 0 && (pfd.revents & (events | POLLERR | POLLHUP));
            }
        }

        auto connect_tcp(std::string const& host, std::uint16_t port, Clock::time_point dl)
            -> std::expected<FdGuard, std::string> {
            addrinfo hints{};
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_family = AF_UNSPEC;
            auto port_str = std::to_string(port);
            addrinfo* res = nullptr;
            if (::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res)
                return std::unexpected("tor control: cannot resolve " + host);
            struct AddrFree { addrinfo* p; ~AddrFree() { ::freeaddrinfo(p); } } af{res};
            for (auto* rp = res; rp; rp = rp->ai_next) {
                int s = ::socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, rp->ai_protocol);
                if (s < 0) continue;
                FdGuard g{s};
                if (platform::invoke_protect_fd(s)) return std::unexpected("tor control: protect_fd failed");
                int r = ::connect(s, rp->ai_addr, rp->ai_addrlen);
                if (r == 0) return g;
                if (errno != EINPROGRESS) continue;
                if (!wait_fd(s, POLLOUT, dl)) continue;
                int err = 0; socklen_t len = sizeof(err);
                if (::getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) return g;
            }
            return std::unexpected("tor control: connect failed to " + host + ":" + port_str);
        }

        auto send_all(int fd, std::string_view data, Clock::time_point dl) -> bool {
            while (!data.empty()) {
                if (!wait_fd(fd, POLLOUT, dl)) return false;
                auto n = ::send(fd, data.data(), data.size(), MSG_NOSIGNAL);
                if (n < 0) {
                    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
                    return false;
                }
                if (n == 0) return false;
                data.remove_prefix(static_cast<std::size_t>(n));
            }
            return true;
        }

        auto recv_reply(int fd, Clock::time_point dl) -> std::expected<relay::tor::ControlReply, std::string> {
            std::string raw;
            std::array<char, 1024> buf{};
            while (raw.size() < 16384) {
                if (!wait_fd(fd, POLLIN, dl)) return std::unexpected("tor control: read timeout");
                auto n = ::recv(fd, buf.data(), buf.size(), 0);
                if (n < 0) {
                    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
                    return std::unexpected("tor control: read error");
                }
                if (n == 0) break;
                raw.append(buf.data(), static_cast<std::size_t>(n));
                // Final ControlPort reply line has space after 3-digit code and ends with \r\n.
                if (raw.ends_with("\r\n")) {
                    auto prev = raw.size() >= 3 ? raw.rfind('\n', raw.size() - 3) : std::string::npos;
                    auto last = prev == std::string::npos ? std::string_view(raw) : std::string_view(raw).substr(prev + 1);
                    if (last.size() >= 4 && last[3] == ' ') break;
                }
            }
            return relay::tor::parse_control_reply(raw);
        }
#endif

        struct TorState {
            relay::tor::Config config;
            std::optional<std::size_t> outbound_index;

            auto control_exchange(std::string_view command) -> std::expected<relay::tor::ControlReply, std::string> {
#ifdef _WIN32
                (void)command;
                return std::unexpected("tor control client is not implemented on Windows");
#else
                auto auth = relay::tor::build_control_authenticate(config);
                if (!auth) return std::unexpected(std::move(auth.error()));
                auto dl = Clock::now() + std::chrono::seconds(2);
                auto sock = connect_tcp(config.control_host, config.control_port, dl);
                if (!sock) return std::unexpected(std::move(sock.error()));
                if (!send_all(sock->get(), *auth, dl)) return std::unexpected("tor control: AUTHENTICATE send failed");
                auto arep = recv_reply(sock->get(), dl);
                if (!arep) return std::unexpected(std::move(arep.error()));
                if (!arep->ok) return std::unexpected(std::format("tor control: AUTHENTICATE rejected ({})", arep->code));
                if (!send_all(sock->get(), command, dl)) return std::unexpected("tor control: command send failed");
                auto crep = recv_reply(sock->get(), dl);
                if (!crep) return std::unexpected(std::move(crep.error()));
                if (!crep->ok) return std::unexpected(std::format("tor control: command rejected ({})", crep->code));
                return crep;
#endif
            }
        };
    }

    auto init_tor_service(config::TorServiceConfig const& cfg, logging::Runtime& logs, TorHooks hooks)
        -> std::expected<ServiceHandle, std::string> {
        relay::tor::Config tc{
            .socks_host = cfg.socks_host,
            .socks_port = cfg.socks_port,
            .control_host = cfg.control_host,
            .control_port = cfg.control_port,
            .control_password = cfg.control_password,
            .cookie_hex = cfg.cookie_hex,
            .isolate_streams = cfg.isolate_streams,
            .allow_remote_socks = cfg.allow_remote_socks,
        };
        if (auto ok = relay::tor::validate_config(tc); !ok)
            return std::unexpected(std::move(ok.error()));

        auto st = std::make_unique<TorState>(TorState{std::move(tc), std::nullopt});
        if (hooks.register_outbound) {
            auto idx = hooks.register_outbound(cfg);
            if (!idx) return std::unexpected("tor outbound registration failed: " + idx.error());
            st->outbound_index = *idx;
        }
        logs.emit(logging::Level::info, logging::Domain::core, 101, {},
            "tor service wired (socks {}:{}, control {}:{}, isolate={})",
            cfg.socks_host, cfg.socks_port, cfg.control_host, cfg.control_port, cfg.isolate_streams);
        return ServiceHandle::create(std::move(st));
    }

    auto tor_signal_newnym(ServiceHandle& h) -> std::expected<void, std::string> {
        if (!h.state) return std::unexpected("tor service not active");
        auto rep = static_cast<TorState*>(h.state.get())->control_exchange(relay::tor::build_control_newnym());
        if (!rep) return std::unexpected(std::move(rep.error()));
        return {};
    }

    auto tor_query_bootstrap(ServiceHandle& h) -> std::expected<int, std::string> {
        if (!h.state) return std::unexpected("tor service not active");
        auto cmd = relay::tor::build_control_getinfo("status/bootstrap-phase");
        if (!cmd) return std::unexpected(std::move(cmd.error()));
        auto rep = static_cast<TorState*>(h.state.get())->control_exchange(*cmd);
        if (!rep) return std::unexpected(std::move(rep.error()));
        return rep->bootstrap_progress.value_or(0);
    }
}
