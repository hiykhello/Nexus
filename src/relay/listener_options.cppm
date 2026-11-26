// Shared TCP & UDP inbound listener socket creation and ListenOptions application.
module;
#include <cerrno>
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif
#include <boost/capy/buffers.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/shutdown_type.hpp>
#include <boost/corosio/socket_option.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/udp_socket.hpp>

export module relay.listener_options;
import std;
import config.listen_types;
import platform.socket_options;
import capy;
import corosio;

export namespace relay {
    [[nodiscard]] inline auto to_socket_binding(config::ListenOptions const& opt,
        std::optional<std::uint32_t> fallback_mark = {}) noexcept
        -> std::expected<platform::SocketBinding, std::error_code> {
        if (!opt.valid()) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        platform::SocketBinding binding{};
        binding.network_namespace = opt.netns;
        if (!opt.bind_interface.empty()) {
            if (opt.bind_interface.size() >= binding.bind_interface.size())
                return std::unexpected(std::make_error_code(std::errc::invalid_argument));
            std::ranges::copy(opt.bind_interface, binding.bind_interface.begin());
        }
        binding.routing_mark = opt.routing_mark ? opt.routing_mark : fallback_mark;
        binding.reuse_addr = opt.reuse_addr;
        binding.udp_fragment = opt.udp_fragment;
        if (!binding.valid()) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        return binding;
    }

    [[nodiscard]] inline auto to_tcp_socket_options(config::ListenOptions const& opt,
        std::optional<std::uint32_t> fallback_mark = {}) noexcept
        -> std::expected<platform::TcpSocketOptions, std::error_code> {
        auto binding = to_socket_binding(opt, fallback_mark);
        if (!binding) return std::unexpected(binding.error());
        platform::TcpSocketOptions tcp{};
        tcp.binding = std::move(*binding);
        tcp.keepalive = opt.tcp_keepalive;
        tcp.keepalive_idle_seconds = opt.tcp_keepalive_idle_s;
        tcp.keepalive_interval_seconds = opt.tcp_keepalive_interval_s;
        tcp.keepalive_count = opt.tcp_keepalive_count;
        tcp.multipath_tcp = opt.multipath_tcp;
        tcp.tcp_fast_open = opt.tcp_fast_open;
        if (!tcp.valid()) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        return tcp;
    }

    [[nodiscard]] inline auto effective_udp_timeout_ms(config::ListenOptions const& opt,
        std::uint32_t fallback_ms = 60000) noexcept -> std::uint32_t {
        return opt.udp_timeout_ms.value_or(fallback_ms);
    }

    [[nodiscard]] inline auto apply_tcp_listen_options(int fd, config::ListenOptions const& opt, bool ipv6,
        bool tproxy = false, bool admission_reuse = false,
        std::optional<std::uint32_t> fallback_mark = {}) noexcept -> std::error_code {
        if (fd < 0) return std::make_error_code(std::errc::bad_file_descriptor);
        auto tcp = to_tcp_socket_options(opt, fallback_mark);
        if (!tcp) return tcp.error();
        if (admission_reuse && !tcp->binding.reuse_addr) tcp->binding.reuse_addr = true;
        if (tcp->configured()) {
            if (auto err = platform::apply_tcp_options(fd, *tcp)) return err;
        }
#if !defined(__linux__)
        if (tcp->binding.reuse_addr) {
            int val = *tcp->binding.reuse_addr ? 1 : 0;
#if defined(_WIN32)
            if (::setsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, SO_REUSEADDR,
                reinterpret_cast<char const*>(&val), sizeof(val)) != 0)
                return {static_cast<int>(::WSAGetLastError()), std::system_category()};
#else
            if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0)
                return {errno, std::generic_category()};
#endif
        }
#endif
        if (opt.tcp_fast_open) {
#if defined(TCP_FASTOPEN)
#if defined(__APPLE__)
            int qlen = *opt.tcp_fast_open ? 1 : 0;
#else
            int qlen = *opt.tcp_fast_open ? 256 : 0;
#endif
#if defined(_WIN32)
            if (::setsockopt(static_cast<SOCKET>(fd), IPPROTO_TCP, TCP_FASTOPEN,
                reinterpret_cast<char const*>(&qlen), sizeof(qlen)) != 0)
                return {static_cast<int>(::WSAGetLastError()), std::system_category()};
#else
            if (::setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen)) < 0)
                return {errno, std::generic_category()};
#endif
#else
            if (*opt.tcp_fast_open) return std::make_error_code(std::errc::operation_not_supported);
#endif
        }
#if defined(__linux__)
        // Inherited by accepted child sockets on Linux; avoids per-accept setsockopt.
        int nodelay = 1;
        (void)::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
#ifdef TCP_USER_TIMEOUT
        std::uint32_t user_timeout = 20000;
        (void)::setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout, sizeof(user_timeout));
#endif
#endif
        if (tproxy) {
#if defined(IP_TRANSPARENT) && defined(IPV6_TRANSPARENT)
            int enabled = 1;
            if (::setsockopt(fd, ipv6 ? IPPROTO_IPV6 : IPPROTO_IP,
                ipv6 ? IPV6_TRANSPARENT : IP_TRANSPARENT, &enabled, sizeof(enabled)) < 0)
                return {errno, std::generic_category()};
#else
            (void)ipv6;
            return std::make_error_code(std::errc::operation_not_supported);
#endif
        }
        return {};
    }

    [[nodiscard]] inline auto open_and_bind_tcp_listener(corosio::tcp_acceptor& acceptor,
        corosio::endpoint const& endpoint, config::ListenOptions const& opt,
        bool tproxy = false, bool reuse_port = false, bool admission_reuse = false,
        bool dual_stack_v6 = false, std::optional<std::uint32_t> fallback_mark = {}) noexcept -> std::error_code {
        if (!opt.valid()) return std::make_error_code(std::errc::invalid_argument);
        bool const ipv6 = endpoint.address().is_v6();
        bool const multipath = opt.multipath_tcp.value_or(false);
        if (multipath || !opt.netns.empty()) {
            auto fd = platform::open_physical_socket(ipv6, false, multipath, opt.netns);
            if (!fd) return fd.error();
            if (auto err = acceptor.assign(*fd)) {
                platform::close_unadopted_socket(*fd);
                return err;
            }
        } else if (auto err = acceptor.open(ipv6 ? corosio::family::v6 : corosio::family::v4)) {
            return err;
        }
        if (auto err = apply_tcp_listen_options(acceptor.native_handle(), opt, ipv6, tproxy, admission_reuse, fallback_mark))
            return err;
        if (ipv6) {
            if (auto err = acceptor.set_option(corosio::socket_option::v6_only(!dual_stack_v6))) return err;
        }
        if (reuse_port) {
            if (auto err = acceptor.set_option(corosio::socket_option::reuse_port(true))) return err;
        }
        return acceptor.bind(endpoint);
    }

    [[nodiscard]] inline auto apply_udp_listen_options(int fd, config::ListenOptions const& opt, bool ipv6) noexcept
        -> std::error_code {
        if (fd < 0) return std::make_error_code(std::errc::bad_file_descriptor);
        auto binding = to_socket_binding(opt);
        if (!binding) return binding.error();
        if (binding->configured()) {
            if (auto err = platform::apply_socket_binding(fd, *binding, true)) return err;
        }
#if !defined(__linux__)
        if (binding->reuse_addr) {
            int val = *binding->reuse_addr ? 1 : 0;
#if defined(_WIN32)
            if (::setsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, SO_REUSEADDR,
                reinterpret_cast<char const*>(&val), sizeof(val)) != 0)
                return {static_cast<int>(::WSAGetLastError()), std::system_category()};
#else
            if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0)
                return {errno, std::generic_category()};
#endif
        }
        if (binding->udp_fragment) {
            (void)ipv6;
#if defined(IP_DONTFRAG) && defined(IPV6_DONTFRAG)
            int val = *binding->udp_fragment ? 0 : 1;
#if defined(_WIN32)
            DWORD dval = static_cast<DWORD>(val);
            if (::setsockopt(static_cast<SOCKET>(fd), ipv6 ? IPPROTO_IPV6 : IPPROTO_IP,
                ipv6 ? IPV6_DONTFRAG : IP_DONTFRAG, reinterpret_cast<char const*>(&dval), sizeof(dval)) != 0)
                return {static_cast<int>(::WSAGetLastError()), std::system_category()};
#else
            if (::setsockopt(fd, ipv6 ? IPPROTO_IPV6 : IPPROTO_IP,
                ipv6 ? IPV6_DONTFRAG : IP_DONTFRAG, &val, sizeof(val)) < 0)
                return {errno, std::generic_category()};
#endif
#endif
        }
#else
        (void)ipv6;
#endif
        return {};
    }

    [[nodiscard]] inline auto open_and_bind_udp_listener(corosio::udp_socket& sock,
        corosio::endpoint const& endpoint, config::ListenOptions const& opt,
        bool reuse_port = false) noexcept -> std::error_code {
        if (!opt.valid()) return std::make_error_code(std::errc::invalid_argument);
        bool const ipv6 = endpoint.address().is_v6();
        if (!opt.netns.empty()) {
            auto fd = platform::open_physical_socket(ipv6, true, false, opt.netns);
            if (!fd) return fd.error();
            if (auto err = sock.assign(*fd)) {
                platform::close_unadopted_socket(*fd);
                return err;
            }
        } else if (auto err = sock.open(ipv6 ? corosio::family::v6 : corosio::family::v4)) {
            return err;
        }
        if (auto err = apply_udp_listen_options(sock.native_handle(), opt, ipv6)) return err;
        if (ipv6) {
            if (auto err = sock.set_option(corosio::socket_option::v6_only(true))) return err;
        }
        if (reuse_port) {
            if (auto err = sock.set_option(corosio::socket_option::reuse_port(true))) return err;
        }
        return sock.bind(endpoint);
    }

    template<class CloseFn>
    inline auto relay_detour_stream(corosio::tcp_socket& client, corosio::tcp_socket& target,
        corosio::endpoint target_ep, bool const& closed,
        std::chrono::steady_clock::time_point& touched, CloseFn close_session) -> capy::task<> {
        if (target_ep.is_v6() && target_ep.address().to_v6().is_unspecified())
            target_ep = corosio::endpoint(corosio::ipv6_address::loopback(), target_ep.port());
        else if (target_ep.is_v4() && target_ep.address().to_v4().to_uint() == 0)
            target_ep = corosio::endpoint(corosio::ipv4_address::loopback(), target_ep.port());
        auto [ec] = co_await target.connect(target_ep);
        if (ec || closed) { close_session(); co_return; }
        auto pump = [&](corosio::tcp_socket& src, corosio::tcp_socket& dst) -> capy::task<capy::results<>> {
            std::array<std::uint8_t, 16384> buf;
            while (!closed) {
                auto [re, n] = co_await src.read_some(capy::mutable_buffer(buf.data(), buf.size()));
                if (re || !n) { (void)dst.shutdown(corosio::shutdown_send); break; }
                std::size_t off = 0;
                while (off < n && !closed) {
                    auto [we, w] = co_await dst.write_some(capy::const_buffer(buf.data() + off, n - off));
                    if (we || !w) { close_session(); co_return capy::results<>{}; }
                    off += w;
                }
                touched = std::chrono::steady_clock::now();
            }
            co_return capy::results<>{};
        };
        (void)co_await capy::when_all(pump(client, target), pump(target, client));
    }
}
