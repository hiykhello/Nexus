module;
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
module udp.direct;
import utility;
import platform.ip_address;
import platform.socket_options;
import rules;
import std;

namespace udp {
    namespace {
        auto system_error() -> std::error_code { return {errno, std::generic_category()}; }
        auto address(Endpoint6 endpoint) -> sockaddr_in6 {
            sockaddr_in6 result{};
            result.sin6_family = AF_INET6;
            std::ranges::copy(endpoint.address, result.sin6_addr.s6_addr);
            result.sin6_port = platform::host_to_net16(endpoint.port);
            return result;
        }
        auto endpoint(sockaddr_in6 const& address) -> Endpoint6 {
            Endpoint6 result{};
            std::ranges::copy(address.sin6_addr.s6_addr, result.address.begin());
            result.port = platform::net_to_host16(address.sin6_port);
            return result;
        }

    }
    Direct6::Direct6(rules::Matcher policy, Mapping mapping, Filtering filtering, Limits limits, std::size_t mtu, std::optional<std::uint32_t> mark)
        : bridge(std::move(policy), mapping, filtering, limits, mtu,
                 {this, [](void* self, FlowId id) noexcept {
                     auto& entries = static_cast<Direct6*>(self)->sockets;
                     std::erase_if(entries, [id](DirectSocket const& entry) { return entry.id == id; });
                 }}), socket_mark(mark) {}
    Direct6::~Direct6() = default;
    auto Direct6::size() const noexcept -> std::size_t { return this->bridge.size(); }
    auto Direct6::expire(std::uint64_t now) -> std::expected<std::size_t, Error> { return this->bridge.expire(now); }
    auto Direct6::stop(std::uint64_t now) -> std::expected<void, Error> {
        auto cleared = this->bridge.clear(now);
        if (!cleared) return std::unexpected(cleared.error());
        this->deferred_error.reset();
        this->deferred_allocation_failure = false;
        return {};
    }
    auto Direct6::submit(std::span<std::uint8_t const> input, std::uint64_t now) -> std::expected<void, DirectError> {
        auto outgoing = this->bridge.prepare(input, now);
        if (!outgoing) return std::unexpected(DirectError{outgoing.error()});
        auto& sockets = this->sockets;
        auto it = std::ranges::find(sockets, outgoing->flow, &DirectSocket::id);
        if (it == sockets.end()) {
#if defined(SOCK_NONBLOCK) && defined(SOCK_CLOEXEC)
            int fd = ::socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
#else
            int fd = ::socket(AF_INET6, SOCK_DGRAM, 0);
            if (fd >= 0) {
                int fl = ::fcntl(fd, F_GETFL, 0), fdfl = ::fcntl(fd, F_GETFD, 0);
                if (fl < 0 || ::fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0 || fdfl < 0 || ::fcntl(fd, F_SETFD, fdfl | FD_CLOEXEC) < 0) {
                    int err = errno; ::close(fd); fd = -1; errno = err;
                }
            }
#endif
            if (fd < 0) {
                auto error = system_error();
                (void)this->bridge.complete(outgoing->flow, outgoing->token, false, now);
                (void)this->bridge.close(outgoing->flow, now);
                return std::unexpected(DirectError{error});
            }
            DirectSocket guard(outgoing->flow, fd);
            if (socket_mark) {
#if defined(SO_MARK)
                if (::setsockopt(fd, SOL_SOCKET, SO_MARK, &*socket_mark, sizeof(*socket_mark)) != 0) {
                    auto error = system_error();
                    (void)this->bridge.complete(outgoing->flow, outgoing->token, false, now);
                    (void)this->bridge.close(outgoing->flow, now);
                    return std::unexpected(DirectError{error});
                }
#else
                (void)this->bridge.complete(outgoing->flow, outgoing->token, false, now);
                (void)this->bridge.close(outgoing->flow, now);
                return std::unexpected(DirectError{std::make_error_code(std::errc::operation_not_supported)});
#endif
            }
            if (auto perr = platform::invoke_protect_fd(fd); perr) {
                (void)this->bridge.complete(outgoing->flow, outgoing->token, false, now);
                (void)this->bridge.close(outgoing->flow, now);
                return std::unexpected(DirectError{perr});
            }
            int v6only = 0;
            if (::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) != 0) {
                auto error = system_error();
                (void)this->bridge.complete(outgoing->flow, outgoing->token, false, now);
                (void)this->bridge.close(outgoing->flow, now);
                return std::unexpected(DirectError{error});
            }
            utility::scope_exit rollback([&] {
                (void)this->bridge.complete(outgoing->flow, outgoing->token, false, now);
                (void)this->bridge.close(outgoing->flow, now);
            });
            sockets.push_back(std::move(guard));
            rollback.release();
            it = std::prev(sockets.end());
        }
        auto target = address(outgoing->remote);
        auto n = ::sendto(it->fd, outgoing->payload.data(), outgoing->payload.size(), 0,
                          reinterpret_cast<sockaddr const*>(&target), sizeof(target));
        if (n < 0 || static_cast<std::size_t>(n) != outgoing->payload.size()) {
            auto error = n < 0 ? system_error() : std::make_error_code(std::errc::io_error);
            (void)this->bridge.complete(outgoing->flow, outgoing->token, false, now);
            if (error != std::errc::resource_unavailable_try_again && error != std::errc::operation_would_block &&
                error != std::errc::interrupted && error != std::errc::message_size)
                (void)this->bridge.close(outgoing->flow, now);
            return std::unexpected(DirectError{error});
        }
        auto complete = this->bridge.complete(outgoing->flow, outgoing->token, true, now);
        if (!complete) return std::unexpected(DirectError{complete.error()});
        return {};
    }
    auto Direct6::poll(std::uint64_t now) -> std::expected<std::vector<packet::Bytes>, DirectError> {
        auto expired = this->bridge.expire(now);
        if (!expired) return std::unexpected(DirectError{expired.error()});
        if (this->deferred_error) {
            auto error = *this->deferred_error;
            this->deferred_error.reset();
            return std::unexpected(DirectError{error});
        }
        if (std::exchange(this->deferred_allocation_failure, false)) throw std::bad_alloc();
        auto& sockets = this->sockets;
        std::vector<packet::Bytes> result;
        if (sockets.empty()) return result;
        auto count = std::min<std::size_t>(sockets.size(), 64);
        result.reserve(count);
        auto start = this->cursor % sockets.size();
        std::array<std::uint8_t, 65536> buffer{};
        for (std::size_t i = 0; i < count; ++i) {
            auto& socket = sockets[(start + i) % sockets.size()];
            sockaddr_in6 from{}; socklen_t length = sizeof(from);
            auto n = ::recvfrom(socket.fd, buffer.data(), buffer.size(), MSG_TRUNC | MSG_PEEK,
                                reinterpret_cast<sockaddr*>(&from), &length);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
                auto error = system_error();
                auto id = socket.id;
                (void)this->bridge.close(id, now);
                if (!result.empty()) { this->deferred_error = error; return result; }
                return std::unexpected(DirectError{error});
            }
            std::optional<packet::Bytes> ready;
            if (length >= sizeof(from) && from.sin6_family == AF_INET6 && from.sin6_scope_id == 0 && static_cast<std::size_t>(n) <= buffer.size()) {
                try {
                    auto reply = this->bridge.reply(socket.id, endpoint(from), std::span(buffer).first(static_cast<std::size_t>(n)), now);
                    if (reply) ready = std::move(*reply);
                } catch (std::bad_alloc const&) {
                    this->cursor = (start + i) % sockets.size();
                    if (!result.empty()) { this->deferred_allocation_failure = true; return result; }
                    throw;
                }
            }
            auto consumed = ::recvfrom(socket.fd, buffer.data(), buffer.size(), MSG_TRUNC, nullptr, nullptr);
            if (consumed < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
                auto error = system_error(); auto id = socket.id; (void)this->bridge.close(id, now);
                if (!result.empty()) { this->deferred_error = error; return result; }
                return std::unexpected(DirectError{error});
            }
            if (ready && consumed == n) result.push_back(std::move(*ready));
        }
        this->cursor = (start + count) % sockets.size();
        return result;
    }
}
