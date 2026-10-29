module;
#include <experimental/scope>
#include <arpa/inet.h>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
module nexus.udp.direct;
import nexus.rules;
import std;

namespace nexus::udp {
    namespace {
        auto system_error() -> std::error_code { return {errno, std::generic_category()}; }
        auto address(Endpoint4 endpoint) -> sockaddr_in {
            sockaddr_in result{};
            result.sin_family = AF_INET;
            auto const& a = endpoint.address;
            auto n = (std::uint32_t{a[0]} << 24) | (std::uint32_t{a[1]} << 16) | (std::uint32_t{a[2]} << 8) | a[3];
            result.sin_addr.s_addr = htonl(n);
            result.sin_port = htons(endpoint.port);
            return result;
        }
        auto endpoint(sockaddr_in const& address) -> Endpoint4 {
            auto n = ntohl(address.sin_addr.s_addr);
            return {{static_cast<std::uint8_t>(n >> 24), static_cast<std::uint8_t>(n >> 16),
                     static_cast<std::uint8_t>(n >> 8), static_cast<std::uint8_t>(n)}, ntohs(address.sin_port)};
        }
    }
    DirectSocket::DirectSocket(FlowId flow, int value) : id(flow), fd(value) {}
    DirectSocket::DirectSocket(DirectSocket&& other) noexcept : id(other.id), fd(std::exchange(other.fd, -1)) {}
    auto DirectSocket::operator=(DirectSocket&& other) noexcept -> DirectSocket& {
        if (this != &other) { if (fd >= 0) ::close(fd); id = other.id; fd = std::exchange(other.fd, -1); }
        return *this;
    }
    DirectSocket::~DirectSocket() { if (fd >= 0) ::close(fd); }
    Direct4::Direct4(rules::Matcher policy, Mapping mapping, Filtering filtering, Limits limits, std::size_t mtu)
        : bridge(std::move(policy), mapping, filtering, limits, mtu,
                 {this, [](void* self, FlowId id) noexcept {
                     auto& entries = static_cast<Direct4*>(self)->sockets;
                     std::erase_if(entries, [id](DirectSocket const& entry) { return entry.id == id; });
                 }}) {}
    Direct4::~Direct4() = default;
    auto Direct4::size() const noexcept -> std::size_t { return this->bridge.size(); }
    auto Direct4::expire(std::uint64_t now) -> std::expected<std::size_t, Error> { return this->bridge.expire(now); }
    auto Direct4::stop(std::uint64_t now) -> std::expected<void, Error> {
        auto cleared = this->bridge.clear(now);
        if (!cleared) return std::unexpected(cleared.error());
        this->deferred_error.reset();
        this->deferred_allocation_failure = false;
        return {};
    }
    auto Direct4::submit(std::span<std::uint8_t const> input, std::uint64_t now) -> std::expected<void, DirectError> {
        auto outgoing = this->bridge.prepare(input, now);
        if (!outgoing) return std::unexpected(DirectError{outgoing.error()});
        auto& sockets = this->sockets;
        auto it = std::ranges::find(sockets, outgoing->flow, &DirectSocket::id);
        if (it == sockets.end()) {
            int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (fd < 0) {
                auto error = system_error();
                (void)this->bridge.complete(outgoing->flow, outgoing->token, false, now);
                (void)this->bridge.close(outgoing->flow, now);
                return std::unexpected(DirectError{error});
            }
            DirectSocket guard(outgoing->flow, fd);
            std::experimental::scope_exit rollback([&] {
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
            if (error != std::errc::resource_unavailable_try_again && error != std::errc::interrupted)
                (void)this->bridge.close(outgoing->flow, now);
            return std::unexpected(DirectError{error});
        }
        auto complete = this->bridge.complete(outgoing->flow, outgoing->token, true, now);
        if (!complete) return std::unexpected(DirectError{complete.error()});
        return {};
    }
    auto Direct4::poll(std::uint64_t now) -> std::expected<std::vector<packet::Bytes>, DirectError> {
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
            sockaddr_in from{}; socklen_t length = sizeof(from);
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
            if (length >= sizeof(from) && from.sin_family == AF_INET && static_cast<std::size_t>(n) <= buffer.size()) {
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
