module;
#include <experimental/scope>
#include <cerrno>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
module tcp.direct;
import std;
import platform.ip_address;

namespace tcp {
    namespace {
        auto system_error() -> std::error_code { return {errno, std::generic_category()}; }
    }
    Direct6::Flow::Flow(ConnectionId i, std::uint64_t time, int f, bool c)
        : id(i), started(time), fd(f), connecting(c) {}
    Direct6::Flow::~Flow() { if (fd >= 0) ::close(fd); }
    Direct6::Direct6(ConnectionTable6& table, MemoryEngine6& engine, rules::Matcher policy, std::size_t limit,
                     std::optional<std::uint32_t> socket_mark)
        : table(table), engine(engine), policy(std::move(policy)), limit(limit), socket_mark(socket_mark) {}
    Direct6::~Direct6() = default;
    auto Direct6::size() const noexcept -> std::size_t { return this->flows.size(); }
    auto Direct6::close(ConnectionId id) noexcept -> bool {
        auto it = std::ranges::find(this->flows, id, &Flow::id);
        if (it == this->flows.end()) return false;
        this->flows.erase(it); return true;
    }
    auto Direct6::start(ConnectionId id, std::uint64_t now) -> std::expected<void, DirectFailure> {
        auto& s = *this;
        if (s.initialized && now < s.now) return std::unexpected(DirectFailure{DirectError::time_reversed});
        s.initialized = true; s.now = now;
        if (std::ranges::find(s.flows, id, &Flow::id) != s.flows.end()) return std::unexpected(DirectFailure{DirectError::duplicate});
        if (s.flows.size() >= s.limit) return std::unexpected(DirectFailure{DirectError::full});
        auto* flow = s.table.get(id);
        auto endpoints = s.table.endpoints(id);
        if (!flow || !endpoints) return std::unexpected(DirectFailure{DirectError::not_found});
        auto target = &endpoints->target;
        if (flow->state() != ConnectionState::established && flow->state() != ConnectionState::peer_closed)
            return std::unexpected(DirectFailure{DirectError::not_established});
        auto const& a = target->address;
        bool mapped=std::ranges::all_of(std::span(a).first<10>(),[](auto b) { return b==0; }) && a[10]==255 && a[11]==255;
        if (!target->port || std::ranges::all_of(a,[](auto b) { return b==0; }) ||
            (mapped && std::ranges::all_of(std::span(a).last<4>(),[](auto b) { return b==0; })) ||
            (a[0]==0xfe && (a[1]&0xc0)==0x80))
            return std::unexpected(DirectFailure{DirectError::invalid_target});
        auto word=[&](std::size_t i) { return (static_cast<unsigned>(a[i])<<8)|a[i+1]; };
        auto text=std::format("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                              word(0),word(2),word(4),word(6),word(8),word(10),word(12),word(14));
        auto match = s.policy.match({.ip=text,.source_port=endpoints->source.port,.source_ip_bytes=std::span(endpoints->source.address)});
        if (!match) return std::unexpected(DirectFailure{DirectError::policy_error});
        if (match->has_value()) return std::unexpected(DirectFailure{DirectError::blocked});
        if (mapped) {
            auto ipv4=std::format("{}.{}.{}.{}",a[12],a[13],a[14],a[15]);
            auto match4=s.policy.match({.ip=ipv4,.source_port=endpoints->source.port,.source_ip_bytes=std::span(endpoints->source.address)});
            if (!match4) return std::unexpected(DirectFailure{DirectError::policy_error});
            if (match4->has_value()) return std::unexpected(DirectFailure{DirectError::blocked});
        }
        int fd = ::socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            DirectFailure error{system_error()};
            s.flows.emplace_back(id, now, -1, false); s.flows.back().failure = error;
            return std::unexpected(error);
        }
        if (s.socket_mark && ::setsockopt(fd, SOL_SOCKET, SO_MARK, &*s.socket_mark, sizeof(*s.socket_mark)) != 0) {
            DirectFailure error{system_error()}; ::close(fd);
            s.flows.emplace_back(id, now, -1, false); s.flows.back().failure = error;
            return std::unexpected(error);
        }
        sockaddr_in6 address{}; address.sin6_family = AF_INET6; address.sin6_port = platform::host_to_net16(target->port);
        std::ranges::copy(a,address.sin6_addr.s6_addr);
        auto status = ::connect(fd, reinterpret_cast<sockaddr const*>(&address), sizeof(address));
        if (status < 0 && errno != EINPROGRESS) {
            DirectFailure error{system_error()}; ::close(fd);
            s.flows.emplace_back(id, now, -1, false); s.flows.back().failure = error;
            return std::unexpected(error);
        }
        std::experimental::scope_exit guard([fd] { ::close(fd); });
        s.flows.emplace_back(id, now, fd, status < 0);
        guard.release();
        return {};
    }
    auto Direct6::step(std::uint64_t now) -> std::expected<DirectStep, DirectError> {
        auto& s = *this;
        if (s.initialized && now < s.now) return std::unexpected(DirectError::time_reversed);
        s.initialized = true; s.now = now;
        DirectStep report;
        if (s.flows.empty()) return report;
        auto it = std::ranges::find_if(s.flows, [&](auto const& entry) { return entry.id > s.cursor; });
        if (it == s.flows.end()) it = s.flows.begin();
        auto& item = *it; s.cursor = item.id; report.id = item.id;
        auto* flow = s.table.get(item.id);
        if (!flow || flow->state() == ConnectionState::reset || flow->state() == ConnectionState::expired) {
            s.flows.erase(it); report.retired = true; return report;
        }
        auto reset_failed = [&]() {
            auto reset = s.engine.reset(item.id, now);
            if (!reset) { report.error = DirectFailure{reset.error()}; s.flows.erase(it); report.retired = true; return; }
            report.read_backpressured = reset->notification.backpressured;
            report.output_error = reset->notification.output_error;
            if (reset->connection_error) { report.error = DirectFailure{*reset->connection_error}; s.flows.erase(it); report.retired = true; return; }
            if (flow->state() == ConnectionState::reset) { s.flows.erase(it); report.retired = true; }
        };
        if (item.failure) { reset_failed(); return report; }
        auto time = flow->send_due(now, 0);
        if (!time) { report.error = DirectFailure{time.error()}; return report; }
        auto fail = [&](DirectFailure error) {
            report.error = error; item.failure = std::move(error);
            if (item.fd >= 0) { ::close(item.fd); item.fd = -1; }
            reset_failed();
        };
        if (item.connecting) {
            if (now - item.started >= 10000) { fail(DirectFailure{DirectError::connect_timeout}); return report; }
            pollfd pfd{.fd=item.fd, .events=POLLOUT, .revents=0};
            auto ready = ::poll(&pfd, 1, 0);
            if (ready < 0) { if (errno != EINTR) fail(DirectFailure{system_error()}); return report; }
            if (!ready) return report;
            int error = 0; socklen_t size = sizeof(error);
            if (::getsockopt(item.fd, SOL_SOCKET, SO_ERROR, &error, &size) < 0) { fail(DirectFailure{system_error()}); return report; }
            if (error) { fail(DirectFailure{std::error_code{error, std::generic_category()}}); return report; }
            item.connecting = false;
        }
        report.connected = true;
        if (item.begin == item.end && !item.local_eof) {
            auto read = s.engine.read(item.id, item.buffer, now, false);
            if (!read) { fail(DirectFailure{read.error()}); return report; }
            if (read->connection_error) { fail(DirectFailure{*read->connection_error}); return report; }
            report.read_backpressured = read->notification.backpressured;
            report.output_error = read->notification.output_error;
            item.begin = 0; item.end = read->bytes; item.local_eof = read->eof;
        }
        if (item.begin < item.end) {
            auto n = ::send(item.fd, item.buffer.data() + item.begin, item.end - item.begin, MSG_NOSIGNAL);
            if (n < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { fail(DirectFailure{system_error()}); return report; }
            } else {
                item.begin += static_cast<std::size_t>(n); report.to_upstream = static_cast<std::size_t>(n);
            }
        }
        if (item.local_eof && item.begin == item.end && !item.shutdown_sent) {
            if (::shutdown(item.fd, SHUT_WR) < 0) { fail(DirectFailure{system_error()}); return report; }
            item.shutdown_sent = true;
            (void)s.table.observe_eof(item.id);
        }
        auto capacity = std::min(flow->send_capacity(), item.incoming.size());
        if (!item.remote_eof && !item.incoming_size && capacity) {
            auto n = ::recv(item.fd, item.incoming.data(), capacity, 0);
            if (n < 0) { if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) fail(DirectFailure{system_error()}); return report; }
            if (!n) {
                item.remote_eof = true;
                if (auto closed = flow->close_send(); !closed) fail(DirectFailure{closed.error()});
            } else {
                item.incoming_size = static_cast<std::size_t>(n);
            }
        }
        if (item.incoming_size) {
            auto added = flow->enqueue(std::span(item.incoming).first(item.incoming_size));
            if (!added) { fail(DirectFailure{added.error()}); return report; }
            report.from_upstream = std::exchange(item.incoming_size,0);
        }
        return report;
    }
}
