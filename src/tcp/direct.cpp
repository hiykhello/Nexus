module;
#include <experimental/scope>
#include <arpa/inet.h>
#include <cerrno>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
module nexus.tcp.direct;
import std;

namespace nexus::tcp {
    namespace {
        auto system_error() -> std::error_code { return {errno, std::generic_category()}; }
    }
    Direct4::Flow::Flow(ConnectionId i, std::uint64_t time, int f, bool c)
        : id(i), started(time), fd(f), connecting(c) {}
    Direct4::Flow::~Flow() { if (fd >= 0) ::close(fd); }
    Direct4::Direct4(ConnectionTable& table, MemoryEngine& engine, rules::Matcher policy, std::size_t limit,
                     std::optional<std::uint32_t> socket_mark)
        : table(table), engine(engine), policy(std::move(policy)), limit(limit), socket_mark(socket_mark) {}
    Direct4::~Direct4() = default;
    auto Direct4::size() const noexcept -> std::size_t { return this->flows.size(); }
    auto Direct4::close(ConnectionId id) noexcept -> bool {
        auto it = std::ranges::find(this->flows, id, &Flow::id);
        if (it == this->flows.end()) return false;
        this->flows.erase(it); return true;
    }
    auto Direct4::start(ConnectionId id, std::uint64_t now) -> std::expected<void, DirectFailure> {
        auto& s = *this;
        if (s.initialized && now < s.now) return std::unexpected(DirectFailure{DirectError::time_reversed});
        s.initialized = true; s.now = now;
        if (std::ranges::find(s.flows, id, &Flow::id) != s.flows.end()) return std::unexpected(DirectFailure{DirectError::duplicate});
        if (s.flows.size() >= s.limit) return std::unexpected(DirectFailure{DirectError::full});
        auto* flow = s.table.get(id);
        auto target = s.table.target(id);
        if (!flow || !target) return std::unexpected(DirectFailure{DirectError::not_found});
        if (flow->state() != ConnectionState::established && flow->state() != ConnectionState::peer_closed)
            return std::unexpected(DirectFailure{DirectError::not_established});
        auto const& a = target->address;
        if (!target->port || std::ranges::all_of(a,[](auto b) { return b==0; }))
            return std::unexpected(DirectFailure{DirectError::invalid_target});
        auto text = std::format("{}.{}.{}.{}", a[0], a[1], a[2], a[3]);
        auto match = s.policy.match({.ip=text});
        if (!match) return std::unexpected(DirectFailure{DirectError::policy_error});
        if (match->has_value()) return std::unexpected(DirectFailure{DirectError::blocked});
        int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
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
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(target->port);
        auto host = (std::uint32_t{a[0]} << 24) | (std::uint32_t{a[1]} << 16) | (std::uint32_t{a[2]} << 8) | a[3];
        address.sin_addr.s_addr = htonl(host);
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
    auto Direct4::step(std::uint64_t now) -> std::expected<DirectStep, DirectError> {
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
