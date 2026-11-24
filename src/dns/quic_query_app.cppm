// QUIC DoQ application state machine module.
export module dns.quic_query_app;
import std;
import dns.corosio_query;
import dns.input_budget;
import quic.cid_registry;
import quic.connection;
import capy;
import ngtcp2;

export namespace dns::doq_detail {
    using Clock = std::chrono::steady_clock;
    using Error = detail::UdpError;
    namespace n = ::ngtcp2;
    namespace capy = ::capy;
    using namespace std::chrono_literals;

    constexpr std::size_t max_streams = 16;
    constexpr std::uint64_t protocol_error = 2, request_cancelled = 3;

    struct Frame {
        Bytes bytes;
        InputBudget::Lease lease;
    };

    struct Query {
        Bytes wire;
        Clock::time_point deadline;
        capy::async_event wake;
        std::optional<std::expected<Frame, Error>> result;
        std::size_t written = 0, received = 0;
        std::array<std::uint8_t, 2> length{};
        std::optional<InputBudget::Lease> lease;
        Bytes reply;
        bool fin_sent = false, reset = false, submitted_bytes = false, replayable;

        Query(Bytes frame, Clock::time_point until, bool can_replay)
            : wire(std::move(frame)), deadline(until), replayable(can_replay) {}
    };

    template<class Tls, bool SupportsEarlyData>
    class Application {
        using Transport = quic::Connection<Tls, Application>;
        using Registry = quic::CidRegistry<1, 8>;
        Registry& registry_;
        quic::SessionHandle owner_;
        Transport* transport_ = nullptr;
        std::deque<std::shared_ptr<Query>> waiting_;
        std::map<std::int64_t, std::shared_ptr<Query>> streams_;
        std::size_t requests_ = 0;
        Clock::time_point idle_until_ = Clock::now() + 1s;
        enum class Early { inactive, available, sending };
        Early early_ = Early::inactive;
        bool ready_ = false, stopping_ = false;
        std::uint64_t close_code_ = 0;

        auto resolve(Query& query, std::expected<Frame, Error> result) noexcept -> void {
            if (query.result) return;
            query.result.emplace(std::move(result));
            if (!--requests_) idle_until_ = Clock::now() + 1s;
            query.wake.set();
        }
        auto invalid(Query& query) noexcept -> int {
            close_code_ = protocol_error;
            resolve(query, std::unexpected(Error::protocol));
            return 0;
        }

    public:
        Application(Registry& registry, quic::SessionHandle slot) : registry_(registry), owner_(slot) {}
        auto attach(Transport& transport) noexcept -> void { transport_ = &transport; }
        auto time(std::uint64_t) noexcept -> void {}
        auto joined() noexcept -> void {}
        auto close_error(n::ngtcp2_ccerr& error) const noexcept -> void {
            if (close_code_) n::ngtcp2_ccerr_set_application_error(&error, close_code_, nullptr, 0);
        }
        auto ready() const noexcept -> bool { return ready_; }
        auto stopping() const noexcept -> bool { return stopping_; }
        auto poisoned() const noexcept -> bool { return close_code_ != 0; }
        auto reject_protocol() noexcept -> void { close_code_ = protocol_error; }
        auto idle_deadline() const noexcept -> std::optional<Clock::time_point> {
            if (requests_) return {};
            return idle_until_;
        }
        auto available() const noexcept -> bool {
            return !stopping_ && !close_code_ && waiting_.size() + streams_.size() < max_streams;
        }
        auto submit(std::shared_ptr<Query> const& query) -> void {
            waiting_.push_back(query);
            ++requests_;
        }
        auto leave(std::shared_ptr<Query> const& query) noexcept -> void {
            if (query->result) return;
            std::erase(waiting_, query);
            query->reset = true;
            resolve(*query, std::unexpected(Error::canceled));
        }
        auto request_stop() noexcept -> void {
            if (std::exchange(stopping_, true)) return;
            auto error = close_code_ ? Error::protocol : Error::transport;
            for (auto const& query : waiting_) resolve(*query, std::unexpected(error));
            waiting_.clear();
            for (auto const& [id, query] : streams_) resolve(*query, std::unexpected(error));
        }
        auto drain() noexcept -> void { early_ = Early::inactive; request_stop(); streams_.clear(); }
        auto connection_closed(Transport&, int) noexcept -> void { request_stop(); }
        auto allow_early_data() noexcept -> void { early_ = Early::available; }
        auto accept_early_data() noexcept -> void { early_ = Early::inactive; }
        auto reject_early_data() -> void {
            if (std::exchange(early_, Early::inactive) != Early::sending) return;
            auto moved = std::move(streams_);
            streams_.clear();
            for (auto it = moved.rbegin(); it != moved.rend(); ++it) {
                auto& query = it->second;
                if (!query || query->result) continue;
                query->written = 0;
                query->fin_sent = false;
                waiting_.push_front(std::move(query));
            }
        }
        auto handshake_complete(Transport&) noexcept -> int {
            early_ = Early::inactive;
            ready_ = true;
            return 0;
        }
        auto handshake_confirmed(Transport&) noexcept -> int { return 0; }
        auto add_connection_id(Transport&, n::ngtcp2_cid const& id, n::ngtcp2_stateless_reset_token const&) noexcept -> int {
            return registry_.insert(owner_, {id.data, id.datalen}) ? 0 : n::err_callback_failure;
        }
        auto remove_connection_id(Transport&, n::ngtcp2_cid const& id) noexcept -> int {
            (void)registry_.remove(owner_, {id.data, id.datalen});
            return 0;
        }
        auto stream_limit(Transport&, bool, std::uint64_t) noexcept -> int { return 0; }
        auto stream_limit(Transport&, std::int64_t, std::uint64_t, void*) noexcept -> int { return 0; }
        auto stream_acked(Transport&, std::int64_t, std::uint64_t, std::uint64_t, void*) noexcept -> int { return 0; }
        auto datagram(Transport&, std::span<std::uint8_t const>) noexcept -> int { return n::err_callback_failure; }
        auto stream_close(Transport&, std::uint32_t, std::int64_t id, std::uint64_t, std::uint64_t, void*) noexcept -> int {
            auto it = streams_.find(id);
            if (it != streams_.end()) {
                resolve(*it->second, std::unexpected(Error::transport));
                streams_.erase(it);
            }
            return 0;
        }
        auto stream_reset(Transport&, std::int64_t id, std::uint64_t, std::uint64_t, void*) noexcept -> int {
            if (auto it = streams_.find(id); it != streams_.end()) {
                it->second->reset = true;
                resolve(*it->second, std::unexpected(Error::protocol));
            }
            return 0;
        }
        auto stop_sending(Transport& transport, std::int64_t id, std::uint64_t code, void* data) noexcept -> int {
            return stream_reset(transport, id, 0, code, data);
        }

        auto stream_data(Transport& transport, std::uint32_t flags, std::int64_t id, std::uint64_t offset,
            std::span<std::uint8_t const> input, void*) -> int {
            auto it = streams_.find(id);
            if (it == streams_.end()) {
                close_code_ = protocol_error;
                return 0;
            }
            auto& query = *it->second;
            n::ngtcp2_conn_extend_max_offset(transport.native(), input.size());
            if (query.result && !*query.result) return 0;
            if (query.result || offset != query.received || input.size() > 65537 - query.received)
                return invalid(query);
            auto before = query.received;
            query.received += input.size();
            if (before < query.length.size()) {
                auto count = std::min(input.size(), query.length.size() - before);
                std::ranges::copy(input.first(count), query.length.begin() + before);
                input = input.subspan(count);
            }
            if (query.received >= 2 && !query.lease) {
                auto size = (std::size_t(query.length[0]) << 8) | query.length[1];
                if (size < 12) return invalid(query);
                query.lease = default_upstream_receive_budget().acquire(size);
                if (!query.lease) {
                    query.reset = true;
                    resolve(query, std::unexpected(Error::budget_exhausted));
                    return 0;
                }
                query.reply.reserve(size);
            }
            auto size = (std::size_t(query.length[0]) << 8) | query.length[1];
            if (input.size() > size - query.reply.size()) return invalid(query);
            query.reply.insert(query.reply.end(), input.begin(), input.end());
            if (flags & n::stream_data_flag_fin) {
                if (query.reply.size() < 12 || query.reply.size() != size || query.reply[0] || query.reply[1])
                    return invalid(query);
                resolve(query, Frame{std::move(query.reply), std::move(*query.lease)});
            }
            return 0;
        }

        auto output(std::span<std::uint8_t> packet, std::uint64_t now, n::ngtcp2_path* path)
            -> std::expected<std::size_t, int> {
            if (close_code_) return std::size_t{0};
            auto* native = transport_->native();
            while (!waiting_.empty() && (ready_ || (SupportsEarlyData && early_ == Early::available))) {
                auto query = waiting_.front();
                if (!ready_ && !query->replayable) break;
                if (Clock::now() >= query->deadline) {
                    resolve(*query, std::unexpected(Error::timeout));
                    waiting_.pop_front();
                    continue;
                }
                std::int64_t id = 0;
                auto open = n::ngtcp2_conn_open_bidi_stream(native, &id, nullptr);
                if (open == n::err_stream_id_blocked) break;
                if (open) return std::unexpected(open);
                streams_.emplace(id, std::move(query));
                waiting_.pop_front();
                if (!ready_) early_ = Early::sending;
            }
            if (!ready_ && (!SupportsEarlyData || early_ != Early::sending))
                return transport_->write_packet(packet, path, nullptr, now);
            for (auto const& [id, query] : streams_) {
                if (!ready_ && query->reset) continue;
                if (std::exchange(query->reset, false)) {
                    if (auto error = n::ngtcp2_conn_shutdown_stream(native, 0, id, request_cancelled))
                        return std::unexpected(error);
                    query->fin_sent = true;
                }
                if (query->fin_sent) continue;
                auto bytes = std::span(query->wire).subspan(query->written);
                n::ngtcp2_vec vector{bytes.data(), bytes.size()};
                auto written = transport_->write_stream(packet, path, nullptr, id, {&vector, 1}, true, now);
                if (!written) {
                    if (written.error() == n::err_stream_data_blocked) continue;
                    return std::unexpected(written.error());
                }
                if (written->stream_bytes >= 0) {
                    query->submitted_bytes |= written->stream_bytes > 0;
                    query->written += static_cast<std::size_t>(written->stream_bytes);
                    query->fin_sent = query->written == query->wire.size();
                }
                if (written->packet_bytes) return written->packet_bytes;
            }
            return transport_->write_packet(packet, path, nullptr, now);
        }
    };
}
