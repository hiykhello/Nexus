// Bounded smux v1 & v2 stream table and sliding-window flow-control accounting.
export module mux.smux_streams;
import std;
import mux.smux_wire;

export namespace mux::smux {
    enum class StreamError { closed, full, exhausted, invalid, duplicate, backpressure };
    enum class PushResult { queued, discarded, backpressure };

    struct Limits {
        std::size_t max_streams = 64;
        std::size_t max_frame_size = default_max_frame_size;
        std::size_t per_stream_rx_bytes = initial_peer_window;
        std::size_t total_rx_bytes = 4 * 1024 * 1024;
        std::size_t per_stream_frames = 256;
        std::size_t total_frames = 2048;

        [[nodiscard]] auto valid() const noexcept -> bool {
            return max_streams > 0 && max_streams <= 1024 && max_frame_size > 0 && max_frame_size <= 65535 &&
                   per_stream_rx_bytes > 0 && total_rx_bytes >= per_stream_rx_bytes &&
                   per_stream_frames > 0 && total_frames >= per_stream_frames;
        }
    };

    struct ReadOutcome {
        std::size_t bytes_read = 0;
        std::optional<UpdPayload> upd;
    };

    class StreamTable {
        struct Stream {
            std::uint32_t id = 0;
            std::deque<std::vector<std::uint8_t>> rx_queue;
            std::size_t rx_buffered = 0, rx_offset = 0;
            bool remote_fin = false, local_fin = false;
            std::uint32_t rx_consumed = 0, rx_last_upd = 0;
            std::uint32_t rx_window = initial_peer_window;
            std::uint32_t tx_sent = 0, tx_peer_consumed = 0, tx_peer_window = initial_peer_window;
        };

        std::vector<Stream> streams_;
        Limits limits_;
        bool client_;
        std::uint8_t version_;
        std::size_t buffered_{0};
        std::uint64_t next_id_;
        bool closed_{false};

        auto find(std::uint32_t id) noexcept -> Stream* {
            if (!id) return nullptr;
            for (auto& s : streams_) if (s.id == id) return &s;
            return nullptr;
        }
        auto find(std::uint32_t id) const noexcept -> Stream const* {
            if (!id) return nullptr;
            for (auto const& s : streams_) if (s.id == id) return &s;
            return nullptr;
        }
    public:
        StreamTable(bool client, std::uint8_t version = version_2, Limits limits = {})
            : limits_(limits), client_(client), version_(version), next_id_(client ? 1u : 2u) {
            if (!limits.valid() || (version != version_1 && version != version_2))
                throw std::invalid_argument("invalid smux stream limits");
            streams_.reserve(std::min<std::size_t>(limits_.max_streams, 64));
        }

        StreamTable(StreamTable const&) = delete;
        auto operator=(StreamTable const&) -> StreamTable& = delete;

        auto set_version(std::uint8_t version) noexcept -> bool {
            if (version != version_1 && version != version_2) return false;
            version_ = version;
            return true;
        }
        [[nodiscard]] auto version() const noexcept -> std::uint8_t { return version_; }

        [[nodiscard]] auto open() -> std::expected<std::uint32_t, StreamError> {
            if (closed_) return std::unexpected(StreamError::closed);
            if (next_id_ > std::numeric_limits<std::uint32_t>::max()) return std::unexpected(StreamError::exhausted);
            if (streams_.size() >= limits_.max_streams) return std::unexpected(StreamError::full);
            auto id = static_cast<std::uint32_t>(next_id_);
            if (find(id)) return std::unexpected(StreamError::duplicate);
            streams_.push_back(Stream{
                .id = id,
                .rx_window = static_cast<std::uint32_t>(limits_.per_stream_rx_bytes),
                .tx_peer_window = initial_peer_window,
            });
            next_id_ += 2;
            return id;
        }

        [[nodiscard]] auto accept(std::uint32_t id) -> std::expected<void, StreamError> {
            if (closed_) return std::unexpected(StreamError::closed);
            bool const peer_parity_ok = client_ ? ((id & 1u) == 0u) : ((id & 1u) == 1u);
            if (!id || !peer_parity_ok) return std::unexpected(StreamError::invalid);
            if (find(id)) return std::unexpected(StreamError::duplicate);
            if (streams_.size() >= limits_.max_streams) return std::unexpected(StreamError::full);
            streams_.push_back(Stream{
                .id = id,
                .rx_window = static_cast<std::uint32_t>(limits_.per_stream_rx_bytes),
                .tx_peer_window = initial_peer_window,
            });
            return {};
        }

        [[nodiscard]] auto push(std::uint32_t id, std::span<std::uint8_t const> payload) -> PushResult {
            auto* s = find(id);
            if (closed_ || !s || s->remote_fin || payload.empty()) return PushResult::discarded;
            if (payload.size() > limits_.per_stream_rx_bytes ||
                s->rx_buffered > limits_.per_stream_rx_bytes - payload.size() ||
                payload.size() > limits_.total_rx_bytes ||
                buffered_ > limits_.total_rx_bytes - payload.size())
                return PushResult::backpressure;
            auto const chunk_cap = std::max(limits_.max_frame_size, default_max_frame_size);
            if (!s->rx_queue.empty() && s->rx_queue.back().size() <= chunk_cap &&
                payload.size() <= chunk_cap - s->rx_queue.back().size()) {
                s->rx_queue.back().insert(s->rx_queue.back().end(), payload.begin(), payload.end());
            } else {
                s->rx_queue.emplace_back(payload.begin(), payload.end());
            }
            s->rx_buffered += payload.size();
            buffered_ += payload.size();
            return PushResult::queued;
        }

        [[nodiscard]] auto read(std::uint32_t id, std::span<std::uint8_t> out) noexcept
            -> std::expected<ReadOutcome, StreamError> {
            auto* s = find(id);
            if (!s) return std::unexpected(StreamError::invalid);
            if (out.empty()) return ReadOutcome{};
            if (s->rx_queue.empty()) {
                if (closed_ && !s->remote_fin) return std::unexpected(StreamError::closed);
                return s->remote_fin ? std::expected<ReadOutcome, StreamError>{ReadOutcome{0, std::nullopt}}
                                     : std::unexpected(StreamError::backpressure);
            }
            auto& front = s->rx_queue.front();
            auto count = std::min(out.size(), front.size() - s->rx_offset);
            std::copy_n(front.begin() + s->rx_offset, count, out.begin());
            s->rx_offset += count;
            s->rx_buffered -= count;
            buffered_ -= count;
            if (s->rx_offset == front.size()) {
                s->rx_queue.pop_front();
                s->rx_offset = 0;
            }
            s->rx_consumed = static_cast<std::uint32_t>(s->rx_consumed + count);
            std::optional<UpdPayload> upd;
            if (version_ == version_2 && !s->remote_fin && !closed_) {
                std::uint32_t delta = s->rx_consumed - s->rx_last_upd;
                if (delta >= s->rx_window / 2) {
                    s->rx_last_upd = s->rx_consumed;
                    upd = UpdPayload{s->rx_consumed, s->rx_window};
                }
            }
            return ReadOutcome{count, upd};
        }

        auto on_upd(std::uint32_t id, UpdPayload upd) noexcept -> bool {
            auto* s = find(id);
            if (!s || closed_) return false;
            std::uint32_t const inflight = s->tx_sent - s->tx_peer_consumed;
            std::uint32_t const advance = upd.consumed - s->tx_peer_consumed;
            if (advance > inflight) return false;
            s->tx_peer_consumed = upd.consumed;
            s->tx_peer_window = upd.window;
            return true;
        }

        [[nodiscard]] auto tx_window_available(std::uint32_t id) const noexcept -> std::size_t {
            auto* s = find(id);
            if (!s || closed_ || s->local_fin) return 0;
            if (version_ == version_1) return limits_.max_frame_size;
            std::uint32_t inflight = s->tx_sent - s->tx_peer_consumed;
            if (inflight >= s->tx_peer_window) return 0;
            return std::min<std::size_t>(limits_.max_frame_size, s->tx_peer_window - inflight);
        }

        auto record_tx(std::uint32_t id, std::size_t n) noexcept -> void {
            if (auto* s = find(id)) s->tx_sent = static_cast<std::uint32_t>(s->tx_sent + n);
        }

        auto unrecord_tx(std::uint32_t id, std::size_t n) noexcept -> void {
            if (auto* s = find(id)) s->tx_sent = static_cast<std::uint32_t>(s->tx_sent - n);
        }

        auto finish_remote(std::uint32_t id) noexcept -> bool {
            auto* s = find(id);
            if (!s) return false;
            s->remote_fin = true;
            return true;
        }

        auto finish_local(std::uint32_t id) noexcept -> bool {
            auto* s = find(id);
            if (!s || s->local_fin) return false;
            s->local_fin = true;
            return true;
        }

        [[nodiscard]] auto can_write(std::uint32_t id) const noexcept -> bool {
            auto* s = find(id);
            return !closed_ && s && !s->local_fin;
        }

        [[nodiscard]] auto exists(std::uint32_t id) const noexcept -> bool { return find(id) != nullptr; }

        auto release(std::uint32_t id) noexcept -> bool {
            for (auto it = streams_.begin(); it != streams_.end(); ++it) {
                if (it->id == id) {
                    buffered_ -= it->rx_buffered;
                    streams_.erase(it);
                    return true;
                }
            }
            return false;
        }

        auto close() noexcept -> void {
            closed_ = true;
            for (auto& s : streams_) {
                s.local_fin = true;
                if (!s.remote_fin) {
                    buffered_ -= s.rx_buffered;
                    s.rx_queue.clear();
                    s.rx_buffered = s.rx_offset = 0;
                }
            }
        }

        [[nodiscard]] auto size() const noexcept -> std::size_t { return streams_.size(); }
        [[nodiscard]] auto buffered() const noexcept -> std::size_t { return buffered_; }
        [[nodiscard]] auto closed() const noexcept -> bool { return closed_; }
        [[nodiscard]] auto exhausted() const noexcept -> bool {
            return next_id_ > std::numeric_limits<std::uint32_t>::max();
        }
    };
}
