// nghttp2 callback policy for h2mux (HTTP/2 multiplex over nghttp2).
export module mux.h2mux_policy;
import std;
import capy;
import http2.headers;
import http2.session_core;
import nghttp2;

export namespace mux::h2mux {
    namespace h2 = ::nghttp2;

    enum class StreamError : std::uint8_t { closed, limit, protocol };

    struct Limits {
        std::size_t max_streams = 256;
        std::size_t stream_window = 256 * 1024;
        std::size_t max_tx_queue = 256 * 1024;
        std::size_t library_bytes = 8 * 1024 * 1024;
    };

    namespace detail {
        struct StreamState {
            std::int32_t id = 0;
            std::vector<std::uint8_t> rx;
            std::size_t rx_off = 0, uncredited = 0;
            std::deque<std::vector<std::uint8_t>> tx;
            std::size_t tx_off = 0, tx_bytes = 0;
            std::uint64_t end_send_seq = 0;
            bool response_ready = false, remote_end = false, local_end_req = false;
            bool local_end_sent = false, closed = false, failed = false, deferred = false, released = false;
        };

        struct Policy {
            using Failure = int;
            bool client = false;
            Limits limits{};
            std::unordered_map<std::int32_t, std::unique_ptr<StreamState>> streams;
            std::deque<std::int32_t> accepted;
            std::optional<int> failure_code;
            std::uint64_t send_seq = 0;
            bool draining = false;
            capy::async_event* rx_ev = nullptr;
            capy::async_event* tx_ev = nullptr;
            capy::async_event* accept_ev = nullptr;
            capy::async_event* write_ev = nullptr;

            Policy(bool is_client, Limits lim, capy::async_event* rx, capy::async_event* tx,
                   capy::async_event* acc, capy::async_event* wr) noexcept
                : client(is_client), limits(lim), rx_ev(rx), tx_ev(tx), accept_ev(acc), write_ev(wr) {}

            static auto core_error(http2::detail::CoreError, int code = 0) noexcept -> int { return code ? code : -1; }
            auto core_fail(http2::detail::CoreError, int code = 0) noexcept -> int {
                if (!failure_code) failure_code = code ? code : -1;
                return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            auto failure() const noexcept -> std::optional<int> { return failure_code; }
            auto memory_charge() const noexcept -> std::size_t { return 0; }
            auto cleanup() noexcept -> void { streams.clear(); accepted.clear(); }

            auto find(std::int32_t id) noexcept -> StreamState* {
                auto it = streams.find(id);
                return it == streams.end() ? nullptr : it->second.get();
            }
            auto open_count() const noexcept -> std::size_t {
                std::size_t n = 0;
                for (auto const& [_, s] : streams) if (s && !s->closed && !s->released) ++n;
                return n;
            }
            auto active_user_streams() const noexcept -> std::size_t {
                std::size_t n = 0;
                for (auto const& [_, s] : streams) if (s && !s->released) ++n;
                return n;
            }
            auto accepts_header(std::int32_t id) noexcept -> bool {
                auto* st = find(id);
                return st && !st->failed && !st->released;
            }
            template<class Core>
            auto reject_headers(Core& core, std::int32_t id, http2::detail::CoreError) noexcept -> int {
                if (auto* st = find(id)) {
                    st->failed = true;
                    if (!client && !st->response_ready) st->released = true;
                }
                auto rc = h2::nghttp2_submit_rst_stream(core.native(), 0, id, h2::NGHTTP2_CANCEL);
                return rc ? core_fail(http2::detail::CoreError::http2, rc) : 0;
            }

            template<class Core>
            auto begin(Core& core, h2::nghttp2_frame const& frame) noexcept -> int {
                if (!client && frame.headers.cat == h2::NGHTTP2_HCAT_REQUEST) {
                    if (draining || open_count() >= limits.max_streams || streams.size() >= limits.max_streams * 2 + 16) {
                        auto rc = h2::nghttp2_submit_rst_stream(core.native(), 0, frame.hd.stream_id, h2::NGHTTP2_REFUSED_STREAM);
                        return rc ? core_fail(http2::detail::CoreError::http2, rc) : h2::NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
                    }
                    try {
                        auto st = std::make_unique<StreamState>();
                        st->id = frame.hd.stream_id;
                        auto* raw = st.get();
                        streams.emplace(frame.hd.stream_id, std::move(st));
                        (void)h2::nghttp2_session_set_stream_user_data(core.native(), frame.hd.stream_id, raw);
                    } catch (...) {
                        return core_fail(http2::detail::CoreError::allocation, h2::NGHTTP2_ERR_NOMEM);
                    }
                }
                return 0;
            }

            template<class Core>
            auto frame(Core& core, h2::nghttp2_frame const& frame) noexcept -> int {
                if (frame.hd.type == h2::NGHTTP2_GOAWAY) {
                    draining = true;
                    if (frame.goaway.error_code)
                        return core_fail(http2::detail::CoreError::http2, static_cast<int>(frame.goaway.error_code));
                    if (client) {
                        for (auto& [id, st] : streams)
                            if (st && id > frame.goaway.last_stream_id) st->failed = true;
                        if (rx_ev) rx_ev->set();
                        if (tx_ev) tx_ev->set();
                    }
                    return 0;
                }
                auto* st = find(frame.hd.stream_id);
                if (!st) return 0;
                bool const end = (frame.hd.flags & h2::NGHTTP2_FLAG_END_STREAM) != 0;
                if (frame.hd.type == h2::NGHTTP2_HEADERS) {
                    if (!client && frame.headers.cat == h2::NGHTTP2_HCAT_REQUEST) {
                        if (st->response_ready) return 0;
                        bool valid_method = false;
                        for (auto const& f : core.headers().fields())
                            if (f.name == ":method" && (f.value == "CONNECT" || f.value == "POST")) valid_method = true;
                        if (!valid_method) {
                            st->failed = true;
                            st->released = true;
                            auto rc = h2::nghttp2_submit_rst_stream(core.native(), 0, st->id, h2::NGHTTP2_PROTOCOL_ERROR);
                            return rc ? core_fail(http2::detail::CoreError::http2, rc) : 0;
                        }
                        std::array<h2::nghttp2_nv, 1> resp{{Core::nv(":status", "200")}};
                        auto provider = core.provider(st);
                        auto rc = h2::nghttp2_submit_response2(core.native(), st->id, resp.data(), resp.size(), &provider);
                        if (rc) return core_fail(http2::detail::CoreError::http2, rc);
                        st->response_ready = true;
                        if (end) st->remote_end = true;
                        try { accepted.push_back(st->id); }
                        catch (...) { return core_fail(http2::detail::CoreError::allocation, h2::NGHTTP2_ERR_NOMEM); }
                        if (accept_ev) accept_ev->set();
                        if (write_ev) write_ev->set();
                    } else if (client && frame.headers.cat == h2::NGHTTP2_HCAT_RESPONSE) {
                        bool ok_status = false;
                        for (auto const& f : core.headers().fields())
                            if (f.name == ":status" && f.value == "200") ok_status = true;
                        if (!ok_status) {
                            st->failed = true;
                            auto rc = h2::nghttp2_submit_rst_stream(core.native(), 0, st->id, h2::NGHTTP2_CANCEL);
                            if (rx_ev) rx_ev->set();
                            if (tx_ev) tx_ev->set();
                            return rc ? core_fail(http2::detail::CoreError::http2, rc) : 0;
                        }
                        st->response_ready = true;
                        if (end) st->remote_end = true;
                        if (rx_ev) rx_ev->set();
                    } else if (end) {
                        st->remote_end = true;
                        if (rx_ev) rx_ev->set();
                    }
                    return 0;
                }
                if (frame.hd.type == h2::NGHTTP2_DATA && end) {
                    st->remote_end = true;
                    if (rx_ev) rx_ev->set();
                }
                return 0;
            }

            template<class Core>
            auto sent(Core&, h2::nghttp2_frame const& frame) noexcept -> int {
                if ((frame.hd.type == h2::NGHTTP2_DATA || frame.hd.type == h2::NGHTTP2_HEADERS) &&
                    (frame.hd.flags & h2::NGHTTP2_FLAG_END_STREAM)) {
                    if (auto* st = find(frame.hd.stream_id)) {
                        st->local_end_sent = true;
                        st->end_send_seq = send_seq;
                        if (tx_ev) tx_ev->set();
                    }
                }
                return 0;
            }

            template<class Core>
            auto data(Core& core, std::uint8_t, std::int32_t id, std::span<std::uint8_t const> bytes) noexcept -> int {
                auto* st = find(id);
                if (!st || st->released || st->failed) {
                    auto rc = h2::nghttp2_session_consume_connection(core.native(), bytes.size());
                    return rc ? core_fail(http2::detail::CoreError::http2, rc) : 0;
                }
                if (st->rx_off > 0 && (st->rx_off >= 65536 || st->rx_off == st->rx.size())) {
                    auto rem = st->rx.size() - st->rx_off;
                    if (rem > 0) std::memmove(st->rx.data(), st->rx.data() + st->rx_off, rem);
                    st->rx.resize(rem);
                    st->rx_off = 0;
                }
                try { st->rx.insert(st->rx.end(), bytes.begin(), bytes.end()); }
                catch (...) { return core_fail(http2::detail::CoreError::allocation, h2::NGHTTP2_ERR_NOMEM); }
                st->uncredited += bytes.size();
                if (rx_ev) rx_ev->set();
                return 0;
            }

            template<class Core>
            auto closed(Core&, std::int32_t id, std::uint32_t code) noexcept -> int {
                if (auto* st = find(id)) {
                    st->closed = true;
                    st->remote_end = true;
                    if (!client && !st->response_ready) st->released = true;
                    if (code != h2::NGHTTP2_NO_ERROR) st->failed = true;
                    st->tx.clear();
                    st->tx_off = st->tx_bytes = 0;
                    if (rx_ev) rx_ev->set();
                    if (tx_ev) tx_ev->set();
                }
                return 0;
            }

            template<class Core>
            auto provide(Core&, std::int32_t id, std::uint8_t* output, std::size_t length,
                         std::uint32_t* flags, h2::nghttp2_data_source*) noexcept -> h2::nghttp2_ssize {
                auto* st = find(id);
                if (!st || st->failed || st->released) return h2::NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
                if (st->tx.empty()) {
                    if (st->local_end_req) {
                        *flags |= h2::NGHTTP2_DATA_FLAG_EOF;
                        return 0;
                    }
                    st->deferred = true;
                    return h2::NGHTTP2_ERR_DEFERRED;
                }
                std::size_t copied = 0;
                while (copied < length && !st->tx.empty()) {
                    auto& front = st->tx.front();
                    auto n = std::min(length - copied, front.size() - st->tx_off);
                    std::memcpy(output + copied, front.data() + st->tx_off, n);
                    copied += n;
                    st->tx_off += n;
                    st->tx_bytes -= n;
                    if (st->tx_off == front.size()) { st->tx.pop_front(); st->tx_off = 0; }
                }
                if (st->tx.empty() && st->local_end_req) *flags |= h2::NGHTTP2_DATA_FLAG_EOF;
                if (tx_ev) tx_ev->set();
                return static_cast<h2::nghttp2_ssize>(copied);
            }
        };
    }
}
