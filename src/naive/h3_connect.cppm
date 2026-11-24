export module naive.h3_connect;
import std;
import naive.padding;
import http.header;
import http2.headers;
import http2.client_types;
import masque.http3;
import masque.session;
import masque.datagram;
import masque.connect_udp;
import masque.target;
import masque.client_profile;
import quic.cid_registry;
import quic.connection;
import quic.http3;
import quic.native_memory;
import quic.datagram_port;
import quic.datagram_session;
import quic.tls_client;
import quic.tls_server;
import net.datagram_driver;
import net.udp_connect;
import hysteria2.transport_options;
import platform.socket_options;
import crypto;
import ngtcp2;
import nghttp3;
import capy;
import corosio;

export namespace naive {
    namespace h3 = ::nghttp3;
    namespace q = ::ngtcp2;
    using H3Clock = std::chrono::steady_clock;
    using H3Deadline = std::optional<H3Clock::time_point>;

    inline constexpr std::size_t kH3StreamCapacity = 32;
    inline constexpr std::size_t kH3Window = 128 * 1024;
    inline constexpr std::size_t kH3MaxDatagramQueue = 256;

    inline auto h3_nv(std::string_view key, std::string_view value) noexcept -> h3::nghttp3_nv {
        return {reinterpret_cast<std::uint8_t const*>(key.data()),
                reinterpret_cast<std::uint8_t const*>(value.data()),
                key.size(), value.size(), h3::nv_flag_none};
    }

    inline auto build_connect_udp_path(std::string_view host, std::uint16_t port) -> std::string {
        std::string encoded;
        encoded.reserve(host.size() * 3 + 32);
        encoded += "/.well-known/masque/udp/";
        for (unsigned char c : host) {
            if (c == ':') encoded += "%3A";
            else encoded.push_back(static_cast<char>(c));
        }
        encoded.push_back('/');
        encoded += std::to_string(port);
        encoded.push_back('/');
        return encoded;
    }

    template<class Registry, bool ServerSide, std::size_t Streams, bool EnableDatagrams>
    class H3ConnectHooks {
        Registry& registry_;
        quic::SessionHandle owner_;
        capy::async_event& event_;

    public:
        struct OutboundPacket {
            std::int64_t stream = -1;
            std::vector<std::uint8_t> payload;
        };
        struct OutboundView {
            std::uint64_t stream = 0;
            std::span<std::uint8_t const> payload;
        };
        struct Stream {
            http2::detail::InputRing input{kH3Window};
            std::vector<http2::Header> headers;
            std::vector<std::uint8_t> output;
            std::deque<std::vector<std::uint8_t>> rx_dgrams;
            std::size_t header_bytes = 0, acked = 0;
            bool accepted = false, complete = false, failed = false, closed = false, retired = false, abort = false;
            bool remote_end = false, fin_requested = false, fin_written = false, supplied = false, credited = false;
            bool is_datagram = false;
        };

        std::map<std::int64_t, Stream> streams;
        std::deque<OutboundPacket> tx_dgrams;
        bool dead = false, goaway = false;

        H3ConnectHooks(Registry& registry, quic::SessionHandle owner, capy::async_event& event) noexcept
            : registry_(registry), owner_(owner), event_(event) {}
        static constexpr auto stream_capacity() noexcept -> std::size_t { return Streams; }
        auto changed() noexcept -> void { event_.set(); }
        auto stopping() noexcept -> void { dead = true; tx_dgrams.clear(); changed(); }
        auto h3_closed() noexcept -> void { dead = true; changed(); }
        auto transport_closed() noexcept -> void { dead = true; changed(); }

        auto add_connection_id(q::ngtcp2_cid const& cid, q::ngtcp2_stateless_reset_token const&) noexcept -> int {
            return registry_.insert(owner_, std::span(cid.data).first(cid.datalen)) ? 0 : q::err_callback_failure;
        }
        auto remove_connection_id(q::ngtcp2_cid const& cid) noexcept -> int {
            (void)registry_.remove(owner_, std::span(cid.data).first(cid.datalen));
            return 0;
        }
        auto find(std::int64_t id) noexcept -> Stream* {
            auto it = streams.find(id);
            return it == streams.end() ? nullptr : &it->second;
        }
        auto open(std::int64_t id, bool datagram_stream = false) -> Stream* {
            if (dead || goaway || streams.size() >= Streams) return nullptr;
            auto [it, inserted] = streams.try_emplace(id);
            if (!inserted) return nullptr;
            it->second.is_datagram = datagram_stream;
            return &it->second;
        }
        auto fail(Stream& stream) noexcept -> void {
            stream.failed = true;
            stream.abort = !stream.closed;
            changed();
        }
        auto take_abort() noexcept -> std::optional<std::pair<std::int64_t, std::uint64_t>> {
            for (auto& [id, stream] : streams)
                if (std::exchange(stream.abort, false))
                    return std::pair{id, std::uint64_t{h3::h3_request_cancelled}};
            return {};
        }

        auto stream_state(std::uint64_t id) noexcept -> masque::Http3StreamState {
            if constexpr (!EnableDatagrams) {
                (void)id;
                return {};
            } else {
                auto* s = find(static_cast<std::int64_t>(id));
                if (!s || !s->is_datagram || s->failed || s->closed || s->retired) return {};
                return {masque::Http3StreamKind::datagram, !s->remote_end, !s->fin_requested};
            }
        }
        auto datagram(std::uint64_t id, std::span<std::uint8_t const> pkt) -> int {
            if constexpr (!EnableDatagrams) {
                (void)id; (void)pkt;
                return 0;
            } else {
                auto* s = find(static_cast<std::int64_t>(id));
                if (!s || !s->is_datagram || s->failed || s->closed || s->retired) return 0;
                auto parsed = masque::parse_proxy_datagram(pkt, true);
                if (!parsed) {
                    fail(*s);
                    return 0;
                }
                if (parsed->context_id == 0 && s->rx_dgrams.size() < kH3MaxDatagramQueue) {
                    s->rx_dgrams.emplace_back(parsed->payload.begin(), parsed->payload.end());
                    changed();
                }
                return 0;
            }
        }
        auto datagram_output() -> std::optional<OutboundView> {
            if constexpr (!EnableDatagrams) return {};
            else {
                if (tx_dgrams.empty()) return {};
                return OutboundView{static_cast<std::uint64_t>(tx_dgrams.front().stream), tx_dgrams.front().payload};
            }
        }
        auto datagram_accepted() -> void { if (!tx_dgrams.empty()) { tx_dgrams.pop_front(); changed(); } }
        auto datagram_rejected() -> void { if (!tx_dgrams.empty()) { tx_dgrams.pop_front(); changed(); } }
        auto datagram_budget() const noexcept -> std::size_t { return 1200; }

        auto begin_headers(std::int64_t id, bool trailers) -> int {
            if constexpr (ServerSide) {
                if (!trailers && !open(id)) return h3::err_callback_failure;
            }
            return 0;
        }
        auto header(std::int64_t id, h3::nghttp3_rcbuf* name, h3::nghttp3_rcbuf* value, bool trailers) -> int {
            auto* stream = find(id);
            if (!stream || stream->failed || stream->retired || trailers) return 0;
            auto key = h3::nghttp3_rcbuf_get_buf(name);
            auto field = h3::nghttp3_rcbuf_get_buf(value);
            auto available = http::max_header_bytes - stream->header_bytes;
            if (stream->complete || stream->headers.size() >= 100 ||
                key.len > available || field.len > available - key.len) {
                fail(*stream);
                return 0;
            }
            stream->header_bytes += key.len + field.len;
            stream->headers.emplace_back(
                std::string(reinterpret_cast<char const*>(key.base), key.len),
                std::string(reinterpret_cast<char const*>(field.base), field.len));
            return 0;
        }
        auto end_headers(std::int64_t id, bool fin, bool trailers) noexcept -> int {
            if (auto* stream = find(id); stream && !stream->retired) {
                if (!trailers) stream->complete = true;
                stream->remote_end |= fin;
                changed();
            }
            return 0;
        }
        auto end_stream(std::int64_t id) noexcept -> int { return end_headers(id, true, true); }
        auto data(std::int64_t id, std::span<std::uint8_t const> bytes) noexcept -> int {
            auto* stream = find(id);
            if (!stream) return 0;
            stream->credited = false;
            if (stream->failed || stream->retired) return 0;
            if (!stream->complete || !stream->input.append(bytes)) {
                fail(*stream);
                return 0;
            }
            stream->credited = true;
            changed();
            return 0;
        }
        auto defer_body_credit(std::int64_t id) noexcept -> bool {
            auto* stream = find(id);
            return stream && stream->credited;
        }
        auto data_acked(std::int64_t id, std::uint64_t count) noexcept -> int {
            auto* stream = find(id);
            if (!stream || count > stream->output.size() - stream->acked) return h3::err_callback_failure;
            stream->acked += count;
            if (stream->acked == stream->output.size()) {
                stream->output.clear();
                stream->acked = 0;
                stream->supplied = false;
                changed();
            }
            return 0;
        }
        auto read_data(std::int64_t id, std::span<h3::nghttp3_vec> vectors, std::uint32_t& flags) noexcept
            -> h3::nghttp3_ssize {
            auto* stream = find(id);
            if (!stream || stream->failed || stream->retired) return h3::err_wouldblock;
            if (stream->fin_requested) flags = h3::data_flag_eof;
            if (stream->supplied || stream->output.empty() || vectors.empty())
                return stream->fin_requested ? 0 : h3::err_wouldblock;
            vectors[0] = {stream->output.data(), stream->output.size()};
            stream->supplied = true;
            return 1;
        }
        auto fin_accepted(std::int64_t id) noexcept -> void {
            if (auto* stream = find(id)) stream->fin_written = true;
            changed();
        }
        auto receive_closed(std::int64_t id, std::uint64_t) noexcept -> void {
            if (auto* stream = find(id); stream && !stream->retired) fail(*stream);
        }
        auto send_closed(std::int64_t id, std::uint64_t code) noexcept -> void { receive_closed(id, code); }
        auto closed_reclaimed(std::int64_t id, std::uint64_t, std::uint64_t, std::size_t& discard_bytes) noexcept -> bool {
            auto it = streams.find(id);
            if (it == streams.end()) return true;
            if (it->second.retired) {
                streams.erase(it);
                changed();
                return true;
            }
            if constexpr (ServerSide) {
                if (!it->second.accepted) {
                    discard_bytes = it->second.input.size();
                    streams.erase(it);
                    changed();
                    return true;
                }
            }
            auto& s = it->second;
            s.closed = true;
            s.failed |= !s.remote_end || !s.complete;
            s.abort = false;
            s.output.clear();
            changed();
            return false;
        }
        auto closed(std::int64_t id, std::uint64_t rx, std::uint64_t tx) noexcept -> void {
            std::size_t discard = 0;
            (void)closed_reclaimed(id, rx, tx, discard);
        }
        auto shutdown(std::int64_t first_unprocessed) noexcept -> int {
            goaway = true;
            if constexpr (!ServerSide) {
                for (auto& [id, stream] : streams)
                    if (id >= first_unprocessed && !stream.closed) fail(stream);
            }
            changed();
            return 0;
        }
    };

    template<class Bundle, class Driver>
    class H3StreamHandle {
        Bundle& bundle_;
        Driver& driver_;
        std::int64_t id_;
        PaddingEncoder encoder_;
        PaddingDecoder decoder_;
        std::vector<std::uint8_t> encoded_;
        std::vector<std::uint8_t> decoded_;
        std::size_t decoded_offset_ = 0;
        bool released_ = false;

    public:
        H3StreamHandle(Bundle& bundle, Driver& driver, std::int64_t id, bool use_padding) noexcept
            : bundle_(bundle), driver_(driver), id_(id), encoder_(use_padding), decoder_(use_padding) {}
        H3StreamHandle(H3StreamHandle const&) = delete;
        auto operator=(H3StreamHandle const&) -> H3StreamHandle& = delete;
        ~H3StreamHandle() { release(); }

        auto id() const noexcept -> std::int64_t { return id_; }
        auto arm_padding(bool enabled) noexcept -> void {
            encoder_ = PaddingEncoder{enabled};
            decoder_ = PaddingDecoder{enabled};
        }

        auto state() noexcept { return bundle_.hooks.find(id_); }

        auto wait(H3Deadline deadline = {}) -> capy::task<bool> {
            if (bundle_.hooks.dead) co_return false;
            auto& event = driver_.changed();
            event.clear();
            auto [error] = deadline ? co_await corosio::timeout(event.wait(), *deadline) : co_await event.wait();
            co_return !error && !bundle_.hooks.dead;
        }

        auto respond(std::span<h3::nghttp3_nv const> fields, bool body) -> bool {
            auto* s = state();
            if (!s || s->failed || s->closed) return false;
            if (bundle_.app.h3().response(id_, fields, body)) {
                if (bundle_.app.h3().terminal_error()) { bundle_.app.request_stop(); driver_.notify(); }
                return false;
            }
            s->fin_requested = !body;
            driver_.notify();
            return true;
        }

        auto send_raw(std::span<std::uint8_t const> bytes, bool fin, H3Deadline until = {}) -> capy::task<bool> {
            auto* s = state();
            if (!s || s->failed || s->closed || s->retired || bundle_.hooks.dead) co_return false;
            while (!s->output.empty()) {
                if (!co_await wait(until)) co_return false;
                s = state();
                if (!s || s->failed || s->closed || s->retired || bundle_.hooks.dead) co_return false;
            }
            if (s->fin_requested) co_return false;
            s->output.assign(bytes.begin(), bytes.end());
            s->fin_requested = fin;
            if (bundle_.app.h3().resume(id_)) {
                if (bundle_.app.h3().terminal_error()) bundle_.app.request_stop();
                release();
                co_return false;
            }
            driver_.notify();
            for (;;) {
                auto* cur = state();
                if (!cur || cur->failed || cur->retired || bundle_.hooks.dead) co_return false;
                if (fin ? cur->fin_written : cur->output.empty()) co_return true;
                if (!co_await wait(until)) co_return false;
            }
        }

        auto send(std::span<std::uint8_t const> bytes, H3Deadline until = {}) -> capy::task<bool> {
            if (bytes.empty()) co_return true;
            std::span<std::uint8_t const> wire = bytes;
            if (!encoder_.in_passthrough()) {
                encoded_.clear();
                encoder_.encode(bytes, encoded_);
                wire = encoded_;
            }
            while (!wire.empty()) {
                auto chunk = wire.first(std::min<std::size_t>(wire.size(), 1024 * 1024));
                if (!co_await send_raw(chunk, false, until)) co_return false;
                wire = wire.subspan(chunk.size());
            }
            co_return true;
        }

        auto read(std::span<std::uint8_t> output, H3Deadline until = {})
            -> capy::task<std::expected<std::size_t, std::string>> {
            if (output.empty()) co_return std::size_t{0};
            for (;;) {
                if (decoded_offset_ < decoded_.size()) {
                    auto count = std::min(output.size(), decoded_.size() - decoded_offset_);
                    std::copy_n(decoded_.begin() + static_cast<std::ptrdiff_t>(decoded_offset_), count, output.begin());
                    decoded_offset_ += count;
                    if (decoded_offset_ == decoded_.size()) {
                        decoded_.clear();
                        decoded_offset_ = 0;
                        if (decoder_.in_passthrough()) std::vector<std::uint8_t>{}.swap(decoded_);
                    }
                    co_return count;
                }
                auto* s = state();
                if (!s || s->failed || s->retired || bundle_.hooks.dead)
                    co_return std::unexpected("HTTP/3 stream failed");
                auto data = s->input.peek();
                if (!data.empty()) {
                    if (decoder_.in_passthrough()) {
                        auto size = std::min(output.size(), data.size());
                        if (s->closed) bundle_.app.discard_body(size);
                        else if (!bundle_.app.consume_body(id_, size))
                            co_return std::unexpected("HTTP/3 flow control failure");
                        std::copy_n(data.begin(), size, output.begin());
                        s->input.consume(size);
                        driver_.notify();
                        co_return size;
                    }
                    auto size = std::min<std::size_t>(16384, data.size());
                    decoded_.clear();
                    decoded_offset_ = 0;
                    if (!decoder_.feed(data.first(size), decoded_))
                        co_return std::unexpected("NaiveProxy H3 padding decode failed");
                    if (s->closed) bundle_.app.discard_body(size);
                    else if (!bundle_.app.consume_body(id_, size))
                        co_return std::unexpected("HTTP/3 flow control failure");
                    s->input.consume(size);
                    driver_.notify();
                    continue;
                }
                if (s->remote_end) co_return std::size_t{0};
                if (!co_await wait(until))
                    co_return std::unexpected("HTTP/3 read timed out");
            }
        }

        auto send_datagram(std::span<std::uint8_t const> payload) -> bool {
            auto* s = state();
            if (!s || !s->is_datagram || s->failed || s->closed || s->retired || bundle_.hooks.dead)
                return false;
            if (bundle_.hooks.tx_dgrams.size() >= kH3MaxDatagramQueue || payload.size() > masque::max_udp_payload)
                return false;
            if (1 + payload.size() > bundle_.hooks.datagram_budget())
                return true;
            std::vector<std::uint8_t> prefixed;
            prefixed.reserve(1 + payload.size());
            prefixed.push_back(0x00); // RFC 9298 context-id = 0
            prefixed.insert(prefixed.end(), payload.begin(), payload.end());
            bundle_.hooks.tx_dgrams.push_back({id_, std::move(prefixed)});
            driver_.notify();
            return true;
        }

        auto recv_datagram(H3Deadline until = {}) -> capy::task<std::optional<std::vector<std::uint8_t>>> {
            for (;;) {
                auto* s = state();
                if (!s || !s->is_datagram || s->failed || s->retired || bundle_.hooks.dead)
                    co_return std::nullopt;
                if (!s->rx_dgrams.empty()) {
                    auto pkt = std::move(s->rx_dgrams.front());
                    s->rx_dgrams.pop_front();
                    co_return pkt;
                }
                if (s->remote_end || s->closed) co_return std::nullopt;
                if (!co_await wait(until)) co_return std::nullopt;
            }
        }

        auto close_output(H3Deadline until = {}) -> capy::task<bool> {
            co_return co_await send_raw({}, true, until);
        }

        auto cancel() noexcept -> void { release(); }

        auto release() noexcept -> void {
            if (std::exchange(released_, true)) return;
            auto* s = state();
            if (!s || s->retired) return;
            bundle_.app.discard_body(s->input.size());
            s->input.discard();
            std::erase_if(bundle_.hooks.tx_dgrams, [id = id_](auto const& p) { return p.stream == id; });
            if (s->closed) {
                bundle_.hooks.streams.erase(id_);
                if ((id_ & 3) == 0) bundle_.app.extend_client_streams(1);
            } else {
                s->retired = true;
                if (!s->remote_end || !s->fin_written) {
                    bundle_.hooks.fail(*s);
                    if (!bundle_.app.stopping() && bundle_.app.flush_pending())
                        bundle_.app.request_stop();
                }
            }
            driver_.notify();
        }
    };
}
