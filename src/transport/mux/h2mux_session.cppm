// Coroutine HTTP/2 (h2mux) session multiplexer and RAII virtual Stream handle over nghttp2.
export module mux.h2mux_session;
import std;
import capy;
import corosio;
import http2.session_core;
import nghttp2;
export import mux.h2mux_policy;

export namespace mux::h2mux {
    template<class SessionT> class Stream;

    template<class Lower>
    class Session {
    public:
        using StreamHandle = Stream<Session>;
    private:
        using Core = http2::detail::SessionCore<detail::Policy>;

        Lower& lower_;
        Limits limits_;
        capy::async_event rx_ev_, tx_ev_, accept_ev_, write_ev_;
        Core core_;
        std::uint64_t flushed_seq_ = 0;
        bool client_;
        bool closed_ = false, running_ = false;

        static auto make_core_limits(Limits lim) noexcept -> http2::detail::CoreLimits {
            auto max_s = std::clamp<std::size_t>(lim.max_streams, 1, 1024);
            auto swin = std::clamp<std::size_t>(lim.stream_window, 65535, 16 * 1024 * 1024);
            auto cwin = std::min<std::size_t>(swin * std::min<std::size_t>(max_s, 32), 32 * 1024 * 1024);
            return {cwin, swin, 32, 4096, static_cast<std::uint32_t>(max_s), 4096, 4096, 64, 5000, 16384};
        }

        struct RunGuard {
            Session& owner;
            ~RunGuard() { owner.running_ = false; owner.cancel(); }
        };
        struct PartGuard {
            Session& owner;
            ~PartGuard() { owner.cancel(); }
        };

        auto reclaim() noexcept -> void {
            if (core_.active()) return;
            auto& map = core_.policy().streams;
            for (auto it = map.begin(); it != map.end();) {
                auto& st = it->second;
                if (st && st->released && st->closed) {
                    if (st->uncredited && core_.native())
                        (void)h2::nghttp2_session_consume_connection(core_.native(), st->uncredited);
                    it = map.erase(it);
                } else {
                    ++it;
                }
            }
        }

        auto read_loop() -> capy::task<capy::results<>> {
            PartGuard guard{*this};
            constexpr std::size_t kBuf = 16640;
            auto buf = std::make_unique_for_overwrite<std::uint8_t[]>(kBuf);
            while (!closed_) {
                auto r = co_await lower_.read(std::span<std::uint8_t>(buf.get(), kBuf));
                if (closed_) break;
                if (!r || *r == 0 || *r > kBuf) break;
                std::span<std::uint8_t const> pending(buf.get(), *r);
                while (!pending.empty() && !closed_) {
                    auto consumed = core_.receive(pending);
                    if (!consumed || *consumed == 0 || *consumed > pending.size()) {
                        cancel();
                        co_return capy::results<>{std::make_error_code(std::errc::protocol_error)};
                    }
                    pending = pending.subspan(*consumed);
                }
                reclaim();
                if (core_.write_pending()) write_ev_.set();
            }
            co_return capy::results<>{};
        }

        auto write_loop() -> capy::task<capy::results<>> {
            PartGuard guard{*this};
            constexpr std::size_t kBuf = 16384;
            auto buf = std::make_unique_for_overwrite<std::uint8_t[]>(kBuf);
            while (!closed_) {
                reclaim();
                if (!core_.usable()) break;
                auto const seq = ++core_.policy().send_seq;
                auto out = core_.output(std::span<std::uint8_t>(buf.get(), kBuf));
                if (!out) {
                    cancel();
                    co_return capy::results<>{std::make_error_code(std::errc::protocol_error)};
                }
                if (*out > 0) {
                    if (!co_await lower_.send(std::span<std::uint8_t const>(buf.get(), *out))) {
                        cancel();
                        co_return capy::results<>{std::make_error_code(std::errc::io_error)};
                    }
                    flushed_seq_ = seq;
                    tx_ev_.set();
                    continue;
                }
                write_ev_.clear();
                if (closed_) break;
                if (core_.write_pending()) continue;
                auto [ec] = co_await write_ev_.wait();
                if (ec || closed_) break;
            }
            co_return capy::results<>{};
        }

    public:
        Session(Lower& lower, bool client, Limits limits = {})
            : lower_(lower), limits_(limits),
              core_(make_core_limits(limits), http2::detail::LocalAccounting(limits.library_bytes),
                    client, limits, &rx_ev_, &tx_ev_, &accept_ev_, &write_ev_),
              client_(client) {
            auto started = core_.start(client ? http2::detail::Role::client : http2::detail::Role::server,
                                       make_core_limits(limits));
            if (!started) closed_ = true;
            else write_ev_.set();
        }
        ~Session() { cancel(); }
        Session(Session const&) = delete;
        auto operator=(Session const&) -> Session& = delete;

        auto cancel() noexcept -> void {
            if (closed_) return;
            closed_ = true;
            for (auto& [_, st] : core_.policy().streams) {
                if (st) {
                    st->closed = true;
                    if (!st->remote_end) st->failed = true;
                    st->tx.clear();
                    st->tx_off = st->tx_bytes = 0;
                }
            }
            lower_.cancel();
            rx_ev_.set();
            tx_ev_.set();
            accept_ev_.set();
            write_ev_.set();
        }

        [[nodiscard]] auto usable() const noexcept -> bool {
            return !closed_ && core_.usable() && core_.native() != nullptr && !core_.policy().draining &&
                   (!client_ || h2::nghttp2_session_check_request_allowed(core_.native()) != 0);
        }
        [[nodiscard]] auto drained() const noexcept -> bool { return !running_; }
        [[nodiscard]] auto active_streams() const noexcept -> std::size_t { return core_.policy().active_user_streams(); }

        auto run() -> capy::task<capy::results<>> {
            if (running_ || closed_)
                co_return capy::results<>{std::make_error_code(std::errc::operation_canceled)};
            running_ = true;
            RunGuard guard{*this};
            auto [err, r, w] = co_await capy::when_all(read_loop(), write_loop());
            (void)r; (void)w;
            co_return capy::results<>{err};
        }

        auto open_stream() -> capy::task<std::expected<std::uint32_t, StreamError>> {
            if (!usable() || !client_) co_return std::unexpected(StreamError::closed);
            auto& pol = core_.policy();
            auto open = pol.open_count();
            auto remote_cap = h2::nghttp2_session_get_remote_settings(core_.native(), h2::NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
            if (open >= limits_.max_streams || open >= remote_cap)
                co_return std::unexpected(StreamError::limit);
            auto st = std::make_unique<detail::StreamState>();
            auto* raw = st.get();
            std::array<h2::nghttp2_nv, 2> hdrs{{Core::nv(":method", "CONNECT"), Core::nv(":authority", "localhost")}};
            auto provider = core_.provider(raw);
            auto id = h2::nghttp2_submit_request2(core_.native(), nullptr, hdrs.data(), hdrs.size(), &provider, raw);
            if (id < 0) {
                if (h2::nghttp2_is_fatal(id)) cancel();
                co_return std::unexpected(StreamError::closed);
            }
            raw->id = id;
            pol.streams.emplace(id, std::move(st));
            write_ev_.set();
            co_return static_cast<std::uint32_t>(id);
        }

        auto accept_stream() -> capy::task<std::optional<std::uint32_t>> {
            auto& q = core_.policy().accepted;
            while (!closed_) {
                if (!q.empty()) {
                    auto id = q.front();
                    q.pop_front();
                    co_return static_cast<std::uint32_t>(id);
                }
                accept_ev_.clear();
                if (!q.empty()) continue;
                auto [ec] = co_await accept_ev_.wait();
                if (ec || closed_) break;
            }
            co_return std::nullopt;
        }

        auto read_stream(std::uint32_t sid, std::span<std::uint8_t> out,
                         std::optional<std::chrono::steady_clock::time_point> deadline = {})
            -> capy::task<std::expected<std::size_t, std::string>> {
            if (out.empty()) co_return std::size_t{0};
            auto const id = static_cast<std::int32_t>(sid);
            for (;;) {
                auto* st = core_.policy().find(id);
                if (!st || st->released) co_return std::unexpected(std::string("h2mux stream closed"));
                if (st->rx_off < st->rx.size()) {
                    auto n = std::min(out.size(), st->rx.size() - st->rx_off);
                    std::memcpy(out.data(), st->rx.data() + st->rx_off, n);
                    st->rx_off += n;
                    if (st->rx_off == st->rx.size()) {
                        st->rx.clear();
                        st->rx_off = 0;
                        if (st->rx.capacity() > 65536) std::vector<std::uint8_t>{}.swap(st->rx);
                    }
                    if (st->uncredited > 0 && core_.native() && !closed_) {
                        auto credit = std::min(n, st->uncredited);
                        auto rc = st->closed
                            ? h2::nghttp2_session_consume_connection(core_.native(), credit)
                            : h2::nghttp2_session_consume(core_.native(), id, credit);
                        if (!rc) { st->uncredited -= credit; write_ev_.set(); }
                    }
                    co_return n;
                }
                if (st->failed) co_return std::unexpected(std::string("h2mux stream reset"));
                if (st->remote_end || st->closed) co_return std::size_t{0};
                if (closed_) co_return std::unexpected(std::string("h2mux session closed"));
                if (deadline && std::chrono::steady_clock::now() >= *deadline)
                    co_return std::unexpected(std::string("h2mux stream read timeout"));
                rx_ev_.clear();
                st = core_.policy().find(id);
                if (!st || st->rx_off < st->rx.size() || st->failed || st->remote_end || st->closed || closed_) continue;
                std::error_code ec;
                if (deadline) {
                    auto [e] = co_await corosio::timeout(rx_ev_.wait(), *deadline);
                    ec = e;
                } else {
                    auto [e] = co_await rx_ev_.wait();
                    ec = e;
                }
                if (ec) co_return std::unexpected(std::string("h2mux stream read canceled"));
            }
        }

        auto write_stream(std::uint32_t sid, std::span<std::uint8_t const> data) -> capy::task<bool> {
            auto const id = static_cast<std::int32_t>(sid);
            while (!data.empty()) {
                auto* st = core_.policy().find(id);
                if (closed_ || !core_.usable() || !st || st->released || st->failed || st->closed || st->local_end_req)
                    co_return false;
                if (st->tx_bytes >= limits_.max_tx_queue) {
                    tx_ev_.clear();
                    st = core_.policy().find(id);
                    if (closed_ || !st || st->failed || st->closed || st->local_end_req) co_return false;
                    if (st->tx_bytes >= limits_.max_tx_queue) {
                        auto [ec] = co_await tx_ev_.wait();
                        if (ec || closed_) co_return false;
                        continue;
                    }
                }
                auto avail = limits_.max_tx_queue - st->tx_bytes;
                auto n = std::min<std::size_t>({data.size(), avail, 32768});
                try { st->tx.emplace_back(data.begin(), data.begin() + n); }
                catch (...) { co_return false; }
                st->tx_bytes += n;
                if (st->deferred && core_.native()) {
                    if (h2::nghttp2_session_resume_data(core_.native(), id)) { cancel(); co_return false; }
                    st->deferred = false;
                }
                write_ev_.set();
                data = data.subspan(n);
            }
            co_return true;
        }

        auto close_stream_output(std::uint32_t sid) -> capy::task<bool> {
            auto const id = static_cast<std::int32_t>(sid);
            auto* st = core_.policy().find(id);
            if (closed_ || !core_.usable() || !st || st->released || st->failed || st->closed) co_return false;
            st->local_end_req = true;
            if (st->deferred && core_.native()) {
                if (h2::nghttp2_session_resume_data(core_.native(), id)) { cancel(); co_return false; }
                st->deferred = false;
            }
            write_ev_.set();
            while (!closed_) {
                st = core_.policy().find(id);
                if (!st || st->failed) co_return false;
                if (st->local_end_sent && flushed_seq_ >= st->end_send_seq) co_return true;
                if (st->closed) co_return !st->failed;
                tx_ev_.clear();
                if ((st->local_end_sent && flushed_seq_ >= st->end_send_seq) || st->closed || st->failed || closed_) continue;
                auto [ec] = co_await tx_ev_.wait();
                if (ec) co_return false;
            }
            co_return false;
        }

        auto release_stream(std::uint32_t sid) noexcept -> void {
            auto const id = static_cast<std::int32_t>(sid);
            auto* st = core_.policy().find(id);
            if (!st || st->released) return;
            st->released = true;
            st->tx.clear();
            st->tx_off = st->tx_bytes = 0;
            if (!st->closed && !closed_ && core_.usable() && core_.native()) {
                (void)h2::nghttp2_submit_rst_stream(core_.native(), 0, id, h2::NGHTTP2_CANCEL);
                write_ev_.set();
            }
            reclaim();
            rx_ev_.set();
            tx_ev_.set();
        }
    };

    template<class SessionT>
    class Stream {
        SessionT* session_ = nullptr;
        std::uint32_t sid_ = 0;
        static auto closed_read() -> capy::task<std::expected<std::size_t, std::string>> {
            co_return std::unexpected(std::string("h2mux stream closed"));
        }
        static auto closed_write() -> capy::task<bool> { co_return false; }
    public:
        Stream() noexcept = default;
        Stream(SessionT& session, std::uint32_t sid) noexcept : session_(&session), sid_(sid) {}
        Stream(Stream const&) = delete;
        auto operator=(Stream const&) -> Stream& = delete;
        Stream(Stream&& other) noexcept
            : session_(std::exchange(other.session_, nullptr)), sid_(std::exchange(other.sid_, 0)) {}
        auto operator=(Stream&& other) noexcept -> Stream& {
            if (this != &other) {
                if (session_ && sid_) session_->release_stream(sid_);
                session_ = std::exchange(other.session_, nullptr);
                sid_ = std::exchange(other.sid_, 0);
            }
            return *this;
        }
        ~Stream() { if (session_ && sid_) session_->release_stream(sid_); }
        [[nodiscard]] auto id() const noexcept -> std::uint32_t { return sid_; }
        auto read(std::span<std::uint8_t> out,
                  std::optional<std::chrono::steady_clock::time_point> deadline = {}) {
            return (!session_ || !sid_) ? closed_read() : session_->read_stream(sid_, out, deadline);
        }
        auto send(std::span<std::uint8_t const> bytes) {
            return (!session_ || !sid_) ? closed_write() : session_->write_stream(sid_, bytes);
        }
        auto close_output() {
            return (!session_ || !sid_) ? closed_write() : session_->close_stream_output(sid_);
        }
        auto cancel() noexcept -> void {
            if (session_ && sid_) {
                session_->release_stream(sid_);
                sid_ = 0;
            }
        }
    };
}
