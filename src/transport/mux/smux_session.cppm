// Coroutine smux v1 & v2 session multiplexer and RAII virtual Stream handle.
export module mux.smux_session;
import std;
import capy;
import corosio;
import mux.smux_wire;
import mux.smux_streams;

export namespace mux::smux {
    template<class Lower>
    class Session {
        struct PendingCtrl {
            Command cmd = Command::fin;
            std::uint32_t sid = 0;
            UpdPayload upd{};
        };

        Lower& lower_;
        StreamTable streams_;
        capy::async_mutex write_mutex_;
        std::vector<std::uint8_t> write_buf_;
        capy::async_event changed_, space_, opened_, window_changed_, ctrl_ready_;
        std::deque<std::uint32_t> accepted_;
        std::deque<PendingCtrl> pending_ctrl_;
        bool client_;
        bool seen_version_{false};
        bool closed_{false}, running_{false};

        struct RunGuard {
            Session& owner;
            ~RunGuard() { owner.running_ = false; owner.cancel(); }
        };
        struct PartGuard {
            Session& owner;
            ~PartGuard() { owner.cancel(); }
        };

        auto send_locked(Command cmd, std::uint32_t sid, std::span<std::uint8_t const> payload = {})
            -> capy::task<bool> {
            FrameHeader hdr{streams_.version(), cmd, static_cast<std::uint16_t>(payload.size()), sid};
            auto raw_hdr = encode_header(hdr);
            if (payload.empty()) co_return co_await lower_.send(raw_hdr);
            write_buf_.clear();
            auto const total = header_size + payload.size();
            if (write_buf_.capacity() < total) write_buf_.reserve(total);
            write_buf_.insert(write_buf_.end(), raw_hdr.begin(), raw_hdr.end());
            write_buf_.insert(write_buf_.end(), payload.begin(), payload.end());
            co_return co_await lower_.send(write_buf_);
        }

        auto write_frame(Command cmd, std::uint32_t sid, std::span<std::uint8_t const> payload = {})
            -> capy::task<bool> {
            if (closed_) co_return false;
            auto [err, guard] = co_await write_mutex_.scoped_lock();
            if (err || closed_) co_return false;
            if (cmd == Command::psh && !streams_.can_write(sid)) co_return false;
            co_return co_await send_locked(cmd, sid, payload);
        }

        auto enqueue_ctrl(PendingCtrl ctrl) noexcept -> void {
            if (closed_) return;
            try {
                pending_ctrl_.push_back(ctrl);
                ctrl_ready_.set();
            } catch (...) { cancel(); }
        }

        // Returns true if handled synchronously, false on protocol error, nullopt if psh hit backpressure.
        auto try_dispatch_sync(FrameHeader const& hdr, std::span<std::uint8_t const> payload) -> std::optional<bool> {
            if (!client_ && !seen_version_) {
                if (!streams_.set_version(hdr.version)) return false;
                seen_version_ = true;
            } else if (hdr.version != streams_.version()) {
                return false;
            }
            switch (hdr.cmd) {
            case Command::syn: {
                if (client_) return false;
                if (!streams_.accept(hdr.stream_id)) return false;
                accepted_.push_back(hdr.stream_id);
                opened_.set();
                return !closed_;
            }
            case Command::psh: {
                if (payload.empty()) return !closed_;
                auto p = streams_.push(hdr.stream_id, payload);
                if (p == PushResult::backpressure) return std::nullopt;
                if (p == PushResult::queued) changed_.set();
                return !closed_;
            }
            case Command::fin:
                (void)streams_.finish_remote(hdr.stream_id);
                changed_.set();
                window_changed_.set();
                return !closed_;
            case Command::upd: {
                if (payload.size() != upd_payload_size) return false;
                auto upd = decode_upd(std::span<std::uint8_t const, upd_payload_size>(payload.data(), upd_payload_size));
                if (streams_.exists(hdr.stream_id) && !streams_.on_upd(hdr.stream_id, upd)) return false;
                window_changed_.set();
                return !closed_;
            }
            case Command::nop:
                return !closed_;
            }
            return !closed_;
        }

        auto read_loop() -> capy::task<capy::results<>> {
            PartGuard guard{*this};
            constexpr std::size_t kRxBufSize = 32768;
            auto rx_buf = std::make_unique_for_overwrite<std::uint8_t[]>(kRxBufSize);
            std::unique_ptr<std::uint8_t[]> large_payload;
            std::size_t rx_off = 0, rx_len = 0;
            auto compact = [&]() noexcept {
                if (rx_off > 0) {
                    auto const rem = rx_len - rx_off;
                    if (rem > 0) std::memmove(rx_buf.get(), rx_buf.get() + rx_off, rem);
                    rx_off = 0;
                    rx_len = rem;
                }
            };
            while (!closed_) {
                if (rx_len - rx_off < header_size) {
                    compact();
                    bool ok = true;
                    while (rx_len < header_size && !closed_) {
                        auto r = co_await lower_.read(std::span<std::uint8_t>(rx_buf.get() + rx_len, kRxBufSize - rx_len));
                        if (!r || *r == 0 || *r > kRxBufSize - rx_len) { ok = false; break; }
                        rx_len += *r;
                    }
                    if (!ok || closed_) break;
                }
                auto hdr = decode_header(std::span<std::uint8_t const, header_size>(rx_buf.get() + rx_off, header_size));
                if (!hdr) co_return capy::results<>{std::make_error_code(std::errc::protocol_error)};
                rx_off += header_size;
                std::span<std::uint8_t const> payload;
                std::size_t const plen = hdr->length;
                if (plen > 0) {
                    if (plen <= kRxBufSize) {
                        if (rx_len - rx_off < plen) {
                            compact();
                            bool ok = true;
                            while (rx_len < plen && !closed_) {
                                auto r = co_await lower_.read(std::span<std::uint8_t>(rx_buf.get() + rx_len, kRxBufSize - rx_len));
                                if (!r || *r == 0 || *r > kRxBufSize - rx_len) { ok = false; break; }
                                rx_len += *r;
                            }
                            if (!ok || closed_) break;
                        }
                        payload = std::span<std::uint8_t const>(rx_buf.get() + rx_off, plen);
                    } else {
                        if (!large_payload) large_payload = std::make_unique_for_overwrite<std::uint8_t[]>(65536);
                        std::size_t filled = std::min(plen, rx_len - rx_off);
                        if (filled > 0) {
                            std::memcpy(large_payload.get(), rx_buf.get() + rx_off, filled);
                            rx_off += filled;
                            if (rx_off == rx_len) rx_off = rx_len = 0;
                        }
                        bool eof_err = false;
                        while (filled < plen && !closed_) {
                            auto r = co_await lower_.read(std::span<std::uint8_t>(large_payload.get() + filled, plen - filled));
                            if (!r || *r == 0 || *r > plen - filled) { eof_err = true; break; }
                            filled += *r;
                        }
                        if (eof_err || closed_) break;
                        payload = std::span<std::uint8_t const>(large_payload.get(), plen);
                    }
                }
                auto sync = try_dispatch_sync(*hdr, payload);
                if (!sync) {
                    for (;;) {
                        space_.clear();
                        if (closed_) co_return capy::results<>{std::make_error_code(std::errc::protocol_error)};
                        auto [err] = co_await space_.wait();
                        if (err || closed_) co_return capy::results<>{std::make_error_code(std::errc::protocol_error)};
                        auto p = streams_.push(hdr->stream_id, payload);
                        if (p != PushResult::backpressure) {
                            if (p == PushResult::queued) changed_.set();
                            break;
                        }
                    }
                } else if (!*sync) {
                    co_return capy::results<>{std::make_error_code(std::errc::protocol_error)};
                }
                if (plen > 0 && plen <= kRxBufSize) {
                    rx_off += plen;
                    if (rx_off == rx_len) rx_off = rx_len = 0;
                }
            }
            co_return capy::results<>{closed_ ? std::error_code{} : std::make_error_code(std::errc::io_error)};
        }

        auto ctrl_loop() -> capy::task<capy::results<>> {
            PartGuard guard{*this};
            while (!closed_) {
                if (pending_ctrl_.empty()) {
                    ctrl_ready_.clear();
                    if (!pending_ctrl_.empty()) continue;
                    auto [err] = co_await ctrl_ready_.wait();
                    if (err || closed_) break;
                    continue;
                }
                auto ctrl = pending_ctrl_.front();
                pending_ctrl_.pop_front();
                bool ok = false;
                if (ctrl.cmd == Command::upd) {
                    auto wire = encode_upd(ctrl.upd);
                    ok = co_await write_frame(Command::upd, ctrl.sid, wire);
                } else {
                    ok = co_await write_frame(ctrl.cmd, ctrl.sid);
                }
                if (!ok) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
            }
            co_return capy::results<>{};
        }

    public:
        Session(Lower& lower, bool client, std::uint8_t version = version_2, Limits limits = {})
            : lower_(lower), streams_(client, version, limits), client_(client) {}

        ~Session() { cancel(); }
        Session(Session const&) = delete;
        auto operator=(Session const&) -> Session& = delete;

        auto cancel() noexcept -> void {
            if (closed_) return;
            closed_ = true;
            streams_.close();
            lower_.cancel();
            changed_.set();
            space_.set();
            opened_.set();
            window_changed_.set();
            ctrl_ready_.set();
        }

        [[nodiscard]] auto usable() const noexcept -> bool { return !closed_ && !streams_.exhausted(); }
        [[nodiscard]] auto drained() const noexcept -> bool { return !running_; }
        [[nodiscard]] auto active_streams() const noexcept -> std::size_t { return streams_.size(); }
        [[nodiscard]] auto protocol_version() const noexcept -> std::uint8_t { return streams_.version(); }

        auto run() -> capy::task<capy::results<>> {
            if (running_ || closed_)
                co_return capy::results<>{std::make_error_code(std::errc::operation_canceled)};
            running_ = true;
            RunGuard guard{*this};
            auto [err, r, c] = co_await capy::when_all(read_loop(), ctrl_loop());
            (void)r; (void)c;
            co_return capy::results<>{err};
        }

        auto open_stream() -> capy::task<std::expected<std::uint32_t, StreamError>> {
            if (closed_) co_return std::unexpected(StreamError::closed);
            auto [err, guard] = co_await write_mutex_.scoped_lock();
            if (err || closed_) co_return std::unexpected(StreamError::closed);
            auto sid = streams_.open();
            if (!sid) co_return std::unexpected(sid.error());
            if (!co_await send_locked(Command::syn, *sid)) {
                (void)streams_.release(*sid);
                cancel();
                co_return std::unexpected(StreamError::closed);
            }
            co_return *sid;
        }

        auto accept_stream() -> capy::task<std::optional<std::uint32_t>> {
            while (!closed_) {
                if (!accepted_.empty()) {
                    auto sid = accepted_.front();
                    accepted_.pop_front();
                    co_return sid;
                }
                opened_.clear();
                if (!accepted_.empty()) continue;
                auto [err] = co_await opened_.wait();
                if (err || closed_) break;
            }
            co_return std::nullopt;
        }

        auto read_stream(std::uint32_t sid, std::span<std::uint8_t> out,
            std::optional<std::chrono::steady_clock::time_point> deadline = {})
            -> capy::task<std::expected<std::size_t, std::string>> {
            if (out.empty()) co_return std::size_t{0};
            for (;;) {
                auto res = streams_.read(sid, out);
                if (res) {
                    space_.set();
                    if (res->upd) enqueue_ctrl({Command::upd, sid, *res->upd});
                    co_return res->bytes_read;
                }
                if (res.error() != StreamError::backpressure)
                    co_return std::unexpected(std::string("smux stream closed"));
                changed_.clear();
                auto recheck = streams_.read(sid, out);
                if (recheck) {
                    space_.set();
                    if (recheck->upd) enqueue_ctrl({Command::upd, sid, *recheck->upd});
                    co_return recheck->bytes_read;
                }
                if (recheck.error() != StreamError::backpressure)
                    co_return std::unexpected(std::string("smux stream closed"));
                if (deadline && std::chrono::steady_clock::now() >= *deadline)
                    co_return std::unexpected(std::string("smux stream read timeout"));
                std::error_code err;
                if (deadline) {
                    auto [e] = co_await corosio::timeout(changed_.wait(), *deadline);
                    err = e;
                } else {
                    auto [e] = co_await changed_.wait();
                    err = e;
                }
                if (err) co_return std::unexpected(std::string("smux session canceled"));
                if (closed_) continue;
            }
        }

        auto write_stream(std::uint32_t sid, std::span<std::uint8_t const> data) -> capy::task<bool> {
            while (!data.empty()) {
                if (!streams_.can_write(sid)) co_return false;
                auto avail = streams_.tx_window_available(sid);
                if (avail == 0) {
                    window_changed_.clear();
                    if (!streams_.can_write(sid)) co_return false;
                    avail = streams_.tx_window_available(sid);
                    if (avail == 0) {
                        auto [err] = co_await window_changed_.wait();
                        if (err || closed_) co_return false;
                        continue;
                    }
                }
                auto chunk = data.first(std::min(data.size(), avail));
                streams_.record_tx(sid, chunk.size());
                struct TxGuard {
                    StreamTable& table;
                    std::uint32_t id;
                    std::size_t n;
                    bool armed = true;
                    void commit() noexcept { armed = false; }
                    ~TxGuard() { if (armed) table.unrecord_tx(id, n); }
                } tx_guard{streams_, sid, chunk.size()};
                auto [err, lock] = co_await write_mutex_.scoped_lock();
                if (err || closed_ || !streams_.can_write(sid)) co_return false;
                if (!co_await send_locked(Command::psh, sid, chunk)) {
                    cancel();
                    co_return false;
                }
                tx_guard.commit();
                data = data.subspan(chunk.size());
            }
            co_return true;
        }

        auto close_stream_output(std::uint32_t sid) -> capy::task<bool> {
            if (!streams_.finish_local(sid)) co_return false;
            window_changed_.set();
            co_return co_await write_frame(Command::fin, sid);
        }

        auto release_stream(std::uint32_t sid) noexcept -> void {
            if (streams_.finish_local(sid)) enqueue_ctrl({Command::fin, sid, {}});
            (void)streams_.release(sid);
            space_.set();
            changed_.set();
            window_changed_.set();
        }
    };

    template<class SessionT>
    class Stream {
        SessionT* session_ = nullptr;
        std::uint32_t sid_ = 0;
        static auto closed_read() -> capy::task<std::expected<std::size_t, std::string>> {
            co_return std::unexpected(std::string("smux stream closed"));
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
        ~Stream() {
            if (session_ && sid_) session_->release_stream(sid_);
        }
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
