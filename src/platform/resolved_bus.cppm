export module platform.resolved_bus;
import std;
import platform.dbus_wire;

export namespace platform::resolved {
    using Clock = std::chrono::steady_clock;
    enum class Error { state, native, remote, timeout, canceled, protocol, ownership, conflict, capacity };
    struct Failure {
        Error code;
        std::error_code system{};
        bool submitted = false;
    };

    inline auto fail(Error code, int native = 0, bool submitted = false) noexcept -> std::unexpected<Failure> {
        return std::unexpected(Failure{
            code,
            native ? std::error_code(native < 0 ? -native : native, std::generic_category()) : std::error_code{},
            submitted,
        });
    }

    struct NoHooks {
        static constexpr auto canceled() noexcept -> bool { return false; }
    };

    using Request = dbus::Request;

    struct Message {
        dbus::Header header{};
        std::span<std::uint8_t const> frame{};
        [[nodiscard]] auto valid() const noexcept -> bool { return !frame.empty() && header.serial != 0; }
        [[nodiscard]] auto sender() const noexcept -> std::string_view { return header.sender; }
        [[nodiscard]] auto error_name() const noexcept -> std::string_view { return header.error_name; }
        [[nodiscard]] auto signature() const noexcept -> std::string_view { return header.signature; }
        [[nodiscard]] auto reader() const noexcept -> dbus::Reader {
            return {frame, header.body_offset, frame.size(), header.big_endian};
        }
    };

    struct SignalFilter {
        std::array<char, 64> sender{};
        std::array<char, 128> path{};
        std::array<char, 64> interface{};
        std::array<char, 64> member{};
        bool active = false;

        [[nodiscard]] auto matches(dbus::Header const& hdr) const noexcept -> bool {
            if (!active || hdr.type != dbus::kTypeSignal) return false;
            if (sender[0] && hdr.sender != std::string_view(sender.data())) return false;
            if (path[0] && hdr.path != std::string_view(path.data())) return false;
            if (interface[0] && hdr.interface != std::string_view(interface.data())) return false;
            if (member[0] && hdr.member != std::string_view(member.data())) return false;
            return true;
        }
    };

    using SignalCallback = void (*)(Message const&, void*) noexcept;

    namespace socket_detail {
        [[nodiscard]] auto is_eintr(int err) noexcept -> bool;
        [[nodiscard]] auto is_ewouldblock(int err) noexcept -> bool;
        [[nodiscard]] auto err_reset() noexcept -> int;
        auto close_fd(int& fd) noexcept -> void;
        auto open_unix(std::string_view address, int& out_fd, bool& connecting) noexcept -> int;
        auto check_connect_error(int fd) noexcept -> int;
        auto send_some(int fd, std::uint8_t const* data, std::size_t len, std::ptrdiff_t& written) noexcept -> int;
        auto recv_some(int fd, std::uint8_t* data, std::size_t len, std::ptrdiff_t& got) noexcept -> int;
        auto poll_once(int fd, bool want_read, bool want_write, int timeout_ms, bool& ready) noexcept -> int;
        auto build_sasl_auth(std::array<std::uint8_t, 96>& out, std::size_t& out_len) noexcept -> void;
    }

    template<class Hooks = NoHooks> class Bus {
        struct Watch {
            SignalFilter filter{};
            SignalCallback callback = nullptr;
            void* userdata = nullptr;
        };

        int fd_ = -1;
        std::uint32_t next_serial_ = 1;
        std::array<std::uint8_t, dbus::kMaxRequestBytes> tx_{};
        std::size_t tx_head_ = 0, tx_tail_ = 0;
        std::array<std::uint8_t, dbus::kMaxMessageBytes> rx_{};
        std::size_t rx_head_ = 0, rx_tail_ = 0;
        std::array<std::uint8_t, dbus::kMaxMessageBytes> reply_{};
        std::array<Watch, 4> watches_{};

        template<bool ObserveCancellation>
        auto wait_io(bool want_read, bool want_write, Clock::time_point deadline) noexcept -> std::expected<bool, Failure> {
            auto checked = budget<ObserveCancellation>(deadline);
            if (!checked) return std::unexpected(checked.error());
            auto const remaining = std::chrono::ceil<std::chrono::milliseconds>(deadline - Clock::now()).count();
            int const ms = static_cast<int>(std::clamp<std::int64_t>(remaining, 1, 10));
            bool ready = false;
            if (int err = socket_detail::poll_once(fd_, want_read, want_write, ms, ready); err != 0) {
                return fail(Error::native, err);
            }
            return ready;
        }

        template<bool ObserveCancellation>
        auto flush_tx(Clock::time_point deadline, bool& any_sent) -> std::expected<void, Failure> {
            while (tx_head_ < tx_tail_) {
                auto checked = budget<ObserveCancellation>(deadline);
                if (!checked) return checked;
                std::ptrdiff_t written = 0;
                int const err = socket_detail::send_some(fd_, tx_.data() + tx_head_, tx_tail_ - tx_head_, written);
                if (err == 0 && written > 0) {
                    tx_head_ += static_cast<std::size_t>(written);
                    any_sent = true;
                    continue;
                }
                if (err != 0 && socket_detail::is_eintr(err)) continue;
                if (err != 0 && !socket_detail::is_ewouldblock(err)) return fail(Error::native, err, any_sent);
                auto waited = wait_io<ObserveCancellation>(false, true, deadline);
                if (!waited) return fail(waited.error().code, waited.error().system.value(), any_sent);
            }
            tx_head_ = tx_tail_ = 0;
            return {};
        }

        template<bool ObserveCancellation>
        auto send_raw(std::uint8_t const* data, std::size_t len, Clock::time_point deadline) -> std::expected<void, Failure> {
            if (len > tx_.size()) return fail(Error::capacity);
            std::memcpy(tx_.data(), data, len);
            tx_head_ = 0;
            tx_tail_ = len;
            bool sent = false;
            return flush_tx<ObserveCancellation>(deadline, sent);
        }

        auto compact_rx() noexcept -> void {
            if (!rx_head_) return;
            if (rx_head_ < rx_tail_) std::memmove(rx_.data(), rx_.data() + rx_head_, rx_tail_ - rx_head_);
            rx_tail_ -= rx_head_;
            rx_head_ = 0;
        }

        auto recv_available() noexcept -> std::expected<bool, Failure> {
            compact_rx();
            if (rx_tail_ >= rx_.size()) return false;
            for (;;) {
                std::ptrdiff_t got = 0;
                int const err = socket_detail::recv_some(fd_, rx_.data() + rx_tail_, rx_.size() - rx_tail_, got);
                if (err == 0) {
                    if (got == 0) return fail(Error::native, socket_detail::err_reset());
                    rx_tail_ += static_cast<std::size_t>(got);
                    return true;
                }
                if (socket_detail::is_eintr(err)) continue;
                if (socket_detail::is_ewouldblock(err)) return false;
                return fail(Error::native, err);
            }
        }

        auto dispatch_signal(dbus::Header const& hdr, std::span<std::uint8_t const> frame) noexcept -> void {
            Message msg{hdr, frame};
            for (auto const& w : watches_) if (w.filter.matches(hdr) && w.callback) w.callback(msg, w.userdata);
        }

        auto copy_reply(std::span<std::uint8_t const> frame) noexcept -> Message {
            std::memcpy(reply_.data(), frame.data(), frame.size());
            std::span<std::uint8_t const> owned(reply_.data(), frame.size());
            dbus::Header hdr{};
            (void)dbus::parse_header(owned, hdr);
            return Message{hdr, owned};
        }

        auto drain_frames(std::uint32_t wait_serial, std::optional<Message>& matched,
            unsigned max_frames, unsigned& count) -> std::expected<void, Failure> {
            while (count < max_frames) {
                std::span<std::uint8_t const> pending(rx_.data() + rx_head_, rx_tail_ - rx_head_);
                std::size_t frame_len = 0;
                auto const status = dbus::peek_frame_size(pending, frame_len);
                if (status == dbus::FrameStatus::incomplete) break;
                if (status == dbus::FrameStatus::too_large) return fail(Error::capacity);
                if (status == dbus::FrameStatus::invalid) return fail(Error::protocol);
                auto const frame = pending.first(frame_len);
                dbus::Header hdr{};
                if (!dbus::parse_header(frame, hdr)) return fail(Error::protocol);
                rx_head_ += frame_len;
                ++count;
                if (hdr.type == dbus::kTypeSignal) {
                    dispatch_signal(hdr, frame);
                } else if (wait_serial && hdr.reply_serial == wait_serial &&
                           (hdr.type == dbus::kTypeMethodReturn || hdr.type == dbus::kTypeError)) {
                    if (hdr.type == dbus::kTypeError) return fail(Error::remote, dbus::map_error_name(hdr.error_name));
                    matched.emplace(copy_reply(frame));
                    if (rx_head_ == rx_tail_) rx_head_ = rx_tail_ = 0;
                    return {};
                }
            }
            if (rx_head_ == rx_tail_) rx_head_ = rx_tail_ = 0;
            return {};
        }

      public:
        Bus() = default;
        ~Bus() { close(); }
        Bus(Bus const&) = delete;
        auto operator=(Bus const&) -> Bus& = delete;
        Bus(Bus&&) = delete;
        auto operator=(Bus&&) -> Bus& = delete;

        template<bool ObserveCancellation = true>
        static auto budget(Clock::time_point deadline) noexcept -> std::expected<void, Failure> {
            static_assert(noexcept(Hooks::canceled()));
            if constexpr (ObserveCancellation) if (Hooks::canceled()) return fail(Error::canceled);
            if (Clock::now() >= deadline) return fail(Error::timeout);
            return {};
        }

        auto close() noexcept -> void {
            socket_detail::close_fd(fd_);
            tx_head_ = tx_tail_ = rx_head_ = rx_tail_ = 0;
            next_serial_ = 1;
            clear_watches();
        }
        auto clear_watches() noexcept -> void { for (auto& w : watches_) w = {}; }

        [[nodiscard]] auto add_watch(SignalFilter filter, SignalCallback cb, void* ud) noexcept -> bool {
            filter.active = true;
            for (auto& w : watches_) if (!w.filter.active) { w = {filter, cb, ud}; return true; }
            return false;
        }
        [[nodiscard]] auto native_handle() const noexcept -> int { return fd_; }

        [[nodiscard]] auto open(Clock::time_point deadline,
            char const* address = "unix:path=/run/dbus/system_bus_socket") -> std::expected<void, Failure> {
            if (fd_ >= 0) return fail(Error::state);
            auto checked = budget(deadline);
            if (!checked) return checked;
            bool connecting = false;
            if (int err = socket_detail::open_unix(address ? address : "", fd_, connecting); err != 0) {
                return fail(Error::native, err);
            }
            auto abort = [&](Failure p) -> std::expected<void, Failure> { close(); return std::unexpected(p); };
            while (connecting) {
                auto waited = wait_io<true>(false, true, deadline);
                if (!waited) return abort(waited.error());
                if (!*waited) continue;
                int const err = socket_detail::check_connect_error(fd_);
                if (err == 0) break;
                if (!socket_detail::is_eintr(err) && !socket_detail::is_ewouldblock(err)) {
                    return abort(Failure{Error::native, {err, std::generic_category()}});
                }
            }
            std::array<std::uint8_t, 96> auth{};
            std::size_t auth_len = 0;
            socket_detail::build_sasl_auth(auth, auth_len);
            if (auto sent = send_raw<true>(auth.data(), auth_len, deadline); !sent) return abort(sent.error());
            for (;;) {
                std::string_view line(reinterpret_cast<char const*>(rx_.data() + rx_head_), rx_tail_ - rx_head_);
                if (auto crlf = line.find("\r\n"); crlf != line.npos) {
                    rx_head_ += crlf + 2;
                    if (!line.substr(0, crlf).starts_with("OK ")) return abort(Failure{Error::protocol});
                    break;
                }
                if (line.size() >= 512) return abort(Failure{Error::protocol});
                auto got = recv_available();
                if (!got) return abort(got.error());
                if (!*got) { auto w = wait_io<true>(true, false, deadline); if (!w) return abort(w.error()); }
            }
            constexpr std::uint8_t kBegin[] = {'B', 'E', 'G', 'I', 'N', '\r', '\n'};
            if (auto sent = send_raw<true>(kBegin, sizeof(kBegin), deadline); !sent) return abort(sent.error());
            auto hello = message("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello");
            if (!hello) return abort(hello.error());
            auto reply = call(*hello, deadline);
            if (!reply) return abort(reply.error());
            std::string_view unique;
            auto r = reply->reader();
            if (reply->signature() != "s" || !r.read_string(unique) || !r.at_end() || !unique.starts_with(':')) {
                return abort(Failure{Error::protocol});
            }
            return {};
        }

        [[nodiscard]] auto message(char const* dest, char const* path, char const* iface, char const* mem) noexcept
            -> std::expected<Request, Failure> {
            if (fd_ < 0) return fail(Error::state);
            Request req;
            if (!req.init(dest ? dest : "", path ? path : "", iface ? iface : "", mem ? mem : "")) {
                return fail(Error::protocol);
            }
            return req;
        }

        template<bool ObserveCancellation = true, class Done>
        [[nodiscard]] auto until(Done done, Clock::time_point deadline) -> std::expected<void, Failure> {
            if (fd_ < 0) return fail(Error::state);
            while (!done()) {
                auto checked = budget<ObserveCancellation>(deadline);
                if (!checked) return checked;
                unsigned count = 0;
                std::optional<Message> unused;
                if (auto d = drain_frames(0, unused, 64, count); !d) return d;
                if (done()) return {};
                auto got = recv_available();
                if (!got) return std::unexpected(got.error());
                if (*got || count == 64) continue;
                auto w = wait_io<ObserveCancellation>(true, false, deadline);
                if (done()) return {};
                if (!w) return std::unexpected(w.error());
            }
            return {};
        }

        template<bool ObserveCancellation = true>
        [[nodiscard]] auto call(Request const& req, Clock::time_point deadline) -> std::expected<Message, Failure> {
            auto checked = budget<ObserveCancellation>(deadline);
            if (!checked) return std::unexpected(checked.error());
            if (fd_ < 0 || !req.valid) return fail(Error::state);
            if (tx_head_ < tx_tail_) {
                bool old_sent = false;
                if (auto prev = flush_tx<ObserveCancellation>(deadline, old_sent); !prev) return std::unexpected(prev.error());
            }
            if (next_serial_ == 0) next_serial_ = 1;
            std::uint32_t const serial = next_serial_++;
            std::size_t const wire_len = req.encode(serial, tx_);
            if (!wire_len) return fail(Error::capacity);
            tx_head_ = 0;
            tx_tail_ = wire_len;
            bool submitted = false;
            if (auto f = flush_tx<ObserveCancellation>(deadline, submitted); !f) {
                return fail(f.error().code, f.error().system.value(), submitted);
            }
            for (;;) {
                unsigned count = 0;
                std::optional<Message> matched;
                if (auto d = drain_frames(serial, matched, 64, count); !d) {
                    return fail(d.error().code, d.error().system.value(), true);
                }
                if (matched) return *matched;
                auto got = recv_available();
                if (!got) return fail(got.error().code, got.error().system.value(), true);
                if (*got || count == 64) continue;
                if (auto w = wait_io<ObserveCancellation>(true, false, deadline); !w) {
                    return fail(w.error().code, w.error().system.value(), true);
                }
            }
        }

        [[nodiscard]] auto process(Clock::time_point deadline) -> std::expected<bool, Failure> {
            if (auto c = budget(deadline); !c) return std::unexpected(c.error());
            if (fd_ < 0) return fail(Error::state);
            if (auto got = recv_available(); !got) return std::unexpected(got.error());
            unsigned count = 0;
            std::optional<Message> unused;
            if (auto d = drain_frames(0, unused, 64, count); !d) return std::unexpected(d.error());
            return count == 64;
        }
    };
}
