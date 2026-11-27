export module cli.control;
import std;
import functional;
import state.lock;

export namespace cli {
    enum class ControlRole { administrator, reader };
    using ControlHandler=functional::function_ref<std::expected<std::string,std::string>(
        ControlRole,std::span<std::string_view const>)>;

    struct ControlDiagnostics {
        std::uint64_t authorized=0;
        std::uint64_t unauthorized=0;
        std::uint64_t expired=0;
        std::uint64_t reply_failed=0;
    };

    class LocalControl {
        struct Impl;
        std::unique_ptr<Impl> impl_;
    public:
        LocalControl() noexcept;
        ~LocalControl();
        LocalControl(LocalControl const&)=delete;
        auto operator=(LocalControl const&) -> LocalControl& = delete;
        auto start(std::string_view path,std::optional<std::uint32_t> reader={}) -> std::expected<void,std::string>;
        auto poll(ControlHandler handler) -> void;
        auto stop() noexcept -> void;
        [[nodiscard]] auto active() const noexcept -> bool;
        [[nodiscard]] auto listen_native_fd() const noexcept -> int;
        [[nodiscard]] auto next_poll_delay() const noexcept -> std::optional<std::chrono::milliseconds>;
        [[nodiscard]] auto instance() const noexcept -> std::string_view;
        [[nodiscard]] auto diagnostics() const noexcept -> ControlDiagnostics;
    };

    struct SelectorChoice {
        std::string group;
        std::string member;
    };

    struct PersistedRouteMode {
        std::string mode;
        std::string global_outbound;
        auto operator==(PersistedRouteMode const&) const -> bool = default;
    };

    class SelectorState {
        std::optional<::state::InstanceLock> instance_;
        std::uint64_t revision_=0;
        std::uint64_t route_mode_revision_=0;
        std::vector<SelectorChoice> choices_;
        std::optional<PersistedRouteMode> route_mode_;
    public:
        SelectorState() noexcept=default;
        ~SelectorState();
        SelectorState(SelectorState const&)=delete;
        auto operator=(SelectorState const&) -> SelectorState& =delete;
        auto open(this SelectorState& self,std::string const& path) -> std::expected<void,std::string>;
        auto open_route_mode_only(this SelectorState& self,std::string const& path) -> std::expected<void,std::string>;
        // False means rename succeeded but directory sync did not confirm durability.
        auto select(this SelectorState& self,std::string_view group,std::string_view member)
            -> std::expected<bool,std::string>;
        auto save_route_mode(this SelectorState& self,std::string_view mode,std::string_view global_outbound)
            -> std::expected<bool,std::string>;
        [[nodiscard]] auto choices(this SelectorState const& self) noexcept -> std::span<SelectorChoice const> {
            return self.choices_;
        }
        [[nodiscard]] auto route_mode(this SelectorState const& self) noexcept -> std::optional<PersistedRouteMode> const& {
            return self.route_mode_;
        }
    };

    [[nodiscard]] inline auto generate_control_instance_id(std::uint64_t process_salt = 0) -> std::string {
        static std::atomic<std::uint64_t> seq{0};
        std::uint64_t a = 0, b = 0;
        try {
            std::random_device rd;
            a = (static_cast<std::uint64_t>(rd()) << 32) | static_cast<std::uint64_t>(rd());
            b = (static_cast<std::uint64_t>(rd()) << 32) | static_cast<std::uint64_t>(rd());
        } catch (...) {}
        auto now_steady = static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
        auto now_sys = static_cast<std::uint64_t>(std::chrono::system_clock::now().time_since_epoch().count());
        auto n = seq.fetch_add(1, std::memory_order_relaxed) + 1;
        a ^= now_steady ^ (process_salt * 0x9e3779b97f4a7c15ull) ^ (n * 0xbf58476d1ce4e5b9ull);
        b ^= now_sys ^ (now_steady << 17) ^ (n * 0x94d049bb133111ebull);
        return std::format("{:016x}{:016x}", a, b);
    }

    inline auto advance_control_logs_cursor(std::string_view current_since, std::string_view wire) -> std::string {
        auto to_u64 = [](std::string_view s) noexcept -> std::optional<std::uint64_t> {
            if (s.empty()) return std::nullopt;
            std::uint64_t v = 0;
            auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
            return (ec == std::errc{} && end == s.data() + s.size()) ? std::optional(v) : std::nullopt;
        };
        auto nl = wire.find('\n');
        auto head = nl == std::string_view::npos ? wire : wire.substr(0, nl);
        auto body = nl == std::string_view::npos ? std::string_view{} : wire.substr(nl + 1);
        std::optional<std::uint64_t> last_seq;
        while (!body.empty()) {
            auto end = body.find('\n');
            auto line = end == std::string_view::npos ? body : body.substr(0, end);
            body = end == std::string_view::npos ? std::string_view{} : body.substr(end + 1);
            if (line.empty()) continue;
            std::size_t pos = line.starts_with("seq=") ? 0 : line.find(" seq=");
            if (pos == std::string_view::npos) continue;
            auto rest = line.substr(pos + (line[pos] == ' ' ? 5 : 4));
            auto sp = rest.find(' ');
            if (auto seq = to_u64(sp == std::string_view::npos ? rest : rest.substr(0, sp))) last_seq = *seq;
        }
        std::optional<std::uint64_t> candidate = last_seq;
        if (!candidate && head.starts_with("latest=")) {
            auto rest = head.substr(7);
            auto sp = rest.find(' ');
            candidate = to_u64(sp == std::string_view::npos ? rest : rest.substr(0, sp));
        }
        auto cur = to_u64(current_since).value_or(0);
        if (candidate && *candidate > cur) return std::to_string(*candidate);
        return std::string(current_since);
    }

    inline constexpr std::size_t kAsyncPipeMaxRequest = 4096;
    inline constexpr std::size_t kAsyncPipeMaxReply = 65536;
    inline constexpr std::size_t kAsyncPipeMaxArgs = 16;

    enum class AsyncPipeIoStatus : std::uint8_t { pending, completed, more_data, broken, failed };
    struct AsyncPipeIoResult {
        AsyncPipeIoStatus status = AsyncPipeIoStatus::failed;
        std::size_t bytes = 0;
    };
    enum class AsyncPipePhase : std::uint8_t { uninitialized, accepting, reading, writing, draining, cancelling };

    [[nodiscard]] inline auto dispatch_control_pipe_wire(
        std::string_view req, bool oversized, ControlHandler handler) -> std::string {
        auto format = [](std::string_view tag, std::string_view msg) {
            std::string out("NEXUS/1 ");
            out += tag;
            out += '\n';
            out += msg;
            if (!out.ends_with('\n')) out += '\n';
            if (out.size() > kAsyncPipeMaxReply) return std::string("NEXUS/1 ERROR\ncontrol reply too large\n");
            return out;
        };
        if (oversized) return format("ERROR", "request-too-large");
        if (!req.starts_with("NEXUS/1 ") || req.size() <= 8) return format("ERROR", "unsupported control frame");
        std::array<std::string_view, kAsyncPipeMaxArgs> args{};
        std::size_t count = 0;
        auto rest = req.substr(8);
        while (!rest.empty()) {
            auto end = rest.find('\0');
            auto tok = end == std::string_view::npos ? rest : rest.substr(0, end);
            if (count == kAsyncPipeMaxArgs || tok.empty()) return format("ERROR", "empty control argument");
            args[count++] = tok;
            if (end == std::string_view::npos) break;
            rest.remove_prefix(end + 1);
            if (rest.empty()) return format("ERROR", "empty control argument");
        }
        if (count == 0) return format("ERROR", "empty control request");
        try {
            auto res = handler(ControlRole::administrator, std::span(args.data(), count));
            return res ? format("OK", *res) : format("ERROR", res.error());
        } catch (std::bad_alloc const&) {
            return format("ERROR", "resource-exhausted");
        } catch (std::system_error const&) {
            return format("ERROR", "operation-failed");
        }
    }

    // Fully non-blocking overlapped named-pipe state machine (accepting -> reading -> writing -> draining -> closing).
    // Never calls FlushFileBuffers or blocking waits; stalled clients time out via CancelIoEx + DisconnectNamedPipe.
    class AsyncPipeEngine {
    public:
        using Clock = std::chrono::steady_clock;
        struct Slot {
            AsyncPipePhase phase = AsyncPipePhase::uninitialized;
            bool io_pending = false;
            Clock::time_point expiry{};
            std::array<char, kAsyncPipeMaxRequest + 1> req_buf{};
            std::string reply_buf;
            std::size_t reply_offset = 0;
            char drain_byte = 0;
        };
    private:
        std::vector<Slot> slots_;
        ControlDiagnostics diag_{};
        std::chrono::milliseconds timeout_{2000};

        template <class Ops>
        auto arm_accept(std::size_t idx, Ops& ops) -> bool {
            auto& s = slots_[idx];
            s.reply_buf.clear();
            s.reply_offset = 0;
            s.phase = AsyncPipePhase::accepting;
            auto st = ops.start_connect(idx);
            if (st == AsyncPipeIoStatus::completed) { s.io_pending = false; return true; }
            if (st == AsyncPipeIoStatus::pending) { s.io_pending = true; return true; }
            s.phase = AsyncPipePhase::uninitialized;
            s.io_pending = false;
            return false;
        }

        template <class Ops>
        auto reset_and_rearm(std::size_t idx, Ops& ops) -> void {
            ops.disconnect(idx);
            (void)arm_accept(idx, ops);
        }

        template <class Ops>
        auto begin_cancel(std::size_t idx, Ops& ops) -> void {
            auto& s = slots_[idx];
            s.phase = AsyncPipePhase::cancelling;
            ops.cancel_io(idx);
            auto r = ops.poll_io(idx);
            if (r.status != AsyncPipeIoStatus::pending) {
                s.io_pending = false;
                reset_and_rearm(idx, ops);
            }
        }

        template <class Ops>
        auto handle_read_result(std::size_t idx, AsyncPipeIoResult r, Ops& ops, ControlHandler handler) -> bool {
            auto& s = slots_[idx];
            if (r.status == AsyncPipeIoStatus::pending) { s.io_pending = true; return false; }
            s.io_pending = false;
            if (r.status == AsyncPipeIoStatus::broken || r.status == AsyncPipeIoStatus::failed ||
                (r.status == AsyncPipeIoStatus::completed && r.bytes == 0)) {
                reset_and_rearm(idx, ops);
                return false;
            }
            bool const oversized = (r.status == AsyncPipeIoStatus::more_data || r.bytes > kAsyncPipeMaxRequest);
            ++diag_.authorized;
            std::string_view req = oversized ? std::string_view{} : std::string_view(s.req_buf.data(), r.bytes);
            s.reply_buf = dispatch_control_pipe_wire(req, oversized, handler);
            s.reply_offset = 0;
            s.phase = AsyncPipePhase::writing;
            return true;
        }

        template <class Ops>
        auto poll_slot(std::size_t idx, Ops& ops, Clock::time_point now, ControlHandler handler) -> void {
            auto& s = slots_[idx];
            for (int step = 0; step < 8; ++step) {
                switch (s.phase) {
                case AsyncPipePhase::uninitialized:
                    return;
                case AsyncPipePhase::accepting: {
                    if (s.io_pending) {
                        auto r = ops.poll_io(idx);
                        if (r.status == AsyncPipeIoStatus::pending) return;
                        s.io_pending = false;
                        if (r.status != AsyncPipeIoStatus::completed) { reset_and_rearm(idx, ops); return; }
                    }
                    s.expiry = now + timeout_;
                    s.phase = AsyncPipePhase::reading;
                    auto r = ops.start_read(idx, s.req_buf);
                    if (!handle_read_result(idx, r, ops, handler)) return;
                    break;
                }
                case AsyncPipePhase::reading: {
                    if (s.io_pending) {
                        auto r = ops.poll_io(idx);
                        if (r.status == AsyncPipeIoStatus::pending) {
                            if (now >= s.expiry) { ++diag_.expired; begin_cancel(idx, ops); }
                            return;
                        }
                        if (!handle_read_result(idx, r, ops, handler)) return;
                    } else {
                        auto r = ops.start_read(idx, s.req_buf);
                        if (!handle_read_result(idx, r, ops, handler)) return;
                    }
                    break;
                }
                case AsyncPipePhase::writing: {
                    if (s.io_pending) {
                        auto r = ops.poll_io(idx);
                        if (r.status == AsyncPipeIoStatus::pending) {
                            if (now >= s.expiry) { ++diag_.expired; ++diag_.reply_failed; begin_cancel(idx, ops); }
                            return;
                        }
                        s.io_pending = false;
                        if (r.status != AsyncPipeIoStatus::completed || r.bytes == 0) {
                            ++diag_.reply_failed;
                            reset_and_rearm(idx, ops);
                            return;
                        }
                        s.reply_offset += std::min(r.bytes, s.reply_buf.size() - s.reply_offset);
                    }
                    while (s.reply_offset < s.reply_buf.size()) {
                        auto rem = std::span<char const>(
                            s.reply_buf.data() + s.reply_offset, s.reply_buf.size() - s.reply_offset);
                        auto r = ops.start_write(idx, rem);
                        if (r.status == AsyncPipeIoStatus::pending) { s.io_pending = true; return; }
                        if (r.status != AsyncPipeIoStatus::completed || r.bytes == 0) {
                            ++diag_.reply_failed;
                            reset_and_rearm(idx, ops);
                            return;
                        }
                        s.reply_offset += std::min(r.bytes, rem.size());
                    }
                    s.reply_buf.clear();
                    s.reply_offset = 0;
                    s.phase = AsyncPipePhase::draining;
                    auto dr = ops.start_drain(idx, s.drain_byte);
                    if (dr.status == AsyncPipeIoStatus::pending) { s.io_pending = true; return; }
                    reset_and_rearm(idx, ops);
                    break;
                }
                case AsyncPipePhase::draining: {
                    if (s.io_pending) {
                        auto r = ops.poll_io(idx);
                        if (r.status == AsyncPipeIoStatus::pending) {
                            if (now >= s.expiry) { ++diag_.expired; begin_cancel(idx, ops); }
                            return;
                        }
                        s.io_pending = false;
                    }
                    reset_and_rearm(idx, ops);
                    break;
                }
                case AsyncPipePhase::cancelling: {
                    if (s.io_pending) {
                        auto r = ops.poll_io(idx);
                        if (r.status == AsyncPipeIoStatus::pending) return;
                        s.io_pending = false;
                    }
                    reset_and_rearm(idx, ops);
                    break;
                }
                }
            }
        }
    public:
        explicit AsyncPipeEngine(std::size_t slot_count = 4, std::chrono::milliseconds timeout = std::chrono::milliseconds(2000))
            : slots_(slot_count), timeout_(timeout) {}

        template <class Ops>
        [[nodiscard]] auto init(Ops& ops) -> bool {
            for (std::size_t i = 0; i < slots_.size(); ++i)
                if (!arm_accept(i, ops)) return false;
            return !slots_.empty();
        }

        template <class Ops>
        auto poll(Ops& ops, Clock::time_point now, ControlHandler handler) -> void {
            for (std::size_t i = 0; i < slots_.size(); ++i) poll_slot(i, ops, now, handler);
        }

        template <class Ops>
        [[nodiscard]] auto next_poll_delay(Ops const& ops) const noexcept -> std::optional<std::chrono::milliseconds> {
            bool any_active = false;
            for (std::size_t i = 0; i < slots_.size(); ++i) {
                auto const& s = slots_[i];
                if (s.phase == AsyncPipePhase::uninitialized) continue;
                if ((s.phase == AsyncPipePhase::accepting && !s.io_pending) || (s.io_pending && ops.has_ready_io(i)))
                    return std::chrono::milliseconds(0);
                if (s.phase != AsyncPipePhase::accepting) any_active = true;
            }
            return any_active ? std::optional(std::chrono::milliseconds(5)) : std::nullopt;
        }

        [[nodiscard]] auto slot_count() const noexcept -> std::size_t { return slots_.size(); }
        [[nodiscard]] auto slot_phase(std::size_t idx) const noexcept -> AsyncPipePhase {
            return idx < slots_.size() ? slots_[idx].phase : AsyncPipePhase::uninitialized;
        }
        [[nodiscard]] auto slot_pending(std::size_t idx) const noexcept -> bool {
            return idx < slots_.size() && slots_[idx].io_pending;
        }
        [[nodiscard]] auto diagnostics() const noexcept -> ControlDiagnostics { return diag_; }
    };

    auto run_control(int argc,char** argv) -> int;
}
