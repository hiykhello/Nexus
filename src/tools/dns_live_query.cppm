// Live async DNS query runner, RDATA JSON formatter, and active DNS/FakeIP flush hooks.
export module cli.dns_live_query;
import std;
import capy;
import corosio;
import config;
import cli.dns_transports;
import cli.outbounds;
import dns.corosio_resolver;
import dns.message;
import dns.message_program;
import dns.local_config;
import dns.policy;
import encoding.hex;
import encoding.json;
import platform.ip_address;
import relay;

export namespace cli {
    namespace live_dns_detail {
        using Clock = std::chrono::steady_clock;

        inline auto rcode_name(std::uint16_t rc) noexcept -> std::string_view {
            switch (rc) {
            case 0: return "NOERROR"; case 1: return "FORMERR"; case 2: return "SERVFAIL";
            case 3: return "NXDOMAIN"; case 4: return "NOTIMP"; case 5: return "REFUSED";
            default: return "OTHER";
            }
        }
        inline auto qtype_name(std::uint16_t t) -> std::string {
            switch (t) {
            case 1: return "A"; case 2: return "NS"; case 5: return "CNAME"; case 6: return "SOA";
            case 12: return "PTR"; case 15: return "MX"; case 16: return "TXT"; case 28: return "AAAA";
            case 33: return "SRV"; case 64: return "SVCB"; case 65: return "HTTPS"; case 257: return "CAA";
            default: return "TYPE" + std::to_string(t);
            }
        }
        inline auto decode_wire_name(std::span<std::uint8_t const> wire, std::size_t& off) -> std::string {
            std::string out;
            std::size_t cursor = off, jumps = 0;
            bool jumped = false;
            while (cursor < wire.size()) {
                auto len = wire[cursor++];
                if ((len & 0xc0u) == 0xc0u) {
                    if (cursor >= wire.size() || ++jumps > 64) return out;
                    std::size_t target = (std::size_t(len & 0x3fu) << 8) | wire[cursor++];
                    if (target >= cursor - 2 || target >= wire.size()) return out;
                    if (!jumped) { off = cursor; jumped = true; }
                    cursor = target; continue;
                }
                if ((len & 0xc0u) != 0) return out;
                if (!len) { if (!jumped) off = cursor; return out.empty() ? std::string(".") : out; }
                if (cursor + len > wire.size() || out.size() + len + 1 > 255) return out;
                if (!out.empty()) out.push_back('.');
                for (std::size_t i = 0; i < len; ++i) {
                    unsigned char ch = wire[cursor++];
                    out.push_back((ch >= 0x20 && ch <= 0x7e) ? static_cast<char>(ch) : '?');
                }
            }
            return out;
        }
        inline auto u16_be(std::span<std::uint8_t const> w, std::size_t o) noexcept -> std::uint16_t {
            return static_cast<std::uint16_t>((std::uint16_t(w[o]) << 8) | w[o + 1]);
        }
        inline auto u32_be(std::span<std::uint8_t const> w, std::size_t o) noexcept -> std::uint32_t {
            return (std::uint32_t(u16_be(w, o)) << 16) | u16_be(w, o + 2);
        }
        inline auto format_rdata(std::span<std::uint8_t const> wire, dns::Record const& rr) -> std::string {
            if (rr.data_offset > wire.size() || rr.data_length > wire.size() - rr.data_offset) return {};
            auto rd = wire.subspan(rr.data_offset, rr.data_length);
            if (rr.type == 1 && rd.size() == 4) return platform::format_ipv4(rd.first<4>());
            if (rr.type == 28 && rd.size() == 16) return platform::format_ipv6(rd.first<16>());
            if (rr.type == 5 || rr.type == 2 || rr.type == 12) {
                if (rr.cname && !rr.cname->empty()) return *rr.cname;
                auto off = rr.data_offset; return decode_wire_name(wire, off);
            }
            if (rr.type == 15 && rd.size() >= 3) {
                auto off = rr.data_offset + 2;
                return std::format("{} {}", u16_be(rd, 0), decode_wire_name(wire, off));
            }
            if (rr.type == 16) {
                std::string txt; std::size_t p = 0;
                while (p < rd.size()) {
                    auto l = rd[p++]; if (p + l > rd.size()) break;
                    if (!txt.empty()) txt.push_back(' ');
                    for (std::size_t i = 0; i < l; ++i) {
                        unsigned char ch = rd[p++];
                        txt.push_back((ch >= 0x20 && ch <= 0x7e) ? static_cast<char>(ch) : '?');
                    }
                }
                return txt;
            }
            if (rr.type == 33 && rd.size() >= 7) {
                auto off = rr.data_offset + 6;
                return std::format("{} {} {} {}", u16_be(rd, 0), u16_be(rd, 2), u16_be(rd, 4), decode_wire_name(wire, off));
            }
            if (rr.type == 6 && rd.size() >= 22) {
                auto off = rr.data_offset;
                auto mname = decode_wire_name(wire, off), rname = decode_wire_name(wire, off);
                if (off + 20 <= rr.data_offset + rr.data_length)
                    return std::format("{} {} {} {} {} {} {}", mname, rname, u32_be(wire, off), u32_be(wire, off + 4),
                        u32_be(wire, off + 8), u32_be(wire, off + 12), u32_be(wire, off + 16));
            }
            if ((rr.type == 64 || rr.type == 65) && rd.size() >= 3) {
                auto off = rr.data_offset + 2;
                auto target = decode_wire_name(wire, off);
                auto end = rr.data_offset + rr.data_length;
                if (off < end) return std::format("{} {} {}", u16_be(rd, 0), target, encoding::hex_encode(wire.subspan(off, end - off)));
                return std::format("{} {}", u16_be(rd, 0), target);
            }
            return encoding::hex_encode(rd);
        }
        inline auto format_dns_response_json(std::string_view name, std::uint16_t qtype,
            dns::Response const& resp, std::uint64_t elapsed_ms) -> std::string {
            std::optional<std::uint32_t> min_ttl;
            std::string answers = "[";
            bool first = true;
            for (auto const& rr : resp.records) {
                if (rr.section != dns::Section::answer) continue;
                if (!min_ttl || rr.ttl < *min_ttl) min_ttl = rr.ttl;
                if (!first) answers.push_back(',');
                first = false;
                answers += std::format("{{\"name\":{},\"type\":{},\"ttl\":{},\"data\":{}}}",
                    encoding::json_quote(rr.name), encoding::json_quote(qtype_name(rr.type)),
                    rr.ttl, encoding::json_quote(format_rdata(resp.wire, rr)));
            }
            answers.push_back(']');
            return std::format(
                "{{\"name\":{},\"type\":{},\"rcode\":{},\"rcode_name\":{},\"ttl\":{},\"elapsed_ms\":{},\"answers\":{}}}\n",
                encoding::json_quote(name), encoding::json_quote(qtype_name(qtype)),
                resp.rcode, encoding::json_quote(rcode_name(resp.rcode)),
                min_ttl.value_or(0), elapsed_ms, answers);
        }
        inline auto make_endpoint(std::array<std::uint8_t, 16> const& address, bool ipv6, std::uint16_t port) -> corosio::endpoint {
            if (ipv6) return {corosio::ipv6_address(address), port};
            corosio::ipv4_address::bytes_type b{};
            std::copy_n(address.begin(), 4, b.begin());
            return {corosio::ipv4_address(b), port};
        }
    }

    struct LiveDnsCompletion {
        struct State {
            std::function<void(std::expected<std::string, std::string>)> fn;
            std::atomic<bool> done{false};
            explicit State(std::function<void(std::expected<std::string, std::string>)> f) noexcept : fn(std::move(f)) {}
            ~State() { if (!done.exchange(true, std::memory_order_acq_rel) && fn) try { fn(std::unexpected("dns-canceled")); } catch (...) {} }
        };
        std::shared_ptr<State> state;
        explicit operator bool() const noexcept { return bool(state); }
        auto operator()(std::expected<std::string, std::string> res) const noexcept -> void {
            if (state && !state->done.exchange(true, std::memory_order_acq_rel) && state->fn)
                try { state->fn(std::move(res)); } catch (...) {}
        }
    };

    class LiveDnsHookGate {
        std::mutex mu_; std::condition_variable cv_; bool alive_ = true; std::size_t active_ = 0;
    public:
        struct Guard {
            LiveDnsHookGate* gate = nullptr;
            Guard() = default;
            explicit Guard(LiveDnsHookGate* g) noexcept : gate(g) {}
            Guard(Guard&& o) noexcept : gate(std::exchange(o.gate, nullptr)) {}
            auto operator=(Guard&& o) noexcept -> Guard& { if (this != &o) { release(); gate = std::exchange(o.gate, nullptr); } return *this; }
            Guard(Guard const&) = delete;
            auto operator=(Guard const&) -> Guard& = delete;
            ~Guard() { release(); }
            explicit operator bool() const noexcept { return gate != nullptr; }
            auto release() noexcept -> void {
                if (!gate) return;
                auto* g = std::exchange(gate, nullptr);
                std::lock_guard lk(g->mu_);
                if (--g->active_ == 0 && !g->alive_) g->cv_.notify_all();
            }
        };
        [[nodiscard]] auto try_enter() noexcept -> Guard {
            std::lock_guard lk(mu_);
            if (!alive_) return {};
            ++active_; return Guard(this);
        }
        auto deactivate_and_drain() noexcept -> void {
            std::unique_lock lk(mu_);
            alive_ = false;
            cv_.wait(lk, [this] { return active_ == 0; });
        }
    };

    namespace live_dns_detail {
        inline auto dispatch_runtime_live_query(corosio::io_context& io, dns::MessageRuleSnapshot snap,
            std::size_t fallback, bool forced, std::string name, std::uint16_t qtype, std::uint32_t timeout_ms,
            LiveDnsCompletion finish) -> void {
            auto run_q = [&io, snap = std::move(snap), fallback, forced, name = std::move(name), qtype,
                timeout_ms, finish = std::move(finish)]() mutable -> capy::task<> {
                auto t0 = Clock::now();
                auto dl = t0 + std::chrono::milliseconds(timeout_ms);
                dns::QueryMessage query{0x1234u, 0x0100u, {name, qtype, 1}, {}};
                auto rules = forced ? std::span<policy::DnsRule const>{} :
                    (snap.rules ? std::span<policy::DnsRule const>(*snap.rules) : std::span<policy::DnsRule const>{});
                dns::MessageProgram prog(io, rules, snap.resolver->upstreams, fallback,
                    snap.resolver->cache, snap.resolver->disable_cache, {}, nullptr, snap.view,
                    snap.resolver->reverse_cache, snap.resolver->independent_cache);
                auto wire = co_await prog.run(query, dl, {});
                auto ms = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count());
                if (!wire) {
                    finish(std::unexpected(wire.error() == dns::detail::ResolveError::timeout ? "dns-timeout" : "dns-query-failed"));
                    co_return;
                }
                auto parsed = dns::parse_response(*wire, query.id, query.question);
                if (!parsed) { finish(std::unexpected("dns-malformed-response")); co_return; }
                finish(format_dns_response_json(name, qtype, *parsed, ms));
            };
            capy::run_async(io.get_executor(), [] {}, [](std::exception_ptr) noexcept {})(run_q());
        }
    }

    struct LiveDnsHooks {
        void* owner = nullptr;
        std::shared_ptr<LiveDnsHookGate> gate{};
        std::function<void()> clear_cache;
        std::function<std::optional<std::size_t>()> flush_fakeip;
        std::function<bool(std::uint64_t id, std::string name, std::uint16_t qtype, std::string server,
            std::uint32_t timeout_ms, LiveDnsCompletion finish)> submit_query;
    };

    class LiveDnsQueryHub {
        using Clock = std::chrono::steady_clock;
        struct Entry {
            std::uint64_t id = 0;
            bool done = false;
            std::expected<std::string, std::string> outcome{};
            Clock::time_point created{};
            Clock::time_point completed{};
            Clock::time_point hard_deadline{};
        };
        struct StandaloneJob {
            config::Config cfg;
            std::string name;
            std::uint16_t qtype = 1;
            std::size_t server_idx = 0;
            bool force_server = false;
            std::uint32_t timeout_ms = 5000;
            LiveDnsCompletion finish;
        };

        std::mutex mu_;
        std::condition_variable worker_cv_;
        std::stop_source stop_src_;
        std::thread standalone_worker_;
        bool stopping_ = false;
        std::deque<StandaloneJob> standalone_queue_;
        std::uint64_t next_id_ = 1;
        std::size_t in_flight_ = 0;
        std::deque<Entry> entries_;
        std::vector<LiveDnsHooks> hooks_;

        auto reap_locked(Clock::time_point now) noexcept -> void {
            for (auto& e : entries_) {
                if (!e.done && now >= e.hard_deadline) {
                    e.done = true; e.outcome = std::unexpected("dns-timeout"); e.completed = now;
                    if (in_flight_ > 0) --in_flight_;
                }
            }
            std::erase_if(entries_, [&](Entry const& e) { return e.done && now - e.completed >= std::chrono::seconds(60); });
        }
        auto complete(std::uint64_t id, std::expected<std::string, std::string> outcome) noexcept -> void {
            std::lock_guard lk(mu_);
            for (auto& e : entries_) {
                if (e.id != id) continue;
                if (!e.done) { if (in_flight_ > 0) --in_flight_; e.done = true; e.outcome = std::move(outcome); e.completed = Clock::now(); }
                break;
            }
        }

        static auto run_standalone(config::Config cfg, std::string name, std::uint16_t qtype,
            std::size_t server_idx, bool force_server, std::uint32_t timeout_ms, std::stop_token stop)
            -> std::expected<std::string, std::string> {
            if (stop.stop_requested()) return std::unexpected("dns-canceled");
            if (!cfg.dns || cfg.dns->servers.empty()) return std::unexpected("dns-unavailable");
            auto transports = prepare_dns_transports(cfg);
            if (!transports) return std::unexpected("dns-unavailable");
            std::unique_ptr<relay::Server> routes;
            std::optional<corosio::io_context> local_io;
            if (uses_proxy_dns(cfg.dns)) {
                auto created = relay::Server::create();
                if (!created) return std::unexpected("dns-unavailable");
                if (!configure_outbounds(**created, cfg, *transports)) return std::unexpected("dns-unavailable");
                if (!(*created)->prepare_routing(1) || !(*created)->activate_context()) return std::unexpected("dns-unavailable");
                routes = std::move(*created);
            } else { local_io.emplace(); }
            auto& io = routes ? routes->executor_context() : *local_io;
            dns::MessageLocalSource local{dns::system_local_snapshots()};
            std::vector<dns::MessageUpstream> upstreams;
            upstreams.reserve(cfg.dns->servers.size());
            for (std::size_t i = 0; i < cfg.dns->servers.size(); ++i) {
                auto const& s = cfg.dns->servers[i];
                dns::MessageUpstream u{};
                if (s.kind != config::DnsServerKind::standard) { u.port = 53; u.endpoint = live_dns_detail::make_endpoint({127, 0, 0, 1}, false, 53); }
                else if (!s.upstream) u.local = &local;
                else {
                    u.tcp = s.upstream->tcp; u.host = s.upstream->host; u.port = s.upstream->port; u.resolver = s.upstream->resolver;
                    if (s.upstream->host.empty()) u.endpoint = live_dns_detail::make_endpoint(s.upstream->address, s.upstream->ipv6, s.upstream->port);
                }
                u.protection = (*transports)[i];
                upstreams.push_back(std::move(u));
            }
            std::span<policy::DnsRule const> rules = force_server ? std::span<policy::DnsRule const>{} : std::span<policy::DnsRule const>(cfg.dns->rules);
            auto fallback = force_server ? server_idx : cfg.dns->final;
            dns::QueryMessage query{0x1234u, 0x0100u, {name, qtype, 1}, {}};
            auto t0 = Clock::now();
            auto deadline = t0 + std::chrono::milliseconds(timeout_ms);
            std::expected<dns::Bytes, dns::detail::ResolveError> result = std::unexpected(dns::detail::ResolveError::state);
            auto task = [&]() -> capy::task<> {
                dns::MessageProgram program(io, rules, upstreams, fallback, nullptr, true);
                result = co_await program.run(query, deadline, {});
            };
            capy::run_async(io.get_executor(), stop, [] {}, [](std::exception_ptr) noexcept {})(task());
            (void)io.run();
            if (routes) routes->stop();
            auto elapsed = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count());
            if (!result) return std::unexpected(stop.stop_requested() ? "dns-canceled" :
                (result.error() == dns::detail::ResolveError::timeout ? "dns-timeout" : "dns-query-failed"));
            auto parsed = dns::parse_response(*result, query.id, query.question);
            if (!parsed) return std::unexpected("dns-malformed-response");
            return live_dns_detail::format_dns_response_json(name, qtype, *parsed, elapsed);
        }

        auto standalone_loop() noexcept -> void {
            auto stop = stop_src_.get_token();
            for (;;) {
                StandaloneJob job{};
                {
                    std::unique_lock lk(mu_);
                    worker_cv_.wait(lk, [this] { return stopping_ || !standalone_queue_.empty(); });
                    if (stopping_) break;
                    job = std::move(standalone_queue_.front());
                    standalone_queue_.pop_front();
                }
                try {
                    job.finish(run_standalone(std::move(job.cfg), std::move(job.name), job.qtype,
                        job.server_idx, job.force_server, job.timeout_ms, stop));
                } catch (...) { job.finish(std::unexpected("dns-query-failed")); }
            }
        }

    public:
        static constexpr std::size_t kMaxInFlight = 8;
        static constexpr std::size_t kMaxEntries = 64;

        ~LiveDnsQueryHub() { shutdown(); }
        static auto instance() -> LiveDnsQueryHub& { static LiveDnsQueryHub hub; return hub; }
        auto shutdown() noexcept -> void {
            std::deque<StandaloneJob> dropped;
            { std::lock_guard lk(mu_); stopping_ = true; dropped.swap(standalone_queue_); }
            stop_src_.request_stop();
            worker_cv_.notify_all();
            if (standalone_worker_.joinable()) standalone_worker_.join();
            dropped.clear();
        }
        auto register_hooks(LiveDnsHooks hooks) -> void {
            std::lock_guard lk(mu_);
            std::erase_if(hooks_, [&](auto const& h) { return h.owner == hooks.owner; });
            hooks_.push_back(std::move(hooks));
        }
        auto unregister_hooks(void* owner) noexcept -> void {
            std::lock_guard lk(mu_);
            std::erase_if(hooks_, [&](auto const& h) { return h.owner == owner; });
        }
        auto clear_active_dns_caches() noexcept -> void {
            std::vector<std::pair<std::shared_ptr<LiveDnsHookGate>, std::function<void()>>> fns;
            { std::lock_guard lk(mu_); for (auto const& h : hooks_) if (h.clear_cache) fns.emplace_back(h.gate, h.clear_cache); }
            for (auto& [gate, fn] : fns) {
                LiveDnsHookGate::Guard g;
                if (gate && !(g = gate->try_enter())) continue;
                try { fn(); } catch (...) {}
            }
        }
        auto flush_active_fakeip() noexcept -> std::optional<std::size_t> {
            std::vector<std::pair<std::shared_ptr<LiveDnsHookGate>, std::function<std::optional<std::size_t>()>>> fns;
            { std::lock_guard lk(mu_); for (auto const& h : hooks_) if (h.flush_fakeip) fns.emplace_back(h.gate, h.flush_fakeip); }
            std::optional<std::size_t> total;
            for (auto& [gate, fn] : fns) {
                LiveDnsHookGate::Guard g;
                if (gate && !(g = gate->try_enter())) continue;
                try { if (auto n = fn()) total = total.value_or(0) + *n; } catch (...) {}
            }
            return total;
        }

        auto enqueue(std::optional<config::Config> const& running, std::string name, std::uint16_t qtype,
            std::string server, std::uint32_t timeout_ms = 5000) -> std::expected<std::string, std::string> {
            if (name.ends_with('.')) name.pop_back();
            if (!running || !running->dns || running->dns->servers.empty())
                return std::unexpected("dns-unavailable");
            std::size_t server_idx = running->dns->final;
            bool force_server = false;
            if (!server.empty()) {
                auto it = std::ranges::find(running->dns->servers, server, &config::DnsServer::name);
                if (it == running->dns->servers.end()) return std::unexpected("unknown-server");
                server_idx = static_cast<std::size_t>(it - running->dns->servers.begin());
                force_server = true;
            }
            std::uint64_t id = 0;
            std::shared_ptr<LiveDnsHookGate> submit_gate;
            std::function<bool(std::uint64_t, std::string, std::uint16_t, std::string, std::uint32_t, LiveDnsCompletion)> submit_fn;
            {
                std::lock_guard lk(mu_);
                if (stopping_) return std::unexpected("dns-unavailable");
                auto now = Clock::now();
                reap_locked(now);
                if (in_flight_ >= kMaxInFlight) return std::unexpected("dns-query-busy");
                while (entries_.size() >= kMaxEntries) {
                    auto it = std::ranges::find_if(entries_, &Entry::done);
                    if (it == entries_.end()) return std::unexpected("dns-query-busy");
                    entries_.erase(it);
                }
                id = next_id_++;
                ++in_flight_;
                auto hard = now + std::chrono::milliseconds(timeout_ms) + std::chrono::seconds(5);
                entries_.push_back(Entry{id, false, {}, now, {}, hard});
                if (!hooks_.empty() && hooks_.back().submit_query) {
                    submit_gate = hooks_.back().gate;
                    submit_fn = hooks_.back().submit_query;
                }
            }
            LiveDnsCompletion finish{};
            try {
                finish.state = std::make_shared<LiveDnsCompletion::State>(
                    [this, id](std::expected<std::string, std::string> res) { complete(id, std::move(res)); });
            } catch (...) {
                complete(id, std::unexpected("dns-unavailable"));
                return std::unexpected("dns-unavailable");
            }
            if (submit_fn) {
                LiveDnsHookGate::Guard g;
                bool ok_gate = !submit_gate || bool(g = submit_gate->try_enter());
                if (ok_gate && submit_fn(id, name, qtype, server, timeout_ms, finish))
                    return std::format("id={} state=pending\n", id);
            }
            // Tracked joinable standalone worker fallback when DNS listener runtime is not started.
            bool queued = false;
            try {
                auto cfg_copy = *running;
                std::lock_guard lk(mu_);
                if (!stopping_) {
                    if (!standalone_worker_.joinable()) standalone_worker_ = std::thread([this] { standalone_loop(); });
                    standalone_queue_.push_back(StandaloneJob{std::move(cfg_copy), std::move(name), qtype,
                        server_idx, force_server, timeout_ms, std::move(finish)});
                    worker_cv_.notify_one();
                    queued = true;
                }
            } catch (...) {}
            if (queued) return std::format("id={} state=pending\n", id);
            finish(std::unexpected("dns-unavailable"));
            return std::unexpected("dns-unavailable");
        }

        auto result(std::uint64_t id) -> std::expected<std::string, std::string> {
            std::lock_guard lk(mu_);
            reap_locked(Clock::now());
            for (auto const& e : entries_) {
                if (e.id != id) continue;
                if (!e.done) return std::string("state=pending\n");
                return e.outcome;
            }
            return std::unexpected("unknown-query");
        }

        [[nodiscard]] auto in_flight_count() noexcept -> std::size_t {
            std::lock_guard lk(mu_);
            reap_locked(Clock::now());
            return in_flight_;
        }
    };
}
