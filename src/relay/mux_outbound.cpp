// Outbound generic sing-mux / smux pool decorator wrapping any stream TunnelFactory.
module;
#include <proxy/proxy_macros.h>
#include <boost/capy/ex/run_async.hpp>

module relay;
import std;
import proxy.v4;
import config;
import capy;
import corosio;
import net.datagram_frame;
import net.stream_relay;
import mux.smux_wire;
import mux.sing_wire;
import mux.smux_streams;
import mux.smux_session;

namespace relay {
    namespace {
        struct MuxLowerAdapter {
            pro::proxy<TunnelFacade> lower;
            auto read(std::span<std::uint8_t> dst) { return lower->read(dst); }
            auto send(std::span<std::uint8_t const> src) { return lower->send(src); }
            auto close_output() { return lower->close_output(); }
            auto cancel() noexcept -> void { if (lower) lower->cancel(); }
        };
        struct PaddedLower {
            MuxLowerAdapter raw; mux::sing::PaddingStream<MuxLowerAdapter> padded{raw}; bool use_padding = false;
            explicit PaddedLower(bool pad) noexcept : use_padding(pad) {}
            auto read(std::span<std::uint8_t> dst) -> capy::task<std::expected<std::size_t, std::string>> { co_return co_await (use_padding ? padded.read(dst) : raw.read(dst)); }
            auto send(std::span<std::uint8_t const> src) -> capy::task<bool> { co_return co_await (use_padding ? padded.send(src) : raw.send(src)); }
            auto close_output() -> capy::task<bool> { co_return co_await raw.close_output(); }
            auto cancel() noexcept -> void { raw.cancel(); }
        };

        using SmuxProto = mux::smux::Session<PaddedLower>;
        using SmuxStream = mux::smux::Stream<SmuxProto>;

        struct MuxCarrier {
            Session state;
            PaddedLower lower;
            SmuxProto proto;
            bool starting = false, running = false, canceled = false;
            Clock::time_point idle_since{};

            struct ReaderGuard {
                std::shared_ptr<MuxCarrier> owner;
                ~ReaderGuard() {
                    if (owner) {
                        owner->running = false;
                        owner->cancel();
                    }
                }
            };

            static auto reader(ReaderGuard guard) -> capy::task<> {
                (void)co_await guard.owner->proto.run();
            }

            MuxCarrier(OutboundContext const& env, config::MultiplexConfig const& cfg, bool direct)
                : state(env.context), lower(cfg.padding),
                  proto(lower, true, cfg.protocol == config::MultiplexProtocol::smux_v1
                        ? mux::smux::version_1 : mux::smux::version_2,
                        mux::smux::Limits{.max_streams = std::max<std::size_t>(cfg.max_streams > 0 ? cfg.max_streams : 64u, 64u)}) {
                state.dns = env.dns;
                state.local_dns = env.local_dns;
                if (env.owner) state.route_snapshot = env.owner->current_route_snapshot();
                state.tunnel_factories = env.factories;
                state.direct_tcp_options = direct ? env.direct_options : nullptr;
                state.direct_connect_timeout_ms = 10000;
            }

            auto cancel() noexcept -> void {
                if (canceled) return;
                canceled = true;
                proto.cancel();
                lower.cancel();
                state.close();
            }

            auto usable() const noexcept -> bool { return !canceled && proto.usable(); }
            auto drained() const noexcept -> bool { return !starting && !running && proto.drained(); }

            auto start_run(std::shared_ptr<MuxCarrier> const& self, corosio::io_context& ctx) -> void {
                running = true;
                try {
                    capy::run_async(ctx.get_executor(), [] {}, [self](std::exception_ptr) noexcept { self->cancel(); })(
                        reader(ReaderGuard{self}));
                } catch (...) {
                    running = false;
                    cancel();
                    throw;
                }
            }
        };

        struct MuxWorker {
            OutboundContext env;
            TunnelFactory const& inner;
            config::MultiplexConfig cfg;
            TunnelFactory const* detour = nullptr;
            bool direct = false;
            capy::async_mutex starting_;
            capy::async_event stop_ev_;
            std::vector<std::shared_ptr<MuxCarrier>> carriers;
            bool stopped = false, reaper_active_ = false;

            MuxWorker(OutboundContext e, TunnelFactory const& in, config::MultiplexConfig c, TunnelFactory const* d, bool dir)
                : env(std::move(e)), inner(in), cfg(c), detour(d), direct(dir) {}
            ~MuxWorker() { stop(); }

            auto reap(Clock::time_point now) noexcept -> void {
                for (auto& c : carriers) {
                    if (!c || c->starting || !c->running || !c->usable()) continue;
                    if (c->proto.active_streams() > 0) c->idle_since = {};
                    else if (c->idle_since == Clock::time_point{}) c->idle_since = now;
                    else if (now - c->idle_since >= std::chrono::seconds(120)) c->cancel();
                }
                std::erase_if(carriers, [](auto const& c) { return !c || (!c->usable() && c->drained()); });
            }
            auto reap_loop() -> capy::task<> {
                struct Done { bool& flag; ~Done() { flag = false; } } done{reaper_active_};
                while (!stopped) {
                    stop_ev_.clear();
                    if (stopped) break;
                    auto [ec] = co_await corosio::timeout(stop_ev_.wait(), Clock::now() + std::chrono::seconds(10));
                    if (stopped || ec != capy::cond::timeout) break;
                    reap(Clock::now());
                }
            }
            auto start_reaper() -> void {
                if (stopped || reaper_active_) return;
                reaper_active_ = true;
                capy::run_async(env.context.get_executor(), [] {}, [this](std::exception_ptr) noexcept {
                    reaper_active_ = false;
                })(reap_loop());
            }
            auto stop() noexcept -> void {
                stopped = true; stop_ev_.set();
                for (auto& c : carriers) c->cancel();
            }
            auto quiesced() const noexcept -> bool {
                return std::ranges::all_of(carriers, [](auto const& c) { return c->drained(); });
            }
            auto drained() const noexcept -> bool { return !reaper_active_ && quiesced(); }

            auto pick_existing(bool below_min) const noexcept -> std::shared_ptr<MuxCarrier> {
                std::shared_ptr<MuxCarrier> best;
                std::size_t best_streams = std::numeric_limits<std::size_t>::max();
                for (auto const& c : carriers) {
                    if (!c || c->starting || !c->running || !c->usable()) continue;
                    auto n = c->proto.active_streams();
                    if (cfg.max_streams > 0 && n >= cfg.max_streams) continue;
                    if (below_min && n >= cfg.min_streams) continue;
                    if (n < best_streams) {
                        best_streams = n;
                        best = c;
                    }
                }
                return best;
            }

            auto active_carrier_count() const noexcept -> std::size_t {
                std::size_t count = 0;
                for (auto const& c : carriers)
                    if (c && !c->canceled && (c->starting || c->running)) ++count;
                return count;
            }

            auto acquire(std::stop_source& stop, Clock::time_point deadline)
                -> capy::task<std::expected<std::shared_ptr<MuxCarrier>, TunnelConnectResult>> {
                if (stopped || stop.stop_requested()) co_return std::unexpected(TunnelConnectResult::failed);
                std::erase_if(carriers, [](auto const& c) { return !c || (!c->usable() && c->drained()); });
                if (auto c = pick_existing(true)) co_return c;
                if (active_carrier_count() >= cfg.max_connections) {
                    if (auto c = pick_existing(false)) co_return c;
                    co_return std::unexpected(TunnelConnectResult::failed);
                }
                auto [lock_err, lock] = co_await corosio::timeout(starting_.scoped_lock(), deadline);
                if (lock_err || stopped || stop.stop_requested() || Clock::now() >= deadline)
                    co_return std::unexpected(Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed);
                if (auto c = pick_existing(true)) co_return c;
                if (active_carrier_count() >= cfg.max_connections) {
                    if (auto c = pick_existing(false)) co_return c;
                    co_return std::unexpected(TunnelConnectResult::failed);
                }
                auto carrier = std::make_shared<MuxCarrier>(env, cfg, direct);
                carrier->starting = true;
                carriers.push_back(carrier);
                carrier->lower.raw.lower = detour
                    ? inner.through(carrier->state, env.context, *detour, false)
                    : inner.create(carrier->state, env.context, false, direct ? env.direct_options : nullptr);
                if (!carrier->lower.raw.lower) {
                    carrier->starting = false;
                    carrier->cancel();
                    co_return std::unexpected(TunnelConnectResult::failed);
                }
                std::stop_callback cb(stop.get_token(), [carrier]() noexcept { carrier->cancel(); });
                auto connected = co_await carrier->lower.raw.lower->connect_domain(
                    mux::sing::magic_domain, mux::sing::magic_port, deadline);
                if (connected != TunnelConnectResult::connected || stopped || stop.stop_requested()) {
                    carrier->starting = false;
                    carrier->cancel();
                    co_return std::unexpected(connected == TunnelConnectResult::connected ? TunnelConnectResult::failed : connected);
                }
                auto sreq = mux::sing::encode_session_request({mux::sing::version_1, mux::sing::proto_smux, cfg.padding});
                if (!co_await carrier->lower.raw.send(sreq)) {
                    carrier->starting = false;
                    carrier->cancel();
                    co_return std::unexpected(TunnelConnectResult::failed);
                }
                carrier->starting = false;
                carrier->start_run(carrier, env.context);
                co_return carrier;
            }
        };

        struct MuxProfile {
            std::shared_ptr<TunnelFactory> inner;
            config::MultiplexConfig cfg;
            std::mutex mutex;
            std::array<std::unique_ptr<MuxWorker>, 17> workers;
            MuxProfile(std::shared_ptr<TunnelFactory> in, config::MultiplexConfig c)
                : inner(std::move(in)), cfg(c) {}

            auto find(corosio::io_context& ctx) noexcept -> MuxWorker* {
                std::lock_guard lock(mutex);
                for (auto const& w : workers) if (w && &w->env.context == &ctx) return w.get();
                return nullptr;
            }
        };

        class MuxTunnel {
            Session& session_;
            io::io_context& context_;
            MuxProfile& profile_;
            MuxWorker* worker_;
            bool relay_local_;
            std::stop_source stop_;
            std::shared_ptr<MuxCarrier> carrier_;
            SmuxStream stream_;
            pro::proxy<TunnelFacade> fallback_;
            bool ready_ = false, resp_checked_ = false;
            std::vector<std::uint8_t> resp_accum_, early_rx_;
            std::size_t early_pos_ = 0;

            auto make_addr(io::endpoint const& ep, std::string_view domain) -> net::ProxyAddress {
                net::ProxyAddress out{};
                out.port = ep.port();
                if (!domain.empty()) {
                    out.family = net::ProxyAddressFamily::domain;
                    out.length = static_cast<std::uint8_t>(std::min<std::size_t>(domain.size(), 255));
                    std::copy_n(domain.begin(), out.length, out.bytes.begin());
                } else if (ep.address().is_v4()) {
                    out.family = net::ProxyAddressFamily::ipv4;
                    out.length = 4;
                    std::ranges::copy(ep.address().to_v4().to_bytes(), out.bytes.begin());
                } else {
                    out.family = net::ProxyAddressFamily::ipv6;
                    out.length = 16;
                    std::ranges::copy(ep.address().to_v6().to_bytes(), out.bytes.begin());
                }
                return out;
            }

            auto open_stream(bool udp, bool paddr, net::ProxyAddress const& dest, Clock::time_point deadline)
                -> capy::task<TunnelConnectResult> {
                if (ready_ || stop_.stop_requested() || session_.closed || !worker_ || worker_->stopped)
                    co_return TunnelConnectResult::failed;
                auto acquired = co_await worker_->acquire(stop_, deadline);
                if (!acquired || session_.closed || stop_.stop_requested())
                    co_return !acquired ? acquired.error() : TunnelConnectResult::failed;
                carrier_ = std::move(*acquired);
                auto opened = co_await carrier_->proto.open_stream();
                if (!opened) {
                    cancel();
                    co_return TunnelConnectResult::failed;
                }
                stream_ = SmuxStream(carrier_->proto, *opened);
                auto sreq = mux::sing::encode_stream_request({udp, paddr, dest});
                if (!sreq || !co_await stream_.send(*sreq)) {
                    cancel();
                    co_return TunnelConnectResult::failed;
                }
                ready_ = true;
                co_return TunnelConnectResult::connected;
            }
        public:
            MuxTunnel(Session& s, io::io_context& ctx, MuxProfile& p, MuxWorker* w, bool rl)
                : session_(s), context_(ctx), profile_(p), worker_(w), relay_local_(rl) {}
            ~MuxTunnel() { cancel(); }

            auto cancel() noexcept -> void {
                stop_.request_stop();
                if (fallback_) fallback_->cancel();
                stream_.cancel();
                if (ready_ && relay_local_) session_.client.cancel();
            }

            auto connect(io::endpoint ep) -> capy::task<TunnelConnectResult> {
                return connect_until(ep, session_.started + std::chrono::milliseconds(profile_.inner->timeout_ms));
            }
            auto connect_until(io::endpoint ep, Clock::time_point dl) -> capy::task<TunnelConnectResult> {
                return open_stream(false, false, make_addr(ep, {}), dl);
            }
            auto connect_domain(std::string_view domain, std::uint16_t port, Clock::time_point dl) -> capy::task<TunnelConnectResult> {
                return open_stream(false, false, make_addr(io::endpoint(io::ipv4_address{}, port), domain), dl);
            }
            auto has_uot() const noexcept -> bool { return false; }
            auto has_xudp() const noexcept -> bool { return false; }
            auto connect_uot() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_xudp() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_uot_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_xudp_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto packet_transport() const noexcept -> net::PacketTransport {
                if (profile_.cfg.only_tcp) {
                    if (fallback_) return fallback_->packet_transport();
                    return {net::PacketTransportKind::framed, {net::AddressWire::uot, false, false}, true};
                }
                return {net::PacketTransportKind::framed, {net::AddressWire::socks, false, false}, false};
            }
            auto connect_packets(net::ProxyAddress const& peer, Clock::time_point dl) -> capy::task<TunnelConnectResult> {
                if (profile_.cfg.only_tcp) {
                    if (!worker_ || worker_->stopped) co_return TunnelConnectResult::failed;
                    fallback_ = worker_->detour
                        ? profile_.inner->through(session_, context_, *worker_->detour, relay_local_)
                        : profile_.inner->create(session_, context_, relay_local_,
                            worker_->direct ? worker_->env.direct_options : nullptr);
                    if (!fallback_) co_return TunnelConnectResult::failed;
                    co_return co_await fallback_->connect_packets(peer, dl);
                }
                co_return co_await open_stream(true, true, mux::sing::magic_proxy_address(), dl);
            }
            auto connect_packets(Clock::time_point dl) -> capy::task<TunnelConnectResult> {
                co_return co_await connect_packets(net::ProxyAddress{}, dl);
            }

            auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
                if (fallback_) co_return co_await fallback_->send(bytes);
                if (!ready_ || stop_.stop_requested()) co_return false;
                auto ok = co_await stream_.send(bytes);
                if (ok) session_.touched = Clock::now();
                else cancel();
                co_return ok;
            }

            auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t, std::string>> {
                if (fallback_) co_return co_await fallback_->read(bytes);
                if (!ready_ || stop_.stop_requested()) co_return std::unexpected(std::string("mux tunnel closed"));
                if (early_pos_ < early_rx_.size()) {
                    auto n = std::min(bytes.size(), early_rx_.size() - early_pos_);
                    std::copy_n(early_rx_.data() + early_pos_, n, bytes.begin());
                    early_pos_ += n;
                    if (early_pos_ == early_rx_.size()) { early_rx_.clear(); early_pos_ = 0; }
                    session_.touched = Clock::now();
                    co_return n;
                }
                while (!resp_checked_) {
                    std::array<std::uint8_t, 512> tmp{};
                    auto r = co_await stream_.read(tmp);
                    if (!r || *r == 0) {
                        cancel();
                        co_return std::unexpected(std::string("mux response EOF"));
                    }
                    resp_accum_.insert(resp_accum_.end(), tmp.begin(), tmp.begin() + *r);
                    auto decoded = mux::sing::decode_stream_response(resp_accum_);
                    if (!decoded) {
                        cancel();
                        co_return std::unexpected(decoded.error());
                    }
                    if (!*decoded) {
                        if (resp_accum_.size() > 4096) { cancel(); co_return std::unexpected(std::string("oversized mux response")); }
                        continue;
                    }
                    if ((*decoded)->first.status != mux::sing::status_success) {
                        auto msg = (*decoded)->first.message;
                        cancel();
                        co_return std::unexpected(msg.empty() ? std::string("remote mux error") : std::move(msg));
                    }
                    resp_checked_ = true;
                    auto consumed = (*decoded)->second;
                    if (consumed < resp_accum_.size()) {
                        auto avail = resp_accum_.size() - consumed;
                        auto n = std::min(bytes.size(), avail);
                        std::copy_n(resp_accum_.data() + consumed, n, bytes.begin());
                        if (n < avail) early_rx_.assign(resp_accum_.begin() + consumed + n, resp_accum_.end());
                        resp_accum_.clear();
                        session_.touched = Clock::now();
                        co_return n;
                    }
                    resp_accum_.clear();
                }
                auto r = co_await stream_.read(bytes);
                if (!r) { cancel(); co_return std::unexpected(r.error()); }
                if (*r) session_.touched = Clock::now();
                co_return *r;
            }

            auto close_output() -> capy::task<bool> {
                if (fallback_) co_return co_await fallback_->close_output();
                if (!ready_ || stop_.stop_requested()) co_return false;
                co_return co_await stream_.close_output();
            }

            auto upload() -> capy::task<bool> {
                if (fallback_) co_return co_await fallback_->upload();
                if (!ready_ || stop_.stop_requested()) co_return false;
                co_return co_await net::stream_relay::upload(net::ByteRelayAdapter{
                    session_.client, *this, [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
            }

            auto download() -> capy::task<bool> {
                if (fallback_) co_return co_await fallback_->download();
                if (!ready_ || stop_.stop_requested()) co_return false;
                co_return co_await net::stream_relay::download(net::ByteRelayAdapter{
                    session_.client, *this, [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
            }
        };
    }

    auto make_mux_factory(TunnelFactory inner, config::MultiplexConfig cfg)
        -> std::expected<TunnelFactory, std::string> {
        if (!cfg.enabled) return inner;
        if (cfg.max_connections == 0 || cfg.max_connections > 64 ||
            (cfg.max_streams > 0 && cfg.min_streams > cfg.max_streams))
            return std::unexpected("invalid multiplex pool limits");
        auto profile = std::make_shared<MuxProfile>(std::make_shared<TunnelFactory>(std::move(inner)), cfg);
        auto detour = profile->inner->detour;
        auto detour_direct = profile->inner->detour_direct;
        auto timeout_ms = profile->inner->timeout_ms;
        auto requires_direct = profile->inner->requires_direct_socket;
        bool dual_family = profile->inner->packet_dual_family;
        bool fixed_peer = profile->inner->packet_fixed_peer;

        TunnelFactory out{
            [profile](Session& session, io::io_context& context, bool local, TcpSocketOptions const*) -> pro::proxy<TunnelFacade> {
                auto* w = profile->find(context);
                return w ? pro::make_proxy<TunnelFacade, MuxTunnel>(session, context, *profile, w, local) : pro::proxy<TunnelFacade>{};
            },
            timeout_ms,
            [profile](Session& session, io::io_context& context, TunnelFactory const&, bool local) -> pro::proxy<TunnelFacade> {
                auto* w = profile->find(context);
                return w ? pro::make_proxy<TunnelFacade, MuxTunnel>(session, context, *profile, w, local) : pro::proxy<TunnelFacade>{};
            },
            detour, requires_direct, detour_direct
        };
        out.packet_dual_family = cfg.only_tcp ? dual_family : true;
        out.packet_fixed_peer = cfg.only_tcp ? fixed_peer : false;

        out.start_context = [profile](OutboundContext const& env, TunnelFactory const* d, bool dir) -> bool {
            if (profile->inner->start_context && !profile->inner->start_context(env, d, dir)) return false;
            std::lock_guard lock(profile->mutex);
            for (auto const& w : profile->workers) if (w && &w->env.context == &env.context) return false;
            auto slot = std::ranges::find_if(profile->workers, [](auto const& w) { return !w; });
            if (slot == profile->workers.end()) return false;
            auto w = std::make_unique<MuxWorker>(env, *profile->inner, profile->cfg, d, dir);
            w->start_reaper();
            *slot = std::move(w);
            return true;
        };
        out.stop_context = [profile](io::io_context& ctx) noexcept {
            if (auto* w = profile->find(ctx)) w->stop();
            if (profile->inner->stop_context) profile->inner->stop_context(ctx);
        };
        out.reap_context = [profile](io::io_context& ctx) noexcept {
            if (auto* w = profile->find(ctx)) w->reap(Clock::time_point::max());
            if (profile->inner->reap_context) profile->inner->reap_context(ctx);
        };
        out.quiesced_context = [profile](io::io_context& ctx) noexcept -> bool {
            auto* w = profile->find(ctx);
            bool ok = !w || w->quiesced();
            if (profile->inner->quiesced_context) ok = ok && profile->inner->quiesced_context(ctx);
            return ok;
        };
        out.finish_context = [profile](io::io_context& ctx) noexcept {
            { std::lock_guard lock(profile->mutex);
              for (auto& w : profile->workers) if (w && &w->env.context == &ctx) { w.reset(); break; } }
            if (profile->inner->finish_context) profile->inner->finish_context(ctx);
        };
        return out;
    }

    auto Server::wrap_outbound_multiplex(std::size_t outbound_index, config::MultiplexConfig const& cfg) -> std::expected<void, std::string> {
        if (!cfg.enabled) return {};
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected("stop the server before wrapping outbound multiplex");
        if (outbound_index < 2 || outbound_index - 2 >= outbounds.size()) return std::unexpected("invalid outbound index for multiplex");
        auto wrapped = make_mux_factory(std::move(outbounds[outbound_index - 2]), cfg);
        if (!wrapped) return std::unexpected(std::move(wrapped.error()));
        outbounds[outbound_index - 2] = std::move(*wrapped);
        return {};
    }
}
