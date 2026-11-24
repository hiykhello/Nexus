module;
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/when_all.hpp>

module cli.proxy_services;
import std;
import capy;
import corosio;
import config;
import logging;
import logging.cli;
import platform.ip_address;
import relay.sni_demux;

namespace cli {
    namespace {
        using Clock = std::chrono::steady_clock;
        using namespace std::chrono_literals;

        auto parse_ip_ep(std::string_view host, std::uint16_t port) -> std::expected<corosio::endpoint, std::string> {
            auto ip = platform::parse_ip_address(host);
            if (!ip) return std::unexpected("sni-demux: invalid IP address: " + std::string(host));
            if (ip->size == 4) {
                corosio::ipv4_address::bytes_type b{};
                std::copy_n(ip->bytes.begin(), 4, b.begin());
                return corosio::endpoint(corosio::ipv4_address(b), port);
            }
            return corosio::endpoint(corosio::ipv6_address(ip->bytes), port);
        }

        auto parse_host_port(std::string_view spec) -> std::expected<corosio::endpoint, std::string> {
            auto parsed = platform::split_host_port(spec);
            if (!parsed) return std::unexpected("sni-demux: invalid upstream host:port: " + std::string(spec));
            return parse_ip_ep(parsed->host, parsed->port);
        }

        auto to_role(std::string_view name) noexcept -> relay::DemuxRole {
            if (name == "https") return relay::DemuxRole::https_site;
            if (name == "console" || name == "web") return relay::DemuxRole::web_console;
            if (name == "custom") return relay::DemuxRole::custom;
            return relay::DemuxRole::proxy_inbound;
        }

        auto write_all(corosio::tcp_socket& s, std::span<std::uint8_t const> data, Clock::time_point dl) -> capy::task<bool> {
            while (!data.empty()) {
                auto [ec, n] = co_await corosio::timeout(s.write_some(capy::const_buffer(data.data(), data.size())), dl);
                if (ec || n == 0 || n > data.size()) co_return false;
                data = data.subspan(n);
            }
            co_return true;
        }

        auto pump_dir(corosio::tcp_socket& src, corosio::tcp_socket& dst, std::atomic_bool const& stopping)
            -> capy::task<capy::results<>> {
            std::array<std::uint8_t, 16384> buf{};
            while (!stopping.load(std::memory_order_acquire)) {
                auto [re, n] = co_await src.read_some(capy::mutable_buffer(buf.data(), buf.size()));
                if (re || n == 0) break;
                std::span<std::uint8_t const> rem(buf.data(), n);
                while (!rem.empty()) {
                    auto [we, wn] = co_await dst.write_some(capy::const_buffer(rem.data(), rem.size()));
                    if (we || wn == 0 || wn > rem.size()) co_return capy::results<>{};
                    rem = rem.subspan(wn);
                }
            }
            (void)dst.shutdown(corosio::shutdown_send);
            co_return capy::results<>{};
        }

        struct SniDemuxState {
            static constexpr std::size_t kMaxConns = 256;
            relay::SniDemuxRouter router;
            std::unordered_map<std::string, corosio::endpoint> upstreams;
            std::uint16_t bound_port = 0;
            std::atomic_bool stopping{false};
            std::atomic<std::size_t> active{0};
            std::mutex socks_mu;
            std::vector<corosio::tcp_socket*> active_socks;
            // Declared after all coroutine-referenced state so ~io_context() destroys
            // any suspended frames while router/upstreams/socks_mu remain alive.
            std::mutex shutdown_mu;
            std::condition_variable shutdown_cv;
            bool shutdown_done = false;
            bool worker_done = false;
            corosio::io_context io;
            corosio::tcp_acceptor acceptor{io};
            std::jthread worker;

            ~SniDemuxState() { stop(); }

            auto track(corosio::tcp_socket* s) -> void {
                std::lock_guard lk(socks_mu);
                active_socks.push_back(s);
            }
            auto untrack(corosio::tcp_socket* s) noexcept -> void {
                std::lock_guard lk(socks_mu);
                std::erase(active_socks, s);
            }

            auto close_on_io() noexcept -> void {
                acceptor.close();
                std::lock_guard lk(socks_mu);
                for (auto* s : active_socks) s->cancel();
            }

            auto shutdown_task() -> capy::task<> {
                close_on_io();
                {
                    std::lock_guard lk(shutdown_mu);
                    shutdown_done = true;
                }
                shutdown_cv.notify_all();
                io.stop();
                co_return;
            }

            auto stop() noexcept -> void {
                if (stopping.exchange(true, std::memory_order_acq_rel)) return;
                if (!worker.joinable()) {
                    close_on_io();
                    return;
                }
                try {
                    capy::run_async(io.get_executor())(shutdown_task());
                    std::unique_lock lk(shutdown_mu);
                    shutdown_cv.wait_for(lk, std::chrono::seconds(2), [&] { return shutdown_done || worker_done; });
                } catch (...) {}
                io.stop();
                worker.join();
            }

            auto handle_client(corosio::tcp_socket client) -> capy::task<> {
                struct ClientGuard {
                    SniDemuxState& st;
                    corosio::tcp_socket* c;
                    ~ClientGuard() {
                        st.untrack(c);
                        st.active.fetch_sub(1, std::memory_order_acq_rel);
                    }
                } client_guard{*this, &client};
                track(&client);

                std::vector<std::uint8_t> peek;
                peek.reserve(1024);
                std::array<std::uint8_t, 4096> tmp{};
                auto dl = Clock::now() + 5s;
                while (peek.size() < 16389 && !stopping.load(std::memory_order_acquire)) {
                    auto [ec, n] = co_await corosio::timeout(client.read_some(capy::mutable_buffer(tmp.data(), tmp.size())), dl);
                    if (ec || n == 0) co_return;
                    peek.insert(peek.end(), tmp.begin(), tmp.begin() + static_cast<std::ptrdiff_t>(n));
                    auto res = relay::inspect_client_hello(peek);
                    if (res.status != relay::SniPeekStatus::incomplete) break;
                }
                if (peek.empty() || stopping.load(std::memory_order_acquire)) co_return;

                auto decision = router.route(peek);
                auto it = upstreams.find(decision.target_upstream);
                if (it == upstreams.end()) co_return;

                corosio::tcp_socket upstream(io);
                if (upstream.open()) co_return;
                struct UpstreamGuard {
                    SniDemuxState& st;
                    corosio::tcp_socket* u;
                    ~UpstreamGuard() { st.untrack(u); }
                } upstream_guard{*this, &upstream};
                track(&upstream);
                auto [ce] = co_await corosio::timeout(upstream.connect(it->second), Clock::now() + 5s);
                if (ce || stopping.load(std::memory_order_acquire)) co_return;
                if (!co_await write_all(upstream, decision.passthrough_bytes, Clock::now() + 5s)) co_return;

                (void)co_await capy::when_all(
                    pump_dir(client, upstream, stopping),
                    pump_dir(upstream, client, stopping));
            }

            auto accept_loop() -> capy::task<> {
                while (!stopping.load(std::memory_order_acquire)) {
                    auto [ec, sock] = co_await acceptor.accept();
                    if (ec) break;
                    if (active.fetch_add(1, std::memory_order_acq_rel) >= kMaxConns) {
                        active.fetch_sub(1, std::memory_order_acq_rel);
                        sock.close();
                        continue;
                    }
                    capy::run_async(io.get_executor())(handle_client(std::move(sock)));
                }
            }
        };
    }

    auto init_sni_demux_service(config::SniDemuxConfig const& cfg, logging::Runtime& logs)
        -> std::expected<ServiceHandle, std::string> {
        auto listen_ep = parse_ip_ep(cfg.listen_host, cfg.listen_port);
        if (!listen_ep) return std::unexpected(listen_ep.error());
        auto fb_ep = parse_host_port(cfg.fallback_upstream);
        if (!fb_ep) return std::unexpected(fb_ep.error());

        auto st = std::make_unique<SniDemuxState>();
        st->router.set_fallback(relay::DemuxRole::https_site, cfg.fallback_upstream);
        st->upstreams.emplace(cfg.fallback_upstream, *fb_ep);
        for (auto const& r : cfg.rules) {
            auto uep = parse_host_port(r.target_upstream);
            if (!uep) return std::unexpected(uep.error());
            st->upstreams.emplace(r.target_upstream, *uep);
            st->router.add_rule({r.host_pattern, r.required_alpn, to_role(r.role), r.target_upstream});
        }
        if (auto ec = st->acceptor.open(); ec)
            return std::unexpected("sni-demux: acceptor open failed: " + ec.message());
        if (auto ec = st->acceptor.bind(*listen_ep); ec)
            return std::unexpected("sni-demux: bind failed on " + cfg.listen_host + ": " + ec.message());
        if (auto ec = st->acceptor.listen(); ec)
            return std::unexpected("sni-demux: listen failed: " + ec.message());
        st->bound_port = st->acceptor.local_endpoint().port();

        capy::run_async(st->io.get_executor())(st->accept_loop());
        st->worker = std::jthread([ptr = st.get()] {
            ptr->io.run();
            { std::lock_guard lk(ptr->shutdown_mu); ptr->worker_done = true; }
            ptr->shutdown_cv.notify_all();
        });
        logs.emit(logging::Level::info, logging::Domain::core, 101, {},
            "sni-demux listening on {}:{} ({} rules)", cfg.listen_host, st->bound_port, cfg.rules.size());
        return ServiceHandle::create(std::move(st));
    }

    auto sni_demux_bound_port(ServiceHandle const& h) noexcept -> std::uint16_t {
        if (!h.state) return 0;
        return static_cast<SniDemuxState const*>(h.state.get())->bound_port;
    }
}
