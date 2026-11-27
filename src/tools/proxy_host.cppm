// Adapts the CLI runtimes to the shared proxy host lifecycle.
module;
#include <csignal>

export module cli.proxy_host;
import std;
import cli.dns_message_runtime;
import cli.proxy_control_wake;
import cli.proxy_listener;
import cli.proxy_run_state;
import cli.proxy_services;
import config;
import corosio;
import dns.tls_query;
import relay;
import relay.host;

export namespace cli::run_detail {
    inline constexpr auto default_tcp_splice_pipes() noexcept -> std::size_t {
#if defined(__linux__)
        return 64;
#else
        return 0;
#endif
    }

    inline auto configure_splice(auto& listeners, std::size_t maximum) -> bool {
        if (std::signal(SIGPIPE, SIG_IGN) == SIG_ERR) return false;
        return std::ranges::all_of(listeners, [maximum](auto& listener) {
            return listener.server->set_tcp_splice_pipes(maximum);
        });
    }

    inline auto reclaim_retired_generations(std::vector<std::unique_ptr<RetiredTcpGeneration>>& retired,
        bool shared_driven, std::uint64_t& reclaimed_upload, std::uint64_t& reclaimed_download) -> bool {
        std::erase_if(retired, [&](auto const& generation) {
            if (!generation->poll(shared_driven)) return false;
            for (auto const& l : generation->listeners) {
                if (!l.server) continue;
                auto snap = l.server->traffic_snapshot();
                reclaimed_upload += snap.bytes.upload;
                reclaimed_download += snap.bytes.download;
            }
            return true;
        });
        return retired.empty();
    }

    template<class Listeners, class Udp, class Hy2, class Masque, class Tuic, class Tun>
    struct ProxyHost {
        Listeners& listeners;
        DnsMessageRuntime& dns;
        std::shared_ptr<Udp>& udp;
        Hy2& hy2;
        Masque& masque;
        Tuic& tuic;
        Tun& tun;
        std::vector<std::unique_ptr<RetiredTcpGeneration>>& retired;
        relay::Host lifecycle{};
        bool dns_after_listeners = false;
        std::shared_ptr<std::atomic_bool> memory_shed{};
        corosio::io_context* shared_io = nullptr;
        ControlEventBridge* control_wake = nullptr;
        dns::TlsQueryMaintenance shared_dns_maint{};
        std::optional<config::TorServiceConfig> tor_service{};
        std::uint64_t reclaimed_upload_bytes = 0, reclaimed_download_bytes = 0;

        [[nodiscard]] auto reclaimed_traffic() const noexcept -> std::pair<std::uint64_t, std::uint64_t> {
            return {reclaimed_upload_bytes, reclaimed_download_bytes};
        }

        auto attach_memory_shed(std::shared_ptr<std::atomic_bool> flag) noexcept -> void {
            memory_shed = std::move(flag);
            for (auto& listener : listeners) listener.server->set_memory_shed(memory_shed);
        }
        auto make_watchdog_hooks(std::shared_ptr<void> acme_credential = {}) -> ServiceHooks {
            auto shed = std::make_shared<std::atomic_bool>(false);
            attach_memory_shed(shed);
            return {
                .watchdog = {std::move(shed), [this](std::uint8_t lvl) noexcept {
                    for (auto& listener : listeners) listener.server->request_memory_reclaim(lvl);
                    dns.reclaim_memory(lvl >= 2);
                }},
                .acme = {{}, std::move(acme_credential)},
                .tor = {[this](config::TorServiceConfig const& cfg) -> std::expected<std::size_t, std::string> {
                    std::size_t idx = 0;
                    for (auto& listener : listeners) {
                        auto added = listener.server->add_tor(cfg);
                        if (!added) return std::unexpected(std::move(added.error()));
                        idx = *added;
                    }
                    tor_service = cfg;
                    return idx;
                }},
            };
        }

        auto start(unsigned workers, bool traffic_stats, std::shared_ptr<relay::TcpAdmission> const& admission = {})
            -> std::expected<void, std::string> {
            auto add_dns = [&] {
                return lifecycle.add({
                    [this, admission] { return dns.start(!admission); },
                    [this]() noexcept { dns.stop(); },
                    [this] { return dns.healthy(); },
                    [this] { dns.begin_drain(); },
                    [this] { return dns.drained(); }
                });
            };
            if ((!dns_after_listeners && !add_dns()) ||
                !lifecycle.add({
                    [this, workers, traffic_stats, admission] { return start_listeners(workers, traffic_stats, admission); },
                    [this]() noexcept { stop_listeners(); },
                    [this] { return listeners_healthy(); },
                    [this] { begin_drain(); },
                    [this] { return poll_drain(); },
                    [this](std::chrono::milliseconds wait) { poll_listeners(wait); }
                }) || (dns_after_listeners && !add_dns()) || !lifecycle.add({
                    [this]() -> std::expected<void, std::string> {
                        if (auto started = udp->start(); !started) return started;
                        return {};
                    },
                    [this]() noexcept { udp->stop(); },
                    [this] { return udp->healthy(); },
                    {}, {},
                    [this](std::chrono::milliseconds) { udp->poll(); }
                })) return std::unexpected("cannot register proxy host services");
            auto canceled = [] { return stopped.load(std::memory_order_relaxed); };
            auto started = lifecycle.start(canceled);
            if (started && admission) {
                if (!admission->publish(1)) {
                    lifecycle.stop();
                    return std::unexpected("cannot publish TCP listeners");
                }
                dns.admit();
            }
            if (started) udp->publish_admission();
            return started;
        }

        auto healthy() const -> bool { return lifecycle.healthy(); }
        auto poll(std::chrono::milliseconds wait) -> void {
            lifecycle.poll(udp->wait(wait));
            poll_retired();
        }
        auto drain(std::chrono::milliseconds grace) -> void { lifecycle.drain(grace); }
        auto stop() noexcept -> void {
            lifecycle.stop();
            retired.clear();
        }

    private:
        static auto ordinary(auto const& listener) noexcept -> bool {
            return !listener.hy2 && !listener.masque && !listener.tuic && !listener.tun;
        }

        auto start_listeners(unsigned workers, bool traffic_stats, std::shared_ptr<relay::TcpAdmission> const& admission)
            -> std::expected<void, std::string> {
            for (std::size_t index = 0; index < listeners.size(); ++index) {
                if (stopped.load(std::memory_order_relaxed)) return std::unexpected("startup canceled");
                auto& listener = listeners[index];
                if (traffic_stats && !listener.server->enable_traffic_stats(listener.packet_slots))
                    return std::unexpected("cannot enable traffic statistics");
                if (listener.tun) {
                    auto name = tun.start(index, *listener.server);
                    if (!name) return std::unexpected("cannot start TUN: " + name.error());
                    listener.host = *name;
                    continue;
                }
                auto bound = [&]() -> std::expected<std::uint16_t, std::string> {
                    if (!listener.unix_path.empty()) {
                        auto started = listener.server->start_unix(listener.unix_path, workers);
                        if (!started) return std::unexpected(started.error().message());
                        return 0;
                    }
                    if (listener.masque) return masque.start(index, *listener.server, listener.port, workers);
                    if (listener.hy2) return hy2.start(index, *listener.server, listener.port, listener.ipv6, workers);
                    if (listener.tuic) return tuic.start(index, *listener.server, listener.port, listener.ipv6, workers);
                    if (admission) {
                        auto staged = listener.server->stage_tcp(admission, 1, listener.port, listener.inbound, workers,
                            listener.ipv6, listener.address);
                        if (!staged) return std::unexpected(staged.error().message());
                        return *staged;
                    }
                    return relay::start_host_tcp(*listener.server,
                        {listener.port, listener.inbound, workers, listener.ipv6, listener.address});
                }();
                if (!bound) {
                    auto name = listener.masque ? "MASQUE" : listener.hy2 ? "Hysteria2" : listener.tuic ? "TUIC" : "proxy";
                    return std::unexpected(std::string("cannot listen ") + name + ": " + bound.error());
                }
                listener.port = *bound;
            }
            return {};
        }

        auto stop_listeners() noexcept -> void {
            hy2.stop();
            masque.stop();
            tuic.stop();
            tun.stop();
            for (auto& listener : listeners) listener.server->stop();
        }

        auto listeners_healthy() const -> bool {
            return hy2.healthy() && masque.healthy() && tuic.healthy() && tun.healthy() &&
                std::ranges::all_of(listeners, [](auto const& item) {
                    return !ordinary(item) || item.server->healthy();
                });
        }

        auto poll_listeners(std::chrono::milliseconds wait) -> void {
            if (shared_io) {
                for (auto& l : listeners) if (ordinary(l)) wait = std::min(wait, l.server->prepare_poll());
                for (auto& g : retired) for (auto& l : g->listeners) if (l.server->uses_shared_context()) wait = std::min(wait, l.server->prepare_poll());
                wait = std::max(wait, std::chrono::milliseconds(0));
                if (control_wake) control_wake->arm();
                shared_io->restart();
                if (wait <= std::chrono::milliseconds(0)) (void)shared_io->poll();
                else (void)shared_io->run_for(wait);
                if (control_wake) control_wake->drain_wake_pipe();
                auto now = std::chrono::steady_clock::now();
                for (auto& l : listeners) if (ordinary(l)) l.server->finish_poll(now, false);
                for (auto& g : retired) for (auto& l : g->listeners) if (l.server->uses_shared_context()) l.server->finish_poll(now, false);
                shared_dns_maint.poll(*shared_io, now);
                return;
            }
            bool polled = false;
            for (auto& listener : listeners) if (ordinary(listener)) {
                listener.server->poll(wait);
                polled = true;
            }
            if (!polled) {
                if (control_wake) control_wake->wait_idle(wait);
                else std::this_thread::sleep_for(wait);
            }
        }

        auto begin_drain() -> void {
            tun.begin_drain();
            for (auto& listener : listeners) if (ordinary(listener)) listener.server->begin_drain();
        }

        auto poll_retired() -> bool {
            return reclaim_retired_generations(retired, shared_io != nullptr, reclaimed_upload_bytes, reclaimed_download_bytes);
        }

        auto poll_drain() -> bool {
            if (shared_io) {
                for (auto& l : listeners) if (ordinary(l) && !l.server->drained()) (void)l.server->prepare_poll();
                for (auto& g : retired) for (auto& l : g->listeners) if (l.server->uses_shared_context() && !l.server->drained()) (void)l.server->prepare_poll();
                shared_io->restart();
                (void)shared_io->poll();
                auto now = std::chrono::steady_clock::now();
                for (auto& l : listeners) if (ordinary(l) && !l.server->drained()) l.server->finish_poll(now, false);
                for (auto& g : retired) for (auto& l : g->listeners) if (l.server->uses_shared_context() && !l.server->drained()) l.server->finish_poll(now, false);
            }
            bool complete = poll_retired() && tun.drained();
            for (auto& listener : listeners) {
                if (!ordinary(listener) || listener.server->drained()) continue;
                if (!shared_io) listener.server->poll(std::chrono::milliseconds(0));
                complete &= listener.server->drained();
            }
            return complete;
        }
    };
}
