// Adapts the CLI runtimes to the shared proxy host lifecycle.
#pragma once
namespace cli::run_detail {
    auto configure_splice(auto& listeners,std::size_t maximum) -> bool {
        if (std::signal(SIGPIPE,SIG_IGN)==SIG_ERR) return false;
        return std::ranges::all_of(listeners,[maximum](auto& listener) {
            return listener.server->set_tcp_splice_pipes(maximum);
        });
    }

    template<class Listeners,class Udp,class Hy2,class Masque,class Tuic,class Tun>
    struct ProxyHost {
        Listeners& listeners;
        DnsMessageRuntime& dns;
        std::shared_ptr<Udp>& udp;
        Hy2& hy2;
        Masque& masque;
        Tuic& tuic;
        Tun& tun;
        std::vector<std::unique_ptr<RetiredTcpGeneration>>& retired;
        proxy::Host lifecycle{};
        bool dns_after_listeners=false;

        auto start(unsigned workers,bool traffic_stats,std::shared_ptr<proxy::TcpAdmission> const& admission={})
            -> std::expected<void,std::string> {
            auto add_dns=[&] {
                return lifecycle.add({
                    [this,admission] {return dns.start(!admission);},
                    [this]() noexcept {dns.stop();},
                    [this] {return dns.healthy();},
                    [this] {dns.begin_drain();},
                    [this] {return dns.drained();}
                });
            };
            if ((!dns_after_listeners && !add_dns()) ||
                !lifecycle.add({
                    [this,workers,traffic_stats,admission] {return start_listeners(workers,traffic_stats,admission);},
                    [this]() noexcept {stop_listeners();},
                    [this] {return listeners_healthy();},
                    [this] {begin_drain();},
                    [this] {return poll_drain();},
                    [this](std::chrono::milliseconds wait) {poll_listeners(wait);}
                }) || (dns_after_listeners && !add_dns()) || !lifecycle.add({
                    [this]() -> std::expected<void,std::string> {
                        if (auto started=udp->start(); !started) return started;
                        return {};
                    },
                    [this]() noexcept {udp->stop();},
                    [this] {return udp->healthy();},
                    {},{},
                    [this](std::chrono::milliseconds) {udp->poll();}
                })) return std::unexpected("cannot register proxy host services");
            auto canceled=[] {return stopped.load(std::memory_order_relaxed);};
            auto started=lifecycle.start(canceled);
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

        auto healthy() const -> bool {return lifecycle.healthy();}
        auto poll(std::chrono::milliseconds wait) -> void {
            lifecycle.poll(udp->wait(wait));
            poll_retired();
        }
        auto drain(std::chrono::milliseconds grace) -> void {lifecycle.drain(grace);}
        auto stop() noexcept -> void {
            lifecycle.stop();
            retired.clear();
        }

    private:
        static auto ordinary(auto const& listener) noexcept -> bool {
            return !listener.hy2 && !listener.masque && !listener.tuic && !listener.tun;
        }

        auto start_listeners(unsigned workers,bool traffic_stats,std::shared_ptr<proxy::TcpAdmission> const& admission)
            -> std::expected<void,std::string> {
            for (std::size_t index=0;index<listeners.size();++index) {
                if (stopped.load(std::memory_order_relaxed)) return std::unexpected("startup canceled");
                auto& listener=listeners[index];
                if (traffic_stats && !listener.server->enable_traffic_stats(listener.packet_slots))
                    return std::unexpected("cannot enable traffic statistics");
                if (listener.tun) {
                    auto name=tun.start(index,*listener.server);
                    if (!name) return std::unexpected("cannot start TUN: "+name.error());
                    listener.host=*name;
                    continue;
                }
                auto bound=[&]() -> std::expected<std::uint16_t,std::string> {
                    if (!listener.unix_path.empty()) {
                        auto started=listener.server->start_unix(listener.unix_path,workers);
                        if (!started) return std::unexpected(started.error().message());
                        return 0;
                    }
                    if (listener.masque) return masque.start(index,*listener.server,listener.port,workers);
                    if (listener.hy2) return hy2.start(index,*listener.server,listener.port,listener.ipv6,workers);
                    if (listener.tuic) return tuic.start(index,*listener.server,listener.port,listener.ipv6,workers);
                    if (admission) {
                        auto staged=listener.server->stage_tcp(admission,1,listener.port,listener.inbound,workers,
                            listener.ipv6,listener.address);
                        if (!staged) return std::unexpected(staged.error().message());
                        return *staged;
                    }
                    return proxy::start_host_tcp(*listener.server,
                        {listener.port,listener.inbound,workers,listener.ipv6,listener.address});
                }();
                if (!bound) {
                    auto name=listener.masque ? "MASQUE" : listener.hy2 ? "Hysteria2" : listener.tuic ? "TUIC" : "proxy";
                    return std::unexpected(std::string("cannot listen ")+name+": "+bound.error());
                }
                listener.port=*bound;
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
                std::ranges::all_of(listeners,[](auto const& item) {
                    return !ordinary(item) || item.server->healthy();
                });
        }

        auto poll_listeners(std::chrono::milliseconds wait) -> void {
            bool polled=false;
            for (auto& listener : listeners) if (ordinary(listener)) {
                listener.server->poll(wait);
                polled=true;
            }
            if (!polled) std::this_thread::sleep_for(wait);
        }

        auto begin_drain() -> void {
            for (auto& listener : listeners) if (ordinary(listener)) listener.server->begin_drain();
        }

        auto poll_retired() -> bool {
            std::erase_if(retired,[](auto const& generation) {return generation->poll();});
            return retired.empty();
        }

        auto poll_drain() -> bool {
            bool complete=poll_retired();
            for (auto& listener : listeners) {
                if (!ordinary(listener) || listener.server->drained()) continue;
                listener.server->poll(std::chrono::milliseconds(0));
                complete&=listener.server->drained();
            }
            return complete;
        }
    };
}
