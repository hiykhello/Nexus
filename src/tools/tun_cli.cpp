module cli.tun_enabled;
import std;
import config;
import proxy;
import cli.tun_host;
import cli.masque_tun;
import packet.tun_network_types;

namespace cli::tun_enabled {
    Runtime::~Runtime() { stop(); }
    auto Runtime::resize(std::size_t count) -> void { entries_.resize(count); }

    auto Runtime::configure(std::size_t index, config::InboundConfig const& entry, config::Config const& config)
        -> std::expected<void, std::string> {
        if (!entry.tun) return {};
        if (index >= entries_.size() || entries_[index]) return std::unexpected("invalid TUN slot");
        entries_[index].emplace(Entry{*entry.tun, nullptr});
        auto& redirect=entries_[index]->redirect;
        if (entry.tun->auto_redirect) {
            redirect.tcp_dns=entry.tun->dns_hijack_tcp;
            redirect.udp_dns=config.ordered_tcp && config.ordered_tcp->udp &&
                std::ranges::any_of(config.ordered_tcp->rules,[](auto const& rule) {
                    return rule.action==config::OrderedTcpAction::hijack_dns;
                });
            if (config.dns && config.dns->fakeip) {
                auto const& fake=*config.dns->fakeip;
                if (entry.tun->inet4_address) {
                    auto& prefix=redirect.protected_destinations[redirect.protected_count++];
                    prefix.family=4;
                    prefix.prefix=static_cast<std::uint8_t>(std::countl_zero(fake.last^fake.first));
                    for (unsigned i=0;i<4;++i) prefix.bytes[i]=static_cast<std::uint8_t>(fake.first>>(24-8*i));
                }
                if (entry.tun->inet6_address && fake.ipv6) {
                    auto& prefix=redirect.protected_destinations[redirect.protected_count++];
                    prefix.family=6;
                    prefix.prefix=fake.ipv6->second;
                    std::ranges::copy(fake.ipv6->first,prefix.bytes.begin());
                }
            }
        }
        if (auto const& name = entry.tun->connect_ip_outbound) {
            auto group=std::ranges::find(config.selectors,*name,&config::OutboundSelector::name);
            if (group!=config.selectors.end() && (group->uses_probe || group->uses_balance))
                return std::unexpected("CONNECT-IP TUN requires a manual outbound group");
            auto found = std::ranges::find(config.masque_outbounds,config::selected_outbound(config,*name),&config::NamedMasqueOutbound::name);
            if (found == config.masque_outbounds.end() || !found->config.connect_ip)
                return std::unexpected("TUN requires a named MASQUE CONNECT-IP outbound");
            auto outbound = found->config;
            std::optional<std::string> lower_host;
            if (outbound.detour_index) {
                if (*outbound.detour_index == 0) outbound.tcp_options.binding = config.direct_tcp_options.binding;
                else {
                    auto next=config::selected_outbound(config,*outbound.detour);
                    auto tunnel=[&](auto const& nodes,auto&& inspect) -> bool {
                        using Node=std::ranges::range_value_t<decltype(nodes)>;
                        auto found=std::ranges::find(nodes,next,&Node::name);
                        if (found==nodes.end() || !inspect(found->config)) return false;
                        auto const& hop=found->config;
                        if (hop.detour_index.value_or(0)) next=config::selected_outbound(config,*hop.detour);
                        else lower_host=hop.host;
                        return true;
                    };
                    bool requires_packets=true;
                    for (std::size_t step=0;!lower_host && step<config.tunnel_count();++step) {
                        if (!tunnel(config.trojan_outbounds,[](auto const&) {return true;}) &&
                            !tunnel(config.shadowsocks_outbounds,[&](auto const& hop) {return !requires_packets || hop.udp_over_tcp;}))
                            break;
                        requires_packets=false;
                    }
                    if (!lower_host) return std::unexpected("CONNECT-IP TUN detour requires a Trojan or Shadowsocks chain with a datagram-capable final hop");
                    if (entry.tun->socket_mark)
                        return std::unexpected("CONNECT-IP TUN socket-mark belongs to the physical detour outbound");
                    if (std::ranges::count_if(config.inbounds, [](auto const& in) {return in.tun.has_value();}) != 1)
                        return std::unexpected("CONNECT-IP TUN detour requires a single TUN inbound");
                }
            }
            entries_[index]->masque = std::make_unique<MasqueTunHost>(*entry.tun, std::move(outbound), std::move(lower_host));
        }
        return {};
    }

    auto Runtime::start(std::size_t index, proxy::Server& server) -> std::expected<std::string, std::string> {
        if (index >= entries_.size() || !entries_[index]) return std::unexpected("TUN inbound not configured");
        auto& e = *entries_[index];
        if (e.masque) return e.masque->start(server);
        if (e.device_adopted) return std::unexpected("TUN device-fd has already been adopted");
        e.host = std::make_unique<TunHost>(server,e.config,true,e.redirect);
        auto started = [&]() -> std::expected<std::string, std::string> {
            if (!e.config.device_fd) return e.host->start();
            auto const fd = *e.config.device_fd;
            auto device = packet::LinuxTun::attach(fd.number,
                fd.adopt ? packet::TunFdOwnership::adopt : packet::TunFdOwnership::borrow);
            if (!device) {
                if (auto* system = std::get_if<std::error_code>(&device.error()))
                    return std::unexpected("failed attaching TUN device-fd: " + system->message());
                return std::unexpected("TUN device-fd must be a nonblocking read/write unframed TUN");
            }
            e.device_adopted = fd.adopt;
            return e.host->start(std::move(*device));
        }();
        if (!started) { failure_ = started.error(); e.host.reset(); return std::unexpected(started.error()); }
        return *started;
    }

    auto Runtime::queue_outbound_probe(std::size_t index,std::shared_ptr<proxy::OutboundProbe> probe) -> bool {
        return index<entries_.size() && entries_[index] && entries_[index]->host &&
            entries_[index]->host->queue_outbound_probe(std::move(probe));
    }

    auto Runtime::healthy() const noexcept -> bool {
        return std::ranges::all_of(entries_, [](auto const& e) {
            if (!e) return true;
            if (e->masque) return e->masque->healthy();
            return !e->host || e->host->healthy();
        });
    }

    auto Runtime::failure() const -> std::optional<std::string> {
        for (auto const& e : entries_) if (e) {
            if (e->masque) if (auto err = e->masque->failure()) return err;
            if (e->host) if (auto err = e->host->failure()) return err;
        }
        return failure_;
    }

    auto Runtime::stop() noexcept -> void {
        for (auto& e : entries_) if (e) {
            if (e->masque) e->masque->stop();
            if (e->host) e->host->stop();
        }
    }
}
