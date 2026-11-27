module config;
import std;
import platform.ip_address;
import rules;

namespace config {
    static auto populate_physical_index(Config& config,std::string_view direct,std::optional<std::string> const& block) -> void {
        config.physical_index.clear();
        config.physical_index.reserve(1 + std::size_t{block.has_value()} + config.tunnel_count());
        config.physical_index.emplace(std::string(direct), std::uint32_t{0});
        if (block) config.physical_index.emplace(*block, std::uint32_t{1});
        std::uint32_t idx = 2;
        auto add = [&](auto const& entries) {
            for (auto const& e : entries) config.physical_index.emplace(e.name, idx++);
        };
        add(config.vless_outbounds); add(config.shadowsocks_outbounds); add(config.trojan_outbounds);
        add(config.anytls_outbounds); add(config.hysteria2_outbounds); add(config.snell_outbounds);
        add(config.shadowtls_outbounds); add(config.tuic_outbounds); add(config.masque_outbounds);
        add(config.wireguard_outbounds); add(config.ssh_outbounds); add(config.naive_outbounds);
        add(config.openvpn_outbounds); add(config.openconnect_outbounds);
        add(config.tailscale_outbounds); add(config.tcp_proxy_outbounds);
    }

    static auto populate_selector_index(Config& config) -> void {
        config.selector_index.clear();
        config.selector_index.reserve(config.selectors.size());
        for (std::uint32_t i = 0; i < config.selectors.size(); ++i)
            config.selector_index.emplace(config.selectors[i].name, i);
    }

    static auto find_selector(Config const& config, std::string_view name) noexcept -> OutboundSelector const* {
        if (!config.selectors.empty() && config.selector_index.size() == config.selectors.size()) {
            auto it = config.selector_index.find(name);
            return it == config.selector_index.end() ? nullptr : &config.selectors[it->second];
        }
        auto group = std::ranges::find(config.selectors, name, &OutboundSelector::name);
        return group == config.selectors.end() ? nullptr : &*group;
    }

    static auto physical_outbound_index(Config const& config,std::string_view direct,std::optional<std::string> const& block,std::string_view name)
        -> std::optional<std::size_t> {
        if (name==direct) return 0;
        if (block && name==*block) return 1;
        auto expected = 1 + std::size_t{block.has_value()} + config.tunnel_count();
        if (config.physical_index.size() == expected && config.physical_index.contains(direct)) {
            auto it = config.physical_index.find(name);
            return it == config.physical_index.end() ? std::nullopt : std::optional<std::size_t>{it->second};
        }
        auto found=std::ranges::find(config.vless_outbounds,name,&NamedVlessOutbound::name);
        if (found!=config.vless_outbounds.end()) return static_cast<std::size_t>(found-config.vless_outbounds.begin())+2;
        auto ss=std::ranges::find(config.shadowsocks_outbounds,name,&NamedShadowsocksOutbound::name);
        if (ss!=config.shadowsocks_outbounds.end()) return static_cast<std::size_t>(ss-config.shadowsocks_outbounds.begin())+2+config.vless_outbounds.size();
        auto trojan=std::ranges::find(config.trojan_outbounds,name,&NamedTrojanOutbound::name);
        if (trojan!=config.trojan_outbounds.end()) return static_cast<std::size_t>(trojan-config.trojan_outbounds.begin())+2+config.vless_outbounds.size()+config.shadowsocks_outbounds.size();
        auto anytls=std::ranges::find(config.anytls_outbounds,name,&NamedAnyTlsOutbound::name);
        auto prefix=2+config.vless_outbounds.size()+config.shadowsocks_outbounds.size()+config.trojan_outbounds.size();
        if(anytls!=config.anytls_outbounds.end())return static_cast<std::size_t>(anytls-config.anytls_outbounds.begin())+prefix;
        auto hy2=std::ranges::find(config.hysteria2_outbounds,name,&NamedHysteria2Outbound::name);
        if(hy2!=config.hysteria2_outbounds.end())return static_cast<std::size_t>(hy2-config.hysteria2_outbounds.begin())+prefix+config.anytls_outbounds.size();
        auto snell=std::ranges::find(config.snell_outbounds,name,&NamedSnellOutbound::name);
        if(snell!=config.snell_outbounds.end())return static_cast<std::size_t>(snell-config.snell_outbounds.begin())+prefix+config.anytls_outbounds.size()+config.hysteria2_outbounds.size();
        auto base=prefix+config.anytls_outbounds.size()+config.hysteria2_outbounds.size()+config.snell_outbounds.size();
        auto stls=std::ranges::find(config.shadowtls_outbounds,name,&NamedShadowTlsOutbound::name);
        if(stls!=config.shadowtls_outbounds.end())return static_cast<std::size_t>(stls-config.shadowtls_outbounds.begin())+base;
        auto tuic=std::ranges::find(config.tuic_outbounds,name,&NamedTuicOutbound::name);
        if(tuic!=config.tuic_outbounds.end())return static_cast<std::size_t>(tuic-config.tuic_outbounds.begin())+base+config.shadowtls_outbounds.size();
        auto masque=std::ranges::find(config.masque_outbounds,name,&NamedMasqueOutbound::name);
        if(masque!=config.masque_outbounds.end())return static_cast<std::size_t>(masque-config.masque_outbounds.begin())+base+config.shadowtls_outbounds.size()+config.tuic_outbounds.size();
        auto wg=std::ranges::find(config.wireguard_outbounds,name,&NamedWireGuardOutbound::name);
        if(wg!=config.wireguard_outbounds.end())return static_cast<std::size_t>(wg-config.wireguard_outbounds.begin())+base+config.shadowtls_outbounds.size()+config.tuic_outbounds.size()+config.masque_outbounds.size();
        auto ssh=std::ranges::find(config.ssh_outbounds,name,&NamedSshOutbound::name);
        if(ssh!=config.ssh_outbounds.end())return static_cast<std::size_t>(ssh-config.ssh_outbounds.begin())+base+config.shadowtls_outbounds.size()+config.tuic_outbounds.size()+config.masque_outbounds.size()+config.wireguard_outbounds.size();
        auto naive=std::ranges::find(config.naive_outbounds,name,&NamedNaiveOutbound::name);
        if(naive!=config.naive_outbounds.end())return static_cast<std::size_t>(naive-config.naive_outbounds.begin())+base+config.shadowtls_outbounds.size()+config.tuic_outbounds.size()+config.masque_outbounds.size()+config.wireguard_outbounds.size()+config.ssh_outbounds.size();
        auto ovpn=std::ranges::find(config.openvpn_outbounds,name,&NamedOpenVpnOutbound::name);
        if(ovpn!=config.openvpn_outbounds.end())return static_cast<std::size_t>(ovpn-config.openvpn_outbounds.begin())+base+config.shadowtls_outbounds.size()+config.tuic_outbounds.size()+config.masque_outbounds.size()+config.wireguard_outbounds.size()+config.ssh_outbounds.size()+config.naive_outbounds.size();
        auto oc=std::ranges::find(config.openconnect_outbounds,name,&NamedOpenConnectOutbound::name);
        if(oc!=config.openconnect_outbounds.end())return static_cast<std::size_t>(oc-config.openconnect_outbounds.begin())+base+config.shadowtls_outbounds.size()+config.tuic_outbounds.size()+config.masque_outbounds.size()+config.wireguard_outbounds.size()+config.ssh_outbounds.size()+config.naive_outbounds.size()+config.openvpn_outbounds.size();
        auto tailscale=std::ranges::find(config.tailscale_outbounds,name,&NamedTailscaleOutbound::name);
        auto tcp_base=config.tunnel_count()+2-config.tcp_proxy_outbounds.size();
        if (tailscale!=config.tailscale_outbounds.end())
            return static_cast<std::size_t>(tailscale-config.tailscale_outbounds.begin())+tcp_base-config.tailscale_outbounds.size();
        auto tcp=std::ranges::find(config.tcp_proxy_outbounds,name,&NamedTcpProxyOutbound::name);
        if (tcp!=config.tcp_proxy_outbounds.end())
            return static_cast<std::size_t>(tcp-config.tcp_proxy_outbounds.begin())+tcp_base;
        return {};
    }

    auto selected_outbound(Config const& config,std::string_view name) noexcept -> std::string_view {
        auto const* group=find_selector(config,name);
        return !group ? name : std::string_view(group->selected_leaf);
    }

    auto outbound_index(Config const& config,std::string_view direct,std::optional<std::string> const& block,
        std::string_view name) -> std::optional<std::size_t> {
        return physical_outbound_index(config,direct,block,selected_outbound(config,name));
    }

    auto configured_outbound_index(Config const& config,std::string_view name) -> std::optional<std::size_t> {
        return outbound_index(config,config.direct_outbound_name,config.block_outbound_name,name);
    }

    namespace {
        auto distribution_index(Config const& config,std::string_view direct,
            std::optional<std::string> const& block,std::string_view name) -> std::optional<std::size_t> {
            auto const* group=find_selector(config,name);
            if (group && group->uses_balance)
                return config.tunnel_count()+2+static_cast<std::size_t>(group-config.selectors.data());
            return outbound_index(config,direct,block,name);
        }

        auto make_outbound_distribution(Config const& config,std::string_view direct,
            std::optional<std::string> const& block) -> std::shared_ptr<rules::OutboundDistribution const> {
            if (std::ranges::none_of(config.selectors,&OutboundSelector::uses_balance)) return {};
            auto result=std::make_shared<rules::OutboundDistribution>(config.tunnel_count()+2,
                std::vector<std::vector<std::size_t>>(config.selectors.size()));
            for (std::size_t index=0;index<config.selectors.size();++index) {
                auto const& group=config.selectors[index];
                if (!group.uses_balance) continue;
                auto& members=result->groups[index];
                if (group.mode==OutboundGroupMode::load_balance) {
                    for (auto const& member:group.members)
                        members.push_back(*distribution_index(config,direct,block,member));
                } else members.push_back(*distribution_index(config,direct,block,group.selected));
            }
            return result;
        }
    }

    auto distributed_outbound_index(Config const& config,std::string_view name) -> std::optional<std::size_t> {
        return distribution_index(config,config.direct_outbound_name,config.block_outbound_name,name);
    }
    auto outbound_distribution(Config const& config) -> std::shared_ptr<rules::OutboundDistribution const> {
        return make_outbound_distribution(config,config.direct_outbound_name,config.block_outbound_name);
    }

    auto bind_outbound_selectors(Config& config,std::string_view direct,std::optional<std::string> const& block)
        -> std::expected<void,std::string> {
        populate_physical_index(config,direct,block);
        config.selector_index.clear();
        config.selector_index.reserve(config.selectors.size());
        for (std::uint32_t index=0;index<config.selectors.size();++index) {
            auto const& selector=config.selectors[index];
            if (config.physical_index.contains(selector.name) ||
                !config.selector_index.emplace(selector.name,index).second)
                return std::unexpected("outbound names must be unique");
        }
        std::vector<policy::DependencyEdge> edges;
        for (std::size_t index=0;index<config.selectors.size();++index) {
            for (auto const& member : config.selectors[index].members) {
                if (auto it=config.selector_index.find(member); it!=config.selector_index.end())
                    edges.push_back({index,it->second});
                else if (!config.physical_index.contains(member))
                    return std::unexpected("unknown selector member: "+member);
            }
        }
        auto order=policy::dependency_order(config.selectors.size(),edges);
        if (!order) return std::unexpected("outbound selector cycle");
        for (auto index : *order) {
            auto& selector=config.selectors[index];
            selector.selected_leaf=selector.selected.empty() ? std::string_view{} : selected_outbound(config,selector.selected);
            auto has_member=[&](bool OutboundSelector::*flag) {
                return std::ranges::any_of(selector.members,[&](auto const& name) {
                    auto const* member=find_selector(config,name);
                    return member && (*member).*flag;
                });
            };
            auto probes=selector.mode==OutboundGroupMode::fallback || selector.mode==OutboundGroupMode::url_test;
            selector.uses_balance=selector.mode==OutboundGroupMode::load_balance || has_member(&OutboundSelector::uses_balance);
            selector.uses_probe=probes || has_member(&OutboundSelector::uses_probe);
            if (probes && selector.uses_balance)
                return std::unexpected("outbound probe groups require deterministically selected members");
        }
        return {};
    }

    auto reselect_outbounds(Config const& running,Config const& requested) -> std::expected<Config,std::string> {
        if (running.selectors.size()!=requested.selectors.size())
            return std::unexpected("selector definitions require restart");
        auto next=running;
        for (auto& selector : next.selectors) {
            auto const* wanted=find_selector(requested,selector.name);
            if (!wanted || wanted->members!=selector.members ||
                wanted->mode!=selector.mode || wanted->probe!=selector.probe)
                return std::unexpected("selector definitions require restart");
            selector.selected=wanted->selected;
        }

        auto const& direct=next.direct_outbound_name;
        auto const& block=next.block_outbound_name;
        if (auto bound=bind_outbound_selectors(next,direct,block); !bound) return std::unexpected(bound.error());
        auto same_detour=[&](auto const& entry) {
            auto const& outbound=[&]() -> auto const& {
                if constexpr (requires { entry.config.connection; }) return entry.config.connection;
                else return entry.config;
            }();
            auto const& name=outbound.detour;
            return !name || selected_outbound(running,*name)==selected_outbound(next,*name);
        };
        auto stable_detours=[&](auto const&... outbounds) {
            return (std::ranges::all_of(outbounds,same_detour) && ...);
        };
        if (!stable_detours(next.vless_outbounds,next.shadowsocks_outbounds,next.trojan_outbounds,
            next.anytls_outbounds,next.hysteria2_outbounds,next.snell_outbounds,next.shadowtls_outbounds,
            next.tuic_outbounds,next.masque_outbounds,next.wireguard_outbounds,next.ssh_outbounds,next.naive_outbounds,next.openvpn_outbounds,next.openconnect_outbounds,next.tcp_proxy_outbounds))
            return std::unexpected("selector change alters a running detour and requires restart");

        auto lookup=[&](std::string_view name) {return *outbound_index(next,direct,block,name);};
        auto action=[](std::size_t index) {
            return index==0 ? RouteAction::direct : index==1 ? RouteAction::block : RouteAction::vless;
        };
        next.default_outbound=lookup(next.default_outbound_name);
        if (next.default_outbound==1) return std::unexpected("default-outbound cannot select block");
        next.default_action=action(next.default_outbound);
        for (auto& route : next.routes) {
            route.outbound=lookup(route.outbound_name);
            route.action=action(route.outbound);
        }
        if (!next.routes.empty()) next.rule_action=next.routes.front().action;
        if (next.ordered_tcp)
            for (auto& rule : next.ordered_tcp->rules)
                if (rule.outbound_name) rule.outbound=lookup(*rule.outbound_name);
        if (auto bound=bind_outbound_dependencies(next,direct,block); !bound)
            return std::unexpected(std::move(bound.error()));
        return next;
    }

    auto bind_outbound_dependencies(Config& config,std::string_view direct,std::optional<std::string> const& block)
        -> std::expected<void,std::string> {
        populate_physical_index(config,direct,block);
        populate_selector_index(config);
        auto group_base=config.tunnel_count()+2;
        auto count=group_base+config.selectors.size();
        auto declared=[&](std::string_view name) -> std::optional<std::size_t> {
            if (auto it=config.selector_index.find(name); it!=config.selector_index.end())
                return group_base+it->second;
            return physical_outbound_index(config,direct,block,name);
        };
        std::vector<policy::DependencyEdge> dependencies;
        for (std::size_t index=0;index<config.selectors.size();++index)
            for (auto const& member : config.selectors[index].members)
                dependencies.push_back({group_base+index,*declared(member)});
        auto bind=[&](auto& outbound,std::size_t index) -> bool {
            if (outbound.detour) {
                auto const* group=find_selector(config,*outbound.detour);
                if (group && (group->uses_probe || group->uses_balance)) return false;
                auto target=outbound_index(config,direct,block,*outbound.detour);
                if (!target || *target==1) return false;
                if (outbound.tcp_options.configured()) return false;
                outbound.detour_index=*target;
                dependencies.push_back({index,*declared(*outbound.detour)});
            }
            if (outbound.bootstrap_index) dependencies.push_back({index,count+*outbound.bootstrap_index});
            return true;
        };
        for (std::size_t i=0;i<config.vless_outbounds.size();++i)
            if (!bind(config.vless_outbounds[i].config,i+2)) return std::unexpected("invalid vless detour or TCP socket settings on a layered node");
        for (std::size_t i=0;i<config.shadowsocks_outbounds.size();++i)
            if (!bind(config.shadowsocks_outbounds[i].config,i+2+config.vless_outbounds.size())) return std::unexpected("invalid shadowsocks detour or TCP socket settings on a layered node");
        for (std::size_t i=0;i<config.trojan_outbounds.size();++i)
            if (!bind(config.trojan_outbounds[i].config,i+2+config.vless_outbounds.size()+config.shadowsocks_outbounds.size())) return std::unexpected("invalid Trojan detour or TCP socket settings on a layered node");
        for (std::size_t i=0;i<config.anytls_outbounds.size();++i)
            if (!bind(config.anytls_outbounds[i].config.connection,i+2+config.vless_outbounds.size()+config.shadowsocks_outbounds.size()+config.trojan_outbounds.size()))
                return std::unexpected("invalid AnyTLS detour or TCP socket settings on a layered node");
        for(std::size_t i=0;i<config.hysteria2_outbounds.size();++i)
            if(!bind(config.hysteria2_outbounds[i].config.connection,i+2+config.vless_outbounds.size()+config.shadowsocks_outbounds.size()+config.trojan_outbounds.size()+config.anytls_outbounds.size()))
                return std::unexpected("invalid Hysteria2 detour or physical UDP socket settings on a layered node");
        for(std::size_t i=0;i<config.snell_outbounds.size();++i)
            if(!bind(config.snell_outbounds[i].config,i+2+config.vless_outbounds.size()+config.shadowsocks_outbounds.size()+config.trojan_outbounds.size()+config.anytls_outbounds.size()+config.hysteria2_outbounds.size()))
                return std::unexpected("invalid Snell detour or TCP socket settings on a layered node");
        auto extra_base=2+config.vless_outbounds.size()+config.shadowsocks_outbounds.size()+config.trojan_outbounds.size()+config.anytls_outbounds.size()+config.hysteria2_outbounds.size()+config.snell_outbounds.size();
        for(std::size_t i=0;i<config.shadowtls_outbounds.size();++i)
            if(!bind(config.shadowtls_outbounds[i].config.connection,i+extra_base))
                return std::unexpected("invalid ShadowTLS detour or TCP socket settings on a layered node");
        for(std::size_t i=0;i<config.tuic_outbounds.size();++i)
            if(!bind(config.tuic_outbounds[i].config,i+extra_base+config.shadowtls_outbounds.size()))
                return std::unexpected("invalid TUIC detour or socket settings on a layered node");
        for(std::size_t i=0;i<config.masque_outbounds.size();++i)
            if(!bind(config.masque_outbounds[i].config,i+extra_base+config.shadowtls_outbounds.size()+config.tuic_outbounds.size()))
                return std::unexpected("invalid MASQUE detour or socket settings on a layered node");
        for(std::size_t i=0;i<config.wireguard_outbounds.size();++i)
            if(!bind(config.wireguard_outbounds[i].config,i+extra_base+config.shadowtls_outbounds.size()+config.tuic_outbounds.size()+config.masque_outbounds.size()))
                return std::unexpected("invalid WireGuard bootstrap or socket settings on a layered node");
        for(std::size_t i=0;i<config.ssh_outbounds.size();++i)
            if(!bind(config.ssh_outbounds[i].config,i+extra_base+config.shadowtls_outbounds.size()+config.tuic_outbounds.size()+config.masque_outbounds.size()+config.wireguard_outbounds.size()))
                return std::unexpected("invalid SSH detour or socket settings on a layered node");
        for(std::size_t i=0;i<config.naive_outbounds.size();++i)
            if(!bind(config.naive_outbounds[i].config,i+extra_base+config.shadowtls_outbounds.size()+config.tuic_outbounds.size()+config.masque_outbounds.size()+config.wireguard_outbounds.size()+config.ssh_outbounds.size()))
                return std::unexpected("invalid NaiveProxy detour or socket settings on a layered node");
        auto vpn_base=extra_base+config.shadowtls_outbounds.size()+config.tuic_outbounds.size()+config.masque_outbounds.size()+config.wireguard_outbounds.size()+config.ssh_outbounds.size()+config.naive_outbounds.size();
        for(std::size_t i=0;i<config.openvpn_outbounds.size();++i)
            if(!bind(config.openvpn_outbounds[i].config,i+vpn_base))
                return std::unexpected("invalid OpenVPN detour or socket settings on a layered node");
        for(std::size_t i=0;i<config.openconnect_outbounds.size();++i)
            if(!bind(config.openconnect_outbounds[i].config,i+vpn_base+config.openvpn_outbounds.size()))
                return std::unexpected("invalid OpenConnect detour or socket settings on a layered node");
        auto tcp_base=group_base-config.tcp_proxy_outbounds.size();
        for (std::size_t index=0;index<config.tcp_proxy_outbounds.size();++index) {
            auto& outbound=config.tcp_proxy_outbounds[index].config;
            if (!bind(outbound,tcp_base+index))
                return std::unexpected("invalid TCP proxy detour or socket settings on a layered node");
            if (outbound.udp && outbound.protocol!=TcpProxyProtocol::http_connect && outbound.detour_index.value_or(0))
                return std::unexpected("SOCKS5 UDP requires a physical or direct detour outbound");
        }
        auto packet_capable=[&](std::string_view name) {
            name=selected_outbound(config,name);
            auto proxy=std::ranges::find(config.tcp_proxy_outbounds,name,&NamedTcpProxyOutbound::name);
            if (proxy!=config.tcp_proxy_outbounds.end()) return proxy->config.udp;
            if (std::ranges::find(config.shadowtls_outbounds,name,&NamedShadowTlsOutbound::name)!=config.shadowtls_outbounds.end() ||
                std::ranges::find(config.ssh_outbounds,name,&NamedSshOutbound::name)!=config.ssh_outbounds.end() ||
                std::ranges::find(config.naive_outbounds,name,&NamedNaiveOutbound::name)!=config.naive_outbounds.end())
                return false;
            auto ss=std::ranges::find(config.shadowsocks_outbounds,name,&NamedShadowsocksOutbound::name);
            if (ss!=config.shadowsocks_outbounds.end())return ss->config.udp_over_tcp || ss->config.udp_native;
            auto hy2=std::ranges::find(config.hysteria2_outbounds,name,&NamedHysteria2Outbound::name);
            return hy2==config.hysteria2_outbounds.end() || hy2->config.transport.udp;
        };
        for(auto const& entry:config.tcp_proxy_outbounds)
            if(entry.config.udp && entry.config.protocol==TcpProxyProtocol::http_connect && entry.config.detour && !packet_capable(*entry.config.detour))
                return std::unexpected("HTTP CONNECT-UDP detour requires a datagram-capable outbound");
        for(auto const& entry:config.naive_outbounds)
            if(entry.config.protocol==NaiveProtocol::h3 && entry.config.detour && !packet_capable(*entry.config.detour))
                return std::unexpected("NaiveProxy H3 detour requires a datagram-capable outbound");
        for(auto const& entry:config.shadowsocks_outbounds)
            if(entry.config.udp_native && entry.config.detour && !packet_capable(*entry.config.detour))
                return std::unexpected("Shadowsocks native UDP detour requires a datagram-capable outbound");
        for(auto const& entry:config.tuic_outbounds)
            if(entry.config.detour && !packet_capable(*entry.config.detour))
                return std::unexpected("TUIC detour requires a datagram-capable outbound");
        for(auto const& entry:config.masque_outbounds)
            if(entry.config.detour && !packet_capable(*entry.config.detour))
                return std::unexpected("MASQUE detour requires a datagram-capable outbound");
        if (config.dns) {
            auto distribution=make_outbound_distribution(config,direct,block);
            for (std::size_t i=0;i<config.dns->servers.size();++i) {
                auto& upstream=config.dns->servers[i].upstream;
                if (!upstream) continue;
                if (upstream->resolver) dependencies.push_back({count+i,count+*upstream->resolver});
                if (!upstream->detour) continue;
                auto group=std::ranges::find(config.selectors,*upstream->detour,&OutboundSelector::name);
                upstream->detour_group=group!=config.selectors.end();
                bool packets=upstream->tls ?
                    (upstream->tls->transport==DnsSecurity::quic || upstream->tls->transport==DnsSecurity::https3) :
                    !upstream->tcp;
                auto validate=[&](std::string_view name) -> std::expected<std::size_t,std::string> {
                    auto target=outbound_index(config,direct,block,name);
                    if (!target || *target==1)
                        return std::unexpected("encrypted DNS detour must name a direct or proxy outbound");
                    if (packets && !packet_capable(name))
                        return std::unexpected("DNS over QUIC/UDP detour requires a datagram-capable outbound");
                    return *target;
                };
                auto target=validate(*upstream->detour);
                if (!target) return std::unexpected(std::move(target.error()));
                if (upstream->detour_group && (group->uses_probe || group->uses_balance)) {
                    std::vector<bool> visited(config.selectors.size());
                    auto all_members=[&](auto&& self,std::string_view name) -> std::expected<void,std::string> {
                        auto nested=std::ranges::find(config.selectors,name,&OutboundSelector::name);
                        if (nested==config.selectors.end()) {
                            auto result=validate(name);
                            if (!result) return std::unexpected(std::move(result.error()));
                        } else {
                            auto index=static_cast<std::size_t>(nested-config.selectors.begin());
                            if (visited[index]) return {};
                            visited[index]=true;
                            for (auto const& member:nested->members)
                                if (auto result=self(self,member); !result) return result;
                        }
                        return {};
                    };
                    if (auto result=all_members(all_members,*upstream->detour); !result) return result;
                }
                if (upstream->detour_group && group->uses_balance) {
                    std::string formatted;
                    auto host=std::string_view(upstream->host);
                    if (host.empty()) {
                        auto address=platform::format_ip_address(
                            std::span(upstream->address).first(upstream->ipv6 ? 16u : 4u));
                        if (!address) return std::unexpected("cannot format DNS upstream target");
                        formatted=std::move(*address);
                        host=formatted;
                    }
                    target=distribution->choose(*distribution_index(config,direct,block,*upstream->detour),host);
                }
                dependencies.push_back({count+i,*declared(*upstream->detour)});
                upstream->detour_index=*target ? std::optional(*target) : std::nullopt;
            }
        }
        auto nodes=count;
        if (config.dns) {
            auto const& dns=*config.dns;
            auto view_base=count+dns.servers.size();
            nodes=view_base+dns.views.size();
            for (std::size_t i=0;i<dns.views.size();++i) {
                dependencies.push_back({view_base+i,count+dns.views[i].final});
                for (auto const& rule:dns.rules)
                    if (rule.action==policy::DnsAction::route || rule.action==policy::DnsAction::evaluate)
                        dependencies.push_back({view_base+i,count+rule.server});
            }
        }
        if (!policy::dependency_order(nodes,dependencies))
            return std::unexpected("outbound or DNS dependency cycle (detour, DNS server or policy view)");
        std::vector<policy::DependencyEdge> inbound_edges;
        for (std::size_t i=0;i<config.inbounds.size();++i) {
            auto const& detour=config.inbounds[i].listen.detour;
            if (!detour) continue;
            auto target=std::ranges::find(config.inbounds,*detour,&InboundConfig::name);
            if (target==config.inbounds.end())
                return std::unexpected("unknown inbound detour target: "+*detour);
            auto idx=static_cast<std::size_t>(target-config.inbounds.begin());
            if (idx==i) return std::unexpected("inbound cannot detour to itself: "+*detour);
            if (target->type==Inbound::tun)
                return std::unexpected("inbound detour target cannot be a TUN inbound: "+*detour);
            config.inbounds[i].detour_index=idx;
            inbound_edges.push_back({i,idx});
        }
        if (!inbound_edges.empty() && !policy::dependency_order(config.inbounds.size(),inbound_edges))
            return std::unexpected("inbound detour cycle");
        auto check_cert_provider = [&](std::string_view provider) -> std::expected<void, std::string> {
            if (provider.empty()) return {};
            if (provider != "acme" || !config.services.acme.has_value())
                return std::unexpected("TLS certificate-provider references unconfigured ACME service: " + std::string(provider));
            return {};
        };
        auto check_quic_tls = [&](std::string_view kind, std::string_view provider,
            std::vector<std::string> const& alpn) -> std::expected<void, std::string> {
            if (auto ok = check_cert_provider(provider); !ok) return ok;
            if (!alpn.empty()) return std::unexpected(std::string(kind) + " inbound does not support custom TLS alpn");
            return {};
        };
        for (auto const& in : config.inbounds) {
            if (in.vless) {
                if (auto ok = check_cert_provider(in.vless->certificate_provider); !ok) return ok;
                if (in.vless->xhttp && in.vless->xhttp->endpoint.version == xhttp::HttpVersion::http3 && !in.vless->ech_key_file.empty())
                    return std::unexpected("VLESS XHTTP HTTP/3 inbound does not support TLS ech-key-file");
            }
            if (in.trojan) { if (auto ok = check_cert_provider(in.trojan->certificate_provider); !ok) return ok; }
            if (in.anytls) { if (auto ok = check_cert_provider(in.anytls->certificate_provider); !ok) return ok; }
            if (in.hysteria2) {
                auto const& cp = !in.hysteria2->certificate_provider.empty() ? in.hysteria2->certificate_provider : in.hysteria2->connection.certificate_provider;
                auto const& alpn = !in.hysteria2->alpn.empty() ? in.hysteria2->alpn : in.hysteria2->connection.alpn;
                if (auto ok = check_quic_tls("Hysteria2", cp, alpn); !ok) return ok;
            }
            if (in.tuic) {
                if (auto ok = check_quic_tls("TUIC", in.tuic->certificate_provider, in.tuic->alpn); !ok) return ok;
            }
            if (in.masque) {
                if (auto ok = check_quic_tls("MASQUE", in.masque->certificate_provider, in.masque->alpn); !ok) return ok;
            }
            if (in.http) {
                if (auto ok = check_cert_provider(in.http->certificate_provider); !ok) return ok;
                if (in.http->has_tls && in.http->http3 && !in.http->ech_key_file.empty())
                    return std::unexpected("HTTP/3 inbound does not support TLS ech-key-file");
            }
            if (in.naive) {
                if (auto ok = check_cert_provider(in.naive->certificate_provider); !ok) return ok;
                if (in.naive->protocol != NaiveProtocol::h2 && !in.naive->ech_key_file.empty())
                    return std::unexpected("NaiveProxy HTTP/3 inbound does not support TLS ech-key-file");
            }
        }
        return {};
    }
}
