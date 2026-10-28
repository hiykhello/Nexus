// Private to the command process. One executor owns all UDP listener state.
#pragma once
#include "../proxy/shadowsocks_udp_dns.hpp"

namespace {
    auto udp_dns_config(nexus::config::Config const& config) -> nexus::proxy::DnsRouting {
        nexus::proxy::DnsRouting result;
        if (config.dns) {
            auto const& dns=*config.dns; result.final=dns.final; result.disable_cache=dns.disable_cache; result.edns=dns.edns;
            switch (dns.strategy) {
            case nexus::config::DnsStrategy::automatic: break;
            case nexus::config::DnsStrategy::prefer_ipv4: result.strategy=nexus::proxy::DnsStrategy::prefer_ipv4; break;
            case nexus::config::DnsStrategy::prefer_ipv6: result.strategy=nexus::proxy::DnsStrategy::prefer_ipv6; break;
            case nexus::config::DnsStrategy::ipv4_only: result.strategy=nexus::proxy::DnsStrategy::ipv4_only; break;
            case nexus::config::DnsStrategy::ipv6_only: result.strategy=nexus::proxy::DnsStrategy::ipv6_only; break;
            }
            for (auto const& server:dns.servers) {
                nexus::proxy::DnsServer entry;
                if (server.upstream) { auto const& up=*server.upstream;
                    entry={up.address,up.ipv6,up.port,up.tcp,up.host,up.resolver}; }
                result.servers.push_back(std::move(entry));
            }
            for (auto const& rule:dns.rules) result.rules.push_back({rule.domain,rule.suffix,rule.server});
        } else if (config.dns_upstream) {
            auto const& up=*config.dns_upstream;
            result.servers.push_back({up.address,up.ipv6,up.port,up.tcp,up.host,up.resolver});
        } else result.servers.push_back({});
        return result;
    }
    class UdpInbounds {
        using State=nexus::shadowsocks::detail::UdpListenerState;
        using Listener=nexus::shadowsocks::detail::UdpListener;
        struct Group { State* state; std::inplace_vector<boost::corosio::endpoint,16> endpoints; };
#if BOOST_COROSIO_HAVE_LIBURING
        boost::corosio::io_context context_{boost::corosio::uring};
#else
        boost::corosio::io_context context_;
#endif
        nexus::shadowsocks::detail::UdpListenerRegistry registry_{64};
        std::vector<Group> groups_;
        std::vector<std::unique_ptr<Listener>> listeners_;
    public:
        UdpInbounds()=default;
        UdpInbounds(UdpInbounds const&)=delete;
        auto operator=(UdpInbounds const&) -> UdpInbounds& = delete;
        ~UdpInbounds() { stop(); }
        [[nodiscard]] auto add(std::span<std::uint8_t const> key,std::uint16_t port,nexus::rules::RouteMatcher const& policy)
            -> std::expected<void,std::string> {
            if (!listeners_.empty() || !port) return std::unexpected("invalid UDP listener state");
            auto* state=registry_.find(key);
            if (!state) {
                auto created=registry_.add(key,policy);
                if (!created) return std::unexpected("cannot create UDP key owner");
                state=*created;
                groups_.push_back({state,{}});
            }
            auto group=std::ranges::find(groups_,state,&Group::state);
            if (group==groups_.end() || group->endpoints.size()>=16) return std::unexpected("too many UDP listeners for one key");
            group->endpoints.emplace_back(boost::corosio::ipv4_address::loopback(),port);
            return {};
        }
        [[nodiscard]] auto start(nexus::proxy::DnsRouting const& routing) -> std::error_code {
            auto config=nexus::proxy::detail::udp_dns_config(routing);
            if (!config) return config.error();
            auto unused=boost::corosio::endpoint(boost::corosio::ipv4_address::loopback(),0);
            for (auto const& group:groups_) {
                listeners_.push_back(std::make_unique<Listener>(context_,*group.state,unused,64,std::chrono::milliseconds(5),config->options,config->routing));
                if (auto error=listeners_.back()->start(group.endpoints)) { stop(); return error; }
            }
            return {};
        }
        auto poll(std::chrono::milliseconds wait) -> void {
            if (listeners_.empty()) return;
            context_.restart(); (void)context_.run_for(wait);
        }
        [[nodiscard]] auto healthy() const noexcept -> bool {
            return std::ranges::all_of(listeners_,[](auto const& listener) { return listener->running(); });
        }
        [[nodiscard]] auto empty() const noexcept -> bool { return groups_.empty(); }
        auto stop() noexcept -> void {
            for (auto& listener:listeners_) listener->stop();
            if (!listeners_.empty()) { context_.restart(); (void)context_.run(); }
            listeners_.clear();
        }
    };
}
