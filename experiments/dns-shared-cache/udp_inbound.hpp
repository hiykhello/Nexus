// Private to the command process. One executor owns all UDP listener state.
#pragma once
#include "shadowsocks_udp_dns.hpp"

namespace {
    namespace udp_io=shadowsocks::detail::udp_io;
    auto udp_dns_config(config::Config const& config) -> relay::DnsRouting {
        relay::DnsRouting result;
        if (config.dns) {
            auto const& dns=*config.dns; result.final=dns.final; result.disable_cache=dns.disable_cache; result.edns=dns.edns;
            switch (dns.strategy) {
            case config::DnsStrategy::automatic: break;
            case config::DnsStrategy::prefer_ipv4: result.strategy=relay::DnsStrategy::prefer_ipv4; break;
            case config::DnsStrategy::prefer_ipv6: result.strategy=relay::DnsStrategy::prefer_ipv6; break;
            case config::DnsStrategy::ipv4_only: result.strategy=relay::DnsStrategy::ipv4_only; break;
            case config::DnsStrategy::ipv6_only: result.strategy=relay::DnsStrategy::ipv6_only; break;
            }
            for (auto const& server:dns.servers) {
                relay::DnsServer entry;
                if (server.upstream) { auto const& up=*server.upstream;
                    entry={up.address,up.ipv6,up.port,up.tcp,up.host,up.resolver}; }
                result.servers.push_back(std::move(entry));
            }
            for (auto const& rule:dns.rules) result.rules.push_back(rule);
        } else if (config.dns_upstream) {
            auto const& up=*config.dns_upstream;
            result.servers.push_back({up.address,up.ipv6,up.port,up.tcp,up.host,up.resolver});
        } else result.servers.push_back({});
        return result;
    }
    class UdpInbounds {
        using State=shadowsocks::detail::UdpListenerState;
        using Listener=shadowsocks::detail::UdpListener;
        struct Group { State* state; containers::inplace_vector<udp_io::endpoint,16> endpoints; };
#ifdef NEXUS_DNS_USE_MODULES
        udp_io::io_context context_{udp_io::make_io_context(udp_io::has_uring)};
#elif BOOST_COROSIO_HAVE_LIBURING
        udp_io::io_context context_{udp_io::uring};
#else
        udp_io::io_context context_;
#endif
        shadowsocks::detail::UdpListenerRegistry registry_{64};
        std::vector<Group> groups_;
#ifdef NEXUS_TEST_DNS_GROUP
        dns_hp_experiment::GroupSnapshot* group_=nullptr;
        std::size_t group_index_=0,reader_index_=0;
        std::optional<dns_hp_experiment::GroupBinding> cache_;
        std::optional<dns_hp_experiment::GroupSnapshot::Reader> reader_;
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
        dns::detail::RefreshBudget* refresh_budget_=nullptr;
        std::optional<shadowsocks::detail::UdpDnsRefresh> refresh_;
#endif
#ifdef NEXUS_TEST_DNS_COORDINATOR
        dns_hp_experiment::Coordinator* coordinator_=nullptr;
        dns_hp_experiment::ViewRegistry* view_registry_=nullptr;
        std::vector<dns_hp_experiment::ViewRegistry::Profile> profiles_;
        std::optional<dns_hp_experiment::ViewBinding> views_;
        std::optional<dns_hp_experiment::CoordinatorOwner> owner_;
        bool optimistic_=false;
#endif
#else
        std::optional<dns::AddressCache> cache_;
#endif
        std::vector<std::unique_ptr<Listener>> listeners_;
    public:
        UdpInbounds()=default;
        UdpInbounds(UdpInbounds const&)=delete;
        auto operator=(UdpInbounds const&) -> UdpInbounds& = delete;
        ~UdpInbounds() { stop(); }
#ifdef NEXUS_TEST_DNS_GROUP
        [[nodiscard]] auto set_dns_group_for_test(dns_hp_experiment::GroupSnapshot& owner,std::size_t group,std::size_t reader
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
            ,dns::detail::RefreshBudget* budget=nullptr
#endif
            ) -> bool {
            if (cache_ || !owner.supports_binding(group,reader,1)) return false;
            group_=&owner; group_index_=group; reader_index_=reader;
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
            refresh_budget_=budget;
#endif
            return true;
        }
#ifdef NEXUS_TEST_DNS_COORDINATOR
        [[nodiscard]] auto set_dns_coordinator_for_test(dns_hp_experiment::Coordinator& coordinator,
            dns_hp_experiment::ViewRegistry& registry,relay::DnsRouting const& routing,bool optimistic=false) -> bool {
            if (cache_ || !group_) return false;
            try {
                std::vector<dns_hp_experiment::ViewRegistry::Profile> profiles;
                profiles.reserve(routing.servers.size());
                for (std::size_t index=0;index<routing.servers.size();++index) {
                    auto profile=registry.register_profile(routing,index); if (!profile) return false;
                    profiles.push_back(*profile);
                }
                coordinator_=&coordinator; view_registry_=&registry; profiles_=std::move(profiles); optimistic_=optimistic;
                return true;
            } catch (std::bad_alloc const&) { return false; }
        }
#endif
#endif
        [[nodiscard]] auto add(std::span<std::uint8_t const> key,std::uint16_t port,::rules::RouteMatcher const& policy)
            -> std::expected<void,std::string> {
            if (cache_ || !port) return std::unexpected("invalid UDP listener state");
            auto* state=registry_.find(key);
            if (!state) {
                auto created=registry_.add(key,policy);
                if (!created) return std::unexpected("cannot create UDP key owner");
                state=*created;
                groups_.push_back({state,{}});
            }
            auto group=std::ranges::find(groups_,state,&Group::state);
            if (group==groups_.end() || group->endpoints.size()>=16) return std::unexpected("too many UDP listeners for one key");
            group->endpoints.emplace_back(udp_io::ipv4_address::loopback(),port);
            return {};
        }
        [[nodiscard]] auto start(relay::DnsRouting const& routing) -> std::error_code {
            if (cache_) return std::make_error_code(std::errc::operation_in_progress);
            auto config=relay::detail::udp_dns_config(routing);
            if (!config) return config.error();
#ifdef NEXUS_TEST_DNS_COORDINATOR
            if (!coordinator_ || !view_registry_ || !view_registry_->sealed() || profiles_.size()!=routing.servers.size())
                return std::make_error_code(std::errc::invalid_argument);
            for (std::size_t index=0;index<profiles_.size();++index) {
                auto valid=view_registry_->matches(profiles_[index],routing,index);
                if (!valid || !*valid) return std::make_error_code(std::errc::invalid_argument);
            }
#endif
            // All groups run on context_ with this same routing snapshot. A
            // fresh cache per start prevents view IDs from crossing reloads.
            auto unused=udp_io::endpoint(udp_io::ipv4_address::loopback(),0);
            try {
#ifdef NEXUS_TEST_DNS_GROUP
                if (!group_ || !group_->supports_binding(group_index_,reader_index_,1))
                    return std::make_error_code(std::errc::invalid_argument);
                cache_.emplace(*group_,group_index_); reader_.emplace(group_->reader(reader_index_));
#ifdef NEXUS_TEST_DNS_COORDINATOR
                views_.emplace(*view_registry_,profiles_); owner_.emplace(context_,*cache_,*coordinator_);
#endif
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
                if (refresh_budget_) refresh_.emplace(context_,*cache_,refresh_budget_->limit(),
                    std::chrono::seconds(5),std::chrono::seconds(1),refresh_budget_);
#endif
#else
                cache_.emplace(256);
#endif
                for (auto const& group:groups_) {
                    listeners_.push_back(std::make_unique<Listener>(context_,*group.state,unused,64,std::chrono::milliseconds(5),config->options,config->routing,&*cache_
#ifdef NEXUS_TEST_DNS_GROUP
                        ,&*reader_
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
                        ,refresh_ ? &*refresh_ : nullptr
#endif
#ifdef NEXUS_TEST_DNS_COORDINATOR
                        ,&*owner_,&*views_,optimistic_
#endif
#endif
                    ));
                    if (auto error=listeners_.back()->start(group.endpoints)) { stop(); return error; }
                }
            } catch (...) { stop(); throw; }
            return {};
        }
        auto poll(std::chrono::milliseconds wait) -> void {
            if (listeners_.empty()) return;
            context_.restart();
            if (wait <= std::chrono::milliseconds::zero()) (void)context_.poll();
            else (void)context_.run_for(wait);
        }
        [[nodiscard]] auto healthy() const noexcept -> bool {
            return std::ranges::all_of(listeners_,[](auto const& listener) { return listener->running(); });
        }
        [[nodiscard]] auto empty() const noexcept -> bool { return groups_.empty(); }
        auto stop() noexcept -> void {
            for (auto& listener:listeners_) listener->stop();
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
            if (refresh_) refresh_->stop();
#endif
#ifdef NEXUS_TEST_DNS_COORDINATOR
            if (owner_) owner_->stop();
#endif
            if (!listeners_.empty()) { context_.restart(); (void)context_.run(); }
            listeners_.clear();
#ifdef NEXUS_TEST_DNS_GROUP
#ifdef NEXUS_TEST_DNS_COORDINATOR
            if (owner_ && !owner_->drained()) std::terminate();
            owner_.reset(); views_.reset();
#endif
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
            if (refresh_ && !refresh_->drained()) std::terminate();
            refresh_.reset();
#endif
            reader_.reset();
#endif
            cache_.reset();
        }
    };
}
