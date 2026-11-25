export module platform.network_selection;
import std;
import containers.inplace_vector;
import platform.network_state;
import platform.socket_options;

export namespace platform::network {
    // The declared type is local policy. Route suitability and link state
    // come from the retained snapshot of the same namespace as the dials.
    [[nodiscard]] auto select_interfaces(Snapshot const& snapshot,Policy const& policy,bool ipv6,
        std::span<std::uint8_t const> explicit_source={}) noexcept -> InterfaceCandidates {
        namespace abi=platform::network::constants;
        auto family=ipv6 ? abi::af_inet6 : abi::af_inet;
        using Candidate=std::tuple<unsigned,std::uint32_t,std::size_t,std::uint32_t>;
        containers::inplace_vector<Candidate,16> ranked;
        for (std::size_t i=0;i<policy.interfaces.size();++i) {
            auto const& allowed=policy.interfaces[i];
            unsigned tier=0;
            if (allowed.type!=policy.preferred) {
                if (policy.strategy==Strategy::require) continue;
                if (policy.fallback && allowed.type==*policy.fallback) tier=1;
                else if (policy.strategy==Strategy::fallback) tier=2;
                else continue;
            }
            auto link=std::ranges::find(snapshot.links,allowed.name,&Link::name);
            if (link==snapshot.links.end() || !link->up() || !link->carrier()) continue;
            auto addressed=std::ranges::any_of(snapshot.addresses,[&](auto const& address) {
                return address.index==link->index && address.family==family && address.scope==abi::rt_scope_universe &&
                    address.usable() && (explicit_source.empty() ||
                        std::ranges::equal(explicit_source,std::span(address.local).first(ipv6 ? 16 : 4)));
            });
            if (!addressed) continue;
            std::optional<std::uint32_t> metric;
            for (auto const& route:snapshot.routes) {
                if (route.family!=family || route.index!=link->index || route.multiple_hops ||
                    route.table!=abi::rt_table_main || route.type!=abi::rtn_unicast ||
                    (route.flags&abi::rtnh_f_linkdown) || !route.default_route()) continue;
                if (!metric || route.priority<*metric) metric=route.priority;
            }
            if (metric) (void)ranked.try_emplace_back(tier,*metric,i,link->index);
        }
        std::ranges::sort(ranked);
        InterfaceCandidates result{
            .fallback_delay=policy.fallback_delay,
            .parallel_fallback=policy.strategy==Strategy::fallback,
        };
        for (auto const& candidate:ranked) {
            result.indices.push_back(std::get<3>(candidate));
            result.tiers.push_back(static_cast<std::uint8_t>(std::get<0>(candidate)));
        }
        return result;
    }

    class SystemInterfaceSelection {
        std::shared_ptr<Monitor const> monitor_;
        Policy policy_;
        std::optional<std::array<std::uint8_t,4>> ipv4_;
        std::optional<std::array<std::uint8_t,16>> ipv6_;
        std::shared_ptr<FallbackMemory> memory_;
    public:
        SystemInterfaceSelection(std::shared_ptr<Monitor const> monitor,Policy policy,SocketBinding const& binding)
            : monitor_(std::move(monitor)),policy_(std::move(policy)),ipv4_(binding.inet4_bind_address),
              ipv6_(binding.inet6_bind_address),memory_(std::make_shared<FallbackMemory>()) {}
        [[nodiscard]] auto operator()(bool ipv6) const noexcept -> InterfaceCandidates {
            auto view=monitor_->get();
            if (!view) return {};
            std::span<std::uint8_t const> source;
            if (ipv6 && ipv6_) source=*ipv6_;
            else if (!ipv6 && ipv4_) source=*ipv4_;
            auto result=select_interfaces(*view,policy_,ipv6,source);
            result.fallback_memory=memory_;
            if (result.parallel_fallback && result.indices.size()>=2 && memory_) {
                auto now_ms=std::chrono::duration_cast<std::chrono::milliseconds>(
                    Clock::now().time_since_epoch()).count();
                if (memory_->is_degraded(result.indices.front(),now_ms,ipv6)) {
                    std::rotate(result.indices.begin(),result.indices.begin()+1,result.indices.end());
                    if (result.tiers.size()==result.indices.size())
                        std::rotate(result.tiers.begin(),result.tiers.begin()+1,result.tiers.end());
                }
            }
            return result;
        }
    };
}
