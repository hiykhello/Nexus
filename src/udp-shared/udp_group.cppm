export module ss_udp.shared_cache;
import std;
import relay;
export import dns.shared_cache;
export import ss_udp.inbounds;

export namespace relay::udp_runtime {
    // Executor-local membership in a configuration generation.
    // Group, reader and refresh owner outlive every query, including cancellation.
    template<bool EnableRefresh>
    class BasicGroupCacheSetup {
        dns_hp_experiment::GroupSnapshot* group_=nullptr;
        std::size_t group_index_=0,reader_index_=0;
        std::optional<dns_hp_experiment::GroupBinding> cache_;
        std::optional<dns_hp_experiment::GroupSnapshot::Reader> reader_;
        using GroupRefresh=dns::detail::BasicRefreshOwner<dns_hp_experiment::GroupBinding>;
        struct NoRefresh {};
        struct WithRefresh { dns::detail::RefreshBudget* budget=nullptr; std::optional<GroupRefresh> owner; };
        [[no_unique_address]] std::conditional_t<EnableRefresh,WithRefresh,NoRefresh> refresh_;
    public:
        using Lookup=shadowsocks::detail::UdpCachedLookup<dns_hp_experiment::GroupBinding,EnableRefresh>;
        [[nodiscard]] auto active() const noexcept -> bool { return cache_.has_value(); }
        [[nodiscard]] auto configured() const noexcept -> bool { return group_!=nullptr; }
        [[nodiscard]] auto bind(dns_hp_experiment::GroupSnapshot& owner,std::size_t group,std::size_t reader,
                                                 dns::detail::RefreshBudget* budget=nullptr) -> bool {
            if (active() || !owner.supports_binding(group,reader,1)) return false;
            if constexpr (!EnableRefresh) { if (budget) return false; }
            else refresh_.budget=budget;
            group_=&owner; group_index_=group; reader_index_=reader;
            return true;
        }
        [[nodiscard]] auto start(udp_io::io_context& context,DnsRouting const&) -> std::error_code {
            if (!group_ || !group_->supports_binding(group_index_,reader_index_,1))
                return std::make_error_code(std::errc::invalid_argument);
            cache_.emplace(*group_,group_index_);
            reader_.emplace(group_->reader(reader_index_));
            if constexpr (EnableRefresh) if (refresh_.budget) refresh_.owner.emplace(context,*cache_,refresh_.budget->limit(),
                std::chrono::seconds(5),std::chrono::seconds(1),refresh_.budget);
            return {};
        }
        [[nodiscard]] auto cache() noexcept -> Lookup::Cache& { return *cache_; }
        [[nodiscard]] auto reader() noexcept -> Lookup::Reader* { return &*reader_; }
        [[nodiscard]] auto extra() noexcept -> Lookup::Extra {
            if constexpr (EnableRefresh) return {refresh_.owner ? &*refresh_.owner : nullptr};
            else return {};
        }
        auto stop_begin() noexcept -> void { if constexpr (EnableRefresh) if (refresh_.owner) refresh_.owner->stop(); }
        [[nodiscard]] auto drained() const noexcept -> bool {
            if constexpr (EnableRefresh) return !refresh_.owner || refresh_.owner->drained();
            else return true;
        }
        auto stop_end() noexcept -> void {
            if constexpr (EnableRefresh) {
                if (refresh_.owner && !refresh_.owner->drained()) std::terminate();
                refresh_.owner.reset();
            }
            reader_.reset(); cache_.reset();
        }
    };
    using GroupCacheSetup=BasicGroupCacheSetup<false>;
    using GroupRefreshCacheSetup=BasicGroupCacheSetup<true>;
    using GroupUdpInbounds=BasicUdpInbounds<GroupCacheSetup>;
    using GroupRefreshUdpInbounds=BasicUdpInbounds<GroupRefreshCacheSetup>;
}
