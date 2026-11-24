module relay.dns_state;
import std;
import relay.dns_backend;
import dns.corosio_cached;
import corosio;

#ifdef NEXUS_TEST_GROUP_REFRESH_CONSTRUCT_FAULT
extern "C" void nexus_test_group_refresh_construct();
#endif

namespace relay {
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
    using GroupRefresh=dns::detail::BasicRefreshOwner<dns_hp_experiment::GroupBinding>;
    auto make_group_refresh(corosio::io_context& context,dns_hp_experiment::GroupBinding& cache,
                            dns::detail::RefreshBudget& budget) -> void* {
#ifdef NEXUS_TEST_GROUP_REFRESH_CONSTRUCT_FAULT
        nexus_test_group_refresh_construct();
#endif
        return new GroupRefresh(context,cache,budget.limit(),std::chrono::seconds(5),std::chrono::seconds(1),&budget);
    }
    auto stop_group_refresh(void* owner) noexcept -> void { static_cast<GroupRefresh*>(owner)->stop(); }
    auto group_refresh_drained(void* owner) noexcept -> bool { return static_cast<GroupRefresh*>(owner)->drained(); }
    auto GroupRefreshDeleter::operator()(void* owner) const noexcept -> void {
        auto* refresh=static_cast<GroupRefresh*>(owner);
        if (!refresh->drained()) std::terminate();
        delete refresh;
    }
#endif
}
