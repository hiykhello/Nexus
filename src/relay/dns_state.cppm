export module relay.dns_state;
import std;
import relay.dns_backend;
import relay.dns_routing;
import dns.message_cache;
import corosio;
#ifdef NEXUS_TEST_DNS_OWNER
extern "C" void nexus_test_dns_owner_destroy();
#endif

export namespace relay {
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
    struct GroupRefreshDeleter { auto operator()(void*) const noexcept -> void; };
    auto make_group_refresh(corosio::io_context&,dns_hp_experiment::GroupBinding&,dns::detail::RefreshBudget&) -> void*;
    auto stop_group_refresh(void*) noexcept -> void;
    [[nodiscard]] auto group_refresh_drained(void*) noexcept -> bool;
#endif
    // Workers borrow the root server's cache, which outlives their shutdown.
    struct DnsState {
        DnsRouting routing;
        std::shared_ptr<dns::MessageCache> message_cache;
#ifdef NEXUS_DNS_RESPONSE
        bool has_response_program=policy::dns_has_response_program(routing.rules);
#endif
        policy::DnsContextRequirements context=policy::dns_context_requirements(routing.rules);
#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_GROUP)
        dns_hp_experiment::GroupBinding cache;
        std::optional<dns_hp_experiment::GroupSnapshot::Reader> reader;
#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_COORDINATOR)
        std::optional<dns_hp_experiment::ViewBinding> views;
#ifdef NEXUS_DNS_SHARED
        std::optional<dns_hp_experiment::LocalViewBinding> local_views;
#endif
        std::optional<dns_hp_experiment::CoordinatorOwner> coordinator;
#ifdef NEXUS_DNS_SHARED
#ifdef NEXUS_DNS_RESPONSE
        std::optional<dns_hp_experiment::ResponseCoordinatorOwner> response_coordinator;
#endif
#endif
        bool optimistic=false;
#endif
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
        std::unique_ptr<void,GroupRefreshDeleter> refresh;
#endif
        inline DnsState(DnsRouting value,dns_hp_experiment::GroupSnapshot& shared,std::size_t group,
                        std::optional<std::size_t> reader_index)
            : routing(std::move(value)),cache(shared,group) {
            if (reader_index) reader.emplace(shared.reader(*reader_index));
        }
#else
        std::unique_ptr<dns::AddressCache> cache_owner;
        dns::AddressCache& cache;
#ifdef NEXUS_TEST_DNS_SNAPSHOT
        std::optional<dns::AddressCache::Reader> reader;
        inline explicit DnsState(DnsRouting value,dns::AddressCache* shared=nullptr,
                                 std::size_t reader_count=1,std::optional<std::size_t> reader_index=0)
            : routing(std::move(value)), cache_owner(shared ? nullptr : std::make_unique<dns::AddressCache>(256,0,true,reader_count)),
              cache(shared ? *shared : *cache_owner) {
            if (reader_index) reader.emplace(cache.reader(*reader_index));
        }
#else
        inline explicit DnsState(DnsRouting value, dns::AddressCache* shared=nullptr)
            : routing(std::move(value)), cache_owner(shared ? nullptr : std::make_unique<dns::AddressCache>(256,0,
#ifdef NEXUS_TEST_DNS_PER_WORKER
                false
#else
                true
#endif
            )), cache(shared ? *shared : *cache_owner) {}
#endif
#endif
#ifdef NEXUS_TEST_DNS_OWNER
        ~DnsState() { nexus_test_dns_owner_destroy(); }
#endif
        inline auto select(std::string_view domain,std::uint16_t type,policy::DnsContext const& input={}) const noexcept -> policy::DnsDecision {
            return policy::select_question_dns_action(routing.rules,domain,type,routing.final,routing.disable_cache,input);
        }
        inline auto wire_cache() -> dns::MessageCache* {
            if (!message_cache)
                message_cache=std::make_shared<dns::MessageCache>(std::chrono::seconds(routing.optimistic_cache_seconds));
            return message_cache.get();
        }
        inline auto stop_message_refresh() noexcept -> void {
            if (message_cache) message_cache->stop_refreshes();
        }
        inline auto endpoint(std::size_t index) const -> corosio::endpoint {
            auto const& server=routing.servers[index];
            if (server.ipv6) return corosio::endpoint(corosio::ipv6_address(server.address),server.port);
            corosio::ipv4_address::bytes_type bytes{};
            std::copy_n(server.address.begin(),4,bytes.begin());
            return corosio::endpoint(corosio::ipv4_address(bytes),server.port);
        }
    };
}
