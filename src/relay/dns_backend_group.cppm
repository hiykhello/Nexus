// Shared DNS provider. Test-only access remains gated by proxy features.
export module relay.dns_backend;
export import dns.cache;
export import dns.shared_cache;
export import dns.shared_coordinator;

import std;
import dns.response_cache;

#ifdef NEXUS_DNS_SHARED
export namespace relay {
    // One configuration generation is shared by its listeners and executors.
    // All borrowers must stop and release their readers before it is destroyed.
    class SharedDnsGeneration {
        std::unique_ptr<dns_hp_experiment::GroupSnapshot> cache_;
        dns_hp_experiment::Coordinator coordinator_;
#ifdef NEXUS_DNS_RESPONSE
        std::unique_ptr<dns::ResponseCache> response_cache_;
#endif
        dns_hp_experiment::ViewRegistry registry_;
        dns_hp_experiment::LocalViewRegistry local_registry_;
    public:
        SharedDnsGeneration(std::size_t groups,std::size_t readers,std::uint32_t optimistic_seconds=0)
            : coordinator_(256,4096),registry_(64,1024*1024,4096) {
            std::vector<std::size_t> capacities(groups,1);
            cache_=std::make_unique<dns_hp_experiment::GroupSnapshot>(capacities,
                dns_hp_experiment::GroupSnapshot::SharedCapacity{groups*256},readers,std::uint64_t{optimistic_seconds}*1000,32*1024*1024,1000);
        }
        SharedDnsGeneration(SharedDnsGeneration const&)=delete;
        auto operator=(SharedDnsGeneration const&) -> SharedDnsGeneration& = delete;
        [[nodiscard]] auto cache() noexcept -> dns_hp_experiment::GroupSnapshot& { return *cache_; }
        [[nodiscard]] auto coordinator() noexcept -> dns_hp_experiment::Coordinator& { return coordinator_; }
#ifdef NEXUS_DNS_RESPONSE
        [[nodiscard]] auto ensure_response_cache() noexcept -> dns::ResponseCache* {
            try { if (!response_cache_) response_cache_=std::make_unique<dns::ResponseCache>(256); }
            catch (std::bad_alloc const&) { return nullptr; }
            return response_cache_.get();
        }
#endif
        [[nodiscard]] auto registry() noexcept -> dns_hp_experiment::ViewRegistry& { return registry_; }
        [[nodiscard]] auto local_registry() noexcept -> dns_hp_experiment::LocalViewRegistry& { return local_registry_; }
        auto seal() noexcept -> void { registry_.seal(); }
    };
}
#endif
