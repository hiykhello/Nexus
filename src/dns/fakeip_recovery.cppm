export module nexus.dns.fakeip_recovery;
import std;
import nexus.dns.fakeip_shared;
import nexus.dns.fakeip_registry;

export namespace nexus::dns {
    struct FakeIpHistoricalRange {
        std::uint32_t first, last;
        // Longest previously published TTL plus its protection grace.
        std::chrono::seconds protection;
    };
    struct FakeIpRecoveryPool {
        std::uint32_t first, last, alloc_first, alloc_last;
        std::chrono::seconds ttl, grace;
    };
    enum class FakeIpRecoveryError { invalid, too_many_ranges, interval_overflow, registry };

    // Prepare the next durable history before publishing from the current
    // pool. Overlapping and adjacent ranges are conservatively merged with
    // the greatest protection period; no previous address is removed.
    [[nodiscard]] auto update_fakeip_history(FakeIpRecoveryPool current,
        std::span<FakeIpHistoricalRange const> history)
        -> std::expected<std::vector<FakeIpHistoricalRange>,FakeIpRecoveryError>;

    // The caller must hold a stable exclusive owner lock, supply the complete
    // durable history and retain both until every response and target drains.
    // A supplied lifetime is retained by the registry and all its handles.
    // This function does not read, write or authenticate that history.
    [[nodiscard]] auto recover_fakeip(FakeIpRecoveryPool current,
        std::span<FakeIpHistoricalRange const> history, std::chrono::seconds transit,
        std::chrono::steady_clock::time_point start,std::shared_ptr<void> lifetime={})
        -> std::expected<std::shared_ptr<FakeIpShared>,FakeIpRecoveryError>;
}
