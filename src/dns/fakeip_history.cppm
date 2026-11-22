export module dns.fakeip_history;
import std;
import dns.fakeip_recovery;
export namespace dns {
    enum class FakeIpHistoryError { invalid, authentication, crypto };
    struct FakeIpHistorySnapshot {
        std::uint64_t generation=0;
        std::vector<FakeIpHistoricalRange> ranges;
    };
    // Experimental authenticated snapshot. A separate trusted mechanism is
    // required to detect deletion, rollback, key loss, and owner replacement.
    [[nodiscard]] auto encode_fakeip_history(FakeIpHistorySnapshot const& snapshot,
        std::span<std::uint8_t const,16> instance,std::span<std::uint8_t const,32> key)
        -> std::expected<std::vector<std::uint8_t>,FakeIpHistoryError>;
    [[nodiscard]] auto decode_fakeip_history(std::span<std::uint8_t const> wire,
        std::span<std::uint8_t const,16> instance,std::span<std::uint8_t const,32> key)
        -> std::expected<FakeIpHistorySnapshot,FakeIpHistoryError>;
}
