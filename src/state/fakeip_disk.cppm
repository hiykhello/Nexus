export module state.fakeip_disk;
import std;
export import state.file;
import state.fakeip;
import state.snapshot;

export namespace state {
    inline constexpr std::size_t fakeip_wal_limit_min = 2 * 1024 * 1024;
    inline constexpr std::size_t fakeip_wal_limit_max = 64 * 1024 * 1024;
    inline constexpr std::size_t fakeip_wal_limit_override_min = 64 * 1024;
    inline constexpr std::size_t fakeip_wal_bytes_per_addr = 32;
    inline constexpr std::size_t fakeip_wal_limit = fakeip_wal_limit_min;
    inline constexpr std::uint64_t fakeip_max_pool_size = 1ull << 20;
    inline constexpr std::uint32_t fakeip_range = 256;

    [[nodiscard]] constexpr auto fakeip_wal_threshold(std::uint64_t pool_size,
        std::optional<std::size_t> explicit_limit = std::nullopt) noexcept -> std::size_t {
        if (explicit_limit) return std::clamp(*explicit_limit, fakeip_wal_limit_override_min, fakeip_wal_limit_max);
        constexpr auto cap_addrs = fakeip_wal_limit_max / fakeip_wal_bytes_per_addr;
        auto scaled = pool_size >= cap_addrs ? fakeip_wal_limit_max : static_cast<std::size_t>(pool_size * fakeip_wal_bytes_per_addr);
        return std::clamp(scaled, fakeip_wal_limit_min, fakeip_wal_limit_max);
    }

    struct FakeIpMeta {
        std::array<std::byte,16> owner{};
        std::uint64_t reserved=0, generation=1;
    };
    struct FakeIpReplay {
        std::vector<FakeIpRow> rows;
        std::size_t wal_bytes=0;
    };

    auto fakeip_meta(InstanceLock const&, FakeIpScope const&) -> std::expected<FakeIpMeta,StateError>;
    auto save_fakeip_meta(InstanceLock const&, FakeIpScope const&, FakeIpMeta const&)
        -> std::expected<void,StateError>;
    auto replay_fakeip(InstanceLock const&, FakeIpScope const&, FakeIpMeta const&, NativeHandle wal,
        std::size_t wal_limit = 0) -> std::expected<FakeIpReplay,StateError>;
    auto append_fakeip(NativeHandle wal, FakeIpMeta const&, std::uint64_t sequence, FakeIpRow const&)
        -> std::expected<std::size_t,StateError>;
    auto compact_fakeip(InstanceLock const&, FakeIpMeta const&, NativeHandle wal, std::span<FakeIpRow const>,
        std::uint64_t pool_capacity = 65536) -> std::expected<void,StateError>;
    auto valid_fakeip_name(std::string_view value) noexcept -> bool;
}
