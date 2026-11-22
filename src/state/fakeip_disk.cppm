export module state.fakeip_disk;
import std;
import state.fakeip;
import state.snapshot;

export namespace state {
    inline constexpr std::size_t fakeip_wal_limit=2*1024*1024;
    inline constexpr std::uint32_t fakeip_range=256;

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
    auto replay_fakeip(InstanceLock const&, FakeIpScope const&, FakeIpMeta const&, int wal)
        -> std::expected<FakeIpReplay,StateError>;
    auto append_fakeip(int wal, FakeIpMeta const&, std::uint64_t sequence, FakeIpRow const&)
        -> std::expected<std::size_t,StateError>;
    auto compact_fakeip(InstanceLock const&, FakeIpMeta const&, int wal, std::span<FakeIpRow const>)
        -> std::expected<void,StateError>;
    auto valid_fakeip_name(std::string_view value) noexcept -> bool;
}
