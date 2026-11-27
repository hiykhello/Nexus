export module state.fakeip;
import std;
import functional;
export import state.core;

export namespace state {
    enum class CrashMode { range_reserve, per_mapping };

    struct FakeIpScope {
        std::uint32_t first, last, alloc_first, alloc_last;
        // Additional pool identity (including the IPv6 CIDR), canonical exclusions
        // are numeric inclusive ranges ordered by starting address.
        Fingerprint identity{};
        std::vector<std::pair<std::uint32_t,std::uint32_t>> exclude_cidrs;
    };

    struct FakeIpRow {
        std::uint32_t address;
        std::uint64_t view;
        std::string domain;
    };

    class FakeIpStore {
        struct Impl;
        std::unique_ptr<Impl> owner_;
        explicit FakeIpStore(std::unique_ptr<Impl> owner) noexcept;
    public:
        ~FakeIpStore();
        [[nodiscard]] static auto open(std::filesystem::path const& root, FakeIpScope scope, CrashMode mode,
            std::optional<std::size_t> wal_limit = std::nullopt)
            -> std::expected<std::unique_ptr<FakeIpStore>, StateError>;
        [[nodiscard]] auto wal_limit() const noexcept -> std::size_t;
        // Called while attaching the runtime pool, before the first allocation.
        [[nodiscard]] auto visit_recovered(functional::function_ref<bool(FakeIpRow const&)> visit) const -> bool;
        [[nodiscard]] auto assign(std::string_view canonical, std::uint64_t view)
            -> std::expected<std::uint32_t,StateError>;
        [[nodiscard]] auto flush() -> std::expected<void,StateError>;
        [[nodiscard]] auto stop() -> std::expected<void,StateError>;
    };
}
