export module state.fakeip;
import std;
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
        [[nodiscard]] static auto open(std::filesystem::path const& root, FakeIpScope scope, CrashMode mode)
            -> std::expected<std::unique_ptr<FakeIpStore>, StateError>;
        // Called while attaching the runtime pool, before the first allocation.
        [[nodiscard]] auto visit_recovered(std::function_ref<bool(FakeIpRow const&)> visit) const -> bool;
        [[nodiscard]] auto assign(std::string_view canonical, std::uint64_t view)
            -> std::expected<std::uint32_t,StateError>;
    };
}
