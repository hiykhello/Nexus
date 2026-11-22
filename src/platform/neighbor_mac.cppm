export module platform.neighbor_mac;
import std;

export namespace platform::neighbor_mac {
    using MacAddress = std::array<std::uint8_t, 6>;

    struct NeighborEntry {
        std::string ip;
        MacAddress mac{};
        std::string device;
        bool complete = false;
    };

    [[nodiscard]] auto parse_mac_text(std::string_view text) noexcept -> std::optional<MacAddress>;
    [[nodiscard]] auto parse_proc_net_arp(std::string_view content) -> std::vector<NeighborEntry>;
    [[nodiscard]] auto read_system_neighbors() -> std::vector<NeighborEntry>;

    class NeighborTable {
        mutable std::mutex mutex_;
        std::vector<NeighborEntry> entries_;
        std::chrono::steady_clock::time_point last_refresh_{};
        std::chrono::milliseconds ttl_{5000};
    public:
        explicit NeighborTable(std::chrono::milliseconds ttl = std::chrono::milliseconds{5000}) noexcept : ttl_(ttl) {}
        auto replace_entries(std::vector<NeighborEntry> entries) -> void;
        auto refresh(bool force = false) -> void;
        [[nodiscard]] auto lookup(std::string_view ip, std::string_view device = {}) const -> std::optional<MacAddress>;
        [[nodiscard]] auto size() const -> std::size_t;
    };
}
