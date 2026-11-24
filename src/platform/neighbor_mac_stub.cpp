module platform.neighbor_mac;
import std;

namespace platform::neighbor_mac {
    auto parse_proc_net_arp(std::string_view) -> std::vector<NeighborEntry> { return {}; }
    auto read_system_neighbors() -> std::vector<NeighborEntry> { return {}; }

    auto NeighborTable::refresh(bool) -> void {
        std::lock_guard lock(mutex_);
        last_refresh_ = std::chrono::steady_clock::now();
    }
}
