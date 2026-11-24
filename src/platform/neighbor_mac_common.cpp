module platform.neighbor_mac;
import std;
import encoding.hex;

namespace platform::neighbor_mac {
    auto parse_mac_text(std::string_view text) noexcept -> std::optional<MacAddress> {
        if (text.size() != 17) return std::nullopt;
        char const sep = text[2];
        if (sep != ':' && sep != '-') return std::nullopt;
        MacAddress out{};
        for (std::size_t i = 0; i < 6; ++i) {
            std::size_t off = i * 3;
            int hi = encoding::hex_value(text[off]);
            int lo = encoding::hex_value(text[off + 1]);
            if (hi < 0 || lo < 0 || (i < 5 && text[off + 2] != sep)) return std::nullopt;
            out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
        }
        return out;
    }

    auto NeighborTable::replace_entries(std::vector<NeighborEntry> entries) -> void {
        std::lock_guard lock(mutex_);
        entries_ = std::move(entries);
        last_refresh_ = std::chrono::steady_clock::now();
    }

    auto NeighborTable::lookup(std::string_view ip, std::string_view device) const -> std::optional<MacAddress> {
        std::lock_guard lock(mutex_);
        for (auto const& entry : entries_) {
            if (entry.ip != ip) continue;
            if (!device.empty() && entry.device != device) continue;
            return entry.mac;
        }
        return std::nullopt;
    }

    auto NeighborTable::size() const -> std::size_t {
        std::lock_guard lock(mutex_);
        return entries_.size();
    }
}
