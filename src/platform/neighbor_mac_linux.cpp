module platform.neighbor_mac;
import std;

namespace platform::neighbor_mac {
    namespace {
        [[nodiscard]] auto is_zero_mac(MacAddress const& mac) noexcept -> bool {
            return std::ranges::all_of(mac, [](std::uint8_t b) { return b == 0; });
        }

        auto split_ws_tokens(std::string_view line, std::array<std::string_view, 8>& out) noexcept -> std::size_t {
            std::size_t count = 0;
            std::size_t i = 0;
            while (i < line.size() && count < out.size()) {
                while (i < line.size() && (line[i] == ' ' || line[i] == '\t' || line[i] == '\r')) ++i;
                if (i >= line.size()) break;
                std::size_t start = i;
                while (i < line.size() && line[i] != ' ' && line[i] != '\t' && line[i] != '\r') ++i;
                out[count++] = line.substr(start, i - start);
            }
            return count;
        }
    }

    auto parse_proc_net_arp(std::string_view content) -> std::vector<NeighborEntry> {
        std::vector<NeighborEntry> result;
        std::size_t pos = 0;
        bool first_line = true;
        while (pos < content.size()) {
            auto nl = content.find('\n', pos);
            auto line = (nl == std::string_view::npos) ? content.substr(pos) : content.substr(pos, nl - pos);
            pos = (nl == std::string_view::npos) ? content.size() : nl + 1;
            if (first_line) {
                first_line = false;
                if (line.contains("IP address")) continue;
            }
            if (line.empty()) continue;
            std::array<std::string_view, 8> cols{};
            if (split_ws_tokens(line, cols) < 6) continue;
            auto mac = parse_mac_text(cols[3]);
            if (!mac || is_zero_mac(*mac)) continue;
            unsigned flags = 0;
            auto flag_sv = cols[2];
            if (flag_sv.starts_with("0x") || flag_sv.starts_with("0X")) flag_sv.remove_prefix(2);
            auto [p, ec] = std::from_chars(flag_sv.data(), flag_sv.data() + flag_sv.size(), flags, 16);
            bool complete = (ec == std::errc{}) && ((flags & 0x2u) != 0);
            if (!complete) continue;
            result.push_back(NeighborEntry{
                .ip = std::string(cols[0]),
                .mac = *mac,
                .device = std::string(cols[5]),
                .complete = true,
            });
        }
        return result;
    }

    auto read_system_neighbors() -> std::vector<NeighborEntry> {
        std::ifstream in("/proc/net/arp");
        if (!in) return {};
        std::ostringstream ss;
        ss << in.rdbuf();
        return parse_proc_net_arp(ss.str());
    }

    auto NeighborTable::refresh(bool force) -> void {
        auto now = std::chrono::steady_clock::now();
        {
            std::lock_guard lock(mutex_);
            if (!force && last_refresh_ != std::chrono::steady_clock::time_point{} && (now - last_refresh_) < ttl_) {
                return;
            }
        }
        auto next = read_system_neighbors();
        std::lock_guard lock(mutex_);
        entries_ = std::move(next);
        last_refresh_ = std::chrono::steady_clock::now();
    }
}
