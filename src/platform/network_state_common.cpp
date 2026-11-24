module platform.network_state;
import std;

namespace platform::network {
    auto Link::up(this Link const& self) noexcept -> bool {
        return (self.flags & constants::iff_up) != 0;
    }

    auto infer_network_type(Link const& link) noexcept -> NetworkType {
        if (link.kind == "wlan" || link.name.starts_with("wlan") || link.name.starts_with("wl"))
            return NetworkType::wifi;
        if (link.kind == "wwan" || link.name.starts_with("wwan") || link.name.starts_with("rmnet") ||
            link.name.starts_with("ccmni") || link.name.starts_with("usb"))
            return NetworkType::cellular;
        if (link.kind == "veth" || link.kind == "bridge" || link.name.starts_with("eth") || link.name.starts_with("en"))
            return NetworkType::ethernet;
        return NetworkType::other;
    }

    auto Snapshot::default_interface_addresses(this Snapshot const& self)
        -> std::vector<std::pair<std::array<std::uint8_t, 16>, std::uint8_t>> {
        std::vector<std::pair<std::array<std::uint8_t, 16>, std::uint8_t>> out;
        if (!self.default_interface_index) return out;
        for (auto const& addr : self.addresses) {
            if (addr.index != self.default_interface_index || !addr.usable()) continue;
            if (addr.family == constants::af_inet) out.emplace_back(addr.local, std::uint8_t{4});
            else if (addr.family == constants::af_inet6) out.emplace_back(addr.local, std::uint8_t{16});
            if (out.size() >= 64) break;
        }
        return out;
    }

    auto Link::carrier(this Link const& self) noexcept -> bool {
        return (self.flags & constants::iff_lower_up) != 0;
    }

    auto Address::usable(this Address const& self) noexcept -> bool {
        return (self.flags & (constants::ifa_f_tentative | constants::ifa_f_dadfailed)) == 0;
    }

    auto Snapshot::find_link(this Snapshot const& self, std::uint32_t index) noexcept -> Link const* {
        auto found = std::ranges::lower_bound(self.links, index, {}, &Link::index);
        return found != self.links.end() && found->index == index ? &*found : nullptr;
    }

    auto Snapshot::neighbor_mac(this Snapshot const& self, std::span<std::uint8_t const> address,
        std::uint32_t index) noexcept -> std::optional<MacAddress> {
        Neighbor key;
        if (address.size() == 4) key.family = constants::af_inet;
        else if (address.size() == 16) key.family = constants::af_inet6;
        else return {};
        std::ranges::copy(address, key.address.begin());
        auto neighbor_key = [](Neighbor const& value) noexcept {
            return std::tie(value.family, value.address);
        };
        auto found = std::ranges::lower_bound(self.neighbors, neighbor_key(key), {}, neighbor_key);
        std::optional<MacAddress> result;
        for (; found != self.neighbors.end() && neighbor_key(*found) == neighbor_key(key); ++found) {
            if (index && found->index != index) continue;
            if (result && *result != found->mac) return {};
            result = found->mac;
        }
        return result;
    }

    auto Monitor::enable_neighbors() noexcept -> void {
        if (!std::exchange(include_neighbors_, true)) stop();
    }
}
