export module relay.masque_ip_addresses;
import std;
import masque.ip_control;
import relay.l3_mux;

export namespace relay {
    // ADDRESS_ASSIGN replaces the entire snapshot, including absent families.
    inline auto apply_masque_assigned_addresses(L3Mux& mux, std::span<masque::AddressEntry const> addresses) -> bool {
        auto const& current = mux.endpoint();
        L3Endpoint next{false, {}, false, {}, current.mtu};
        for (auto const& entry : addresses) {
            if (masque::address_rejection(entry)) continue;
            if (entry.version == 4 && !next.has_v4) {
                auto addr = std::span(entry.address).first<4>();
                if (std::ranges::any_of(addr, [](auto byte) { return byte != 0; })) {
                    std::ranges::copy(addr, next.local_v4.begin());
                    next.has_v4 = true;
                }
            } else if (entry.version == 6 && current.mtu >= 1280 && !next.has_v6 &&
                       std::ranges::any_of(entry.address, [](auto byte) { return byte != 0; })) {
                next.local_v6 = entry.address;
                next.has_v6 = true;
            }
        }
        if (current.has_v4 == next.has_v4 && (!next.has_v4 || current.local_v4 == next.local_v4) &&
            current.has_v6 == next.has_v6 && (!next.has_v6 || current.local_v6 == next.local_v6))
            return false;

        mux.set_endpoint(next);
        mux.reset_flows();
        return true;
    }
}
