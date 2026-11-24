#pragma once

namespace {
    auto check_address_replacement() -> bool {
        using namespace relay;
        auto send = +[](void*, std::span<std::uint8_t const>) { return true; };
        L3Mux mux(L3Endpoint{}, send, nullptr);
        constexpr std::array addresses{
            m::AddressEntry{0, 4, 32, {10, 10, 0, 2}},
            m::AddressEntry{0, 6, 128, {0xfd, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}},
        };
        if (!apply_masque_assigned_addresses(mux, addresses) ||
            !mux.endpoint().has_v4 || !mux.endpoint().has_v6) return false;

        auto endpoint = io::endpoint(io::ipv4_address::loopback(), 80);
        auto tcp = mux.open_tcp(endpoint, 1, 0);
        auto udp = mux.open_udp();
        if (!tcp || !udp || apply_masque_assigned_addresses(mux, addresses) ||
            tcp->state != L3Mux::TcpFlow::State::syn_sent || udp->closed) return false;

        if (!apply_masque_assigned_addresses(mux, std::span(addresses).first<1>()) ||
            !mux.endpoint().has_v4 || mux.endpoint().has_v6 ||
            tcp->state != L3Mux::TcpFlow::State::closed || !udp->closed || mux.active()) return false;
        udp = mux.open_udp();
        if (!udp || mux.send_udp(*udp, true, addresses[1].address, 53, {})) return false;

        if (!apply_masque_assigned_addresses(mux, {}) || !udp->closed ||
            mux.endpoint().has_v4 || mux.endpoint().has_v6 || mux.open_tcp(endpoint, 2, 0)) return false;
        constexpr std::array refused{m::AddressEntry{1, 4, 32, {}}};
        if (apply_masque_assigned_addresses(mux, refused) || mux.endpoint().has_v4) return false;

        return apply_masque_assigned_addresses(mux, addresses) && mux.endpoint().has_v4 &&
            mux.endpoint().has_v6 && mux.open_tcp(endpoint, 3, 0);
    }
}
