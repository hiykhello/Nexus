import std;
import crypto;
import tls.schedule;
import tuic.wire;

namespace t = tuic;
namespace c = ::crypto;

int main() {
    // 1. RFC 8446 Exporter + TUIC v5 32-byte auth token derivation & roundtrip.
    std::array<std::uint8_t, 32> master{};
    std::array<std::uint8_t, 32> sf_transcript{};
    for (std::size_t i = 0; i < 32; ++i) {
        master[i] = static_cast<std::uint8_t>(0x10 + i);
        sf_transcript[i] = static_cast<std::uint8_t>(0x80 + i);
    }
    auto exp_master = tls::exporter_master_secret(c::Hash::sha256, master, sf_transcript);
    if (!exp_master) return 1;
    std::array<std::uint8_t, 16> uuid{0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4,
                                      0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00};
    auto tok1 = t::derive_auth_token(c::Hash::sha256, exp_master->view(), uuid, "tuic-secret");
    auto tok2 = t::derive_auth_token(c::Hash::sha256, exp_master->view(), uuid, "tuic-secret");
    auto tok_wrong = t::derive_auth_token(c::Hash::sha256, exp_master->view(), uuid, "other-secret");
    if (!tok1 || !tok2 || !tok_wrong || *tok1 != *tok2 || *tok1 == *tok_wrong) return 2;

    t::Authenticate auth{uuid, *tok1};
    auto auth_wire = t::encode_authenticate(auth);
    auto auth_decoded = t::decode_authenticate(auth_wire);
    if (!auth_decoded || *auth_decoded != auth) return 3;
    if (t::decode_authenticate(std::span(auth_wire).first(49)).error() != t::WireError::incomplete) return 4;

    // 2. Connect (Domain, IPv4, IPv6; reject AddressType::none), Dissociate, Heartbeat.
    t::TargetAddress dom{t::AddressType::domain, "example.com", {}, 443};
    t::TargetAddress v4{t::AddressType::ipv4, {}, {127, 0, 0, 1}, 8443};
    t::TargetAddress v6{t::AddressType::ipv6, {}, {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 53};
    for (auto const& addr : {dom, v4, v6}) {
        auto enc = t::encode_connect(addr);
        if (!enc) return 5;
        auto dec = t::decode_connect(*enc);
        if (!dec || dec->first != addr || dec->second != enc->size()) return 6;
    }
    if (t::encode_connect(t::TargetAddress{}).error() != t::WireError::invalid) return 7;

    auto dissoc = t::encode_dissociate(0x1234);
    auto dissoc_dec = t::decode_dissociate(dissoc);
    if (!dissoc_dec || *dissoc_dec != 0x1234) return 8;
    auto hb = t::encode_heartbeat();
    if (!t::decode_heartbeat(hb)) return 9;

    // 3. UDP fragmentation, out-of-order reassembly, duplicate/conflict guards.
    std::vector<std::uint8_t> udp_payload(1400);
    for (std::size_t i = 0; i < udp_payload.size(); ++i) udp_payload[i] = static_cast<std::uint8_t>(i ^ 0x5a);
    auto frags = t::fragment_udp_packet(7, 42, dom, udp_payload, 500);
    if (!frags || frags->size() < 3) return 10;

    t::UdpDefragmenter defrag;
    // Feed in reverse order (last fragment first, first fragment last).
    for (std::size_t idx = frags->size(); idx-- > 0;) {
        auto pkt = t::decode_packet((*frags)[idx]);
        if (!pkt) return 11;
        auto step = defrag.feed(*pkt);
        if (!step) return 12;
        if (idx > 0 && step->has_value()) return 13;
        if (idx == 0) {
            if (!step->has_value()) return 14;
            if ((*step)->assoc_id != 7 || (*step)->packet_id != 42 ||
                (*step)->destination != dom || (*step)->payload != udp_payload) return 15;
        }
    }
    if (defrag.active_entries() != 0) return 16;

    // Partial packet duplicate rejection & association cleanup.
    auto p0 = t::decode_packet((*frags)[0]);
    if (!p0) return 17;
    if (!defrag.feed(*p0) || defrag.active_entries() != 1) return 18;
    if (defrag.feed(*p0).error() != t::WireError::duplicate) return 19;
    defrag.clear_association(7);
    if (defrag.active_entries() != 0) return 20;

    std::println("TUIC v5 TLS exporter token, commands, address encoding and UDP defragmentation passed");
}
