#include <cassert>

import std;
import platform.ip_address;
import dns.dhcp_upstream;
import dns.mdns;

int main() {
    // 1. DHCP Option 6 binary + lease text parsing
    std::array<std::uint8_t, 12> opt6{8, 8, 8, 8, 1, 1, 1, 1, 8, 8, 8, 8};
    auto parsed6 = dns::parse_dhcp_option6(opt6, 1800);
    assert(parsed6.size() == 2 && parsed6[0].lease_ttl_seconds == 1800);

    auto lease = dns::parse_dhcp_lease_text(
        "LIFETIME_SEC=900\n"
        "option domain-name-servers 192.168.1.1, 1.1.1.1;\n"
        "DNS=192.168.1.1 fe80::1%eth0\n"
        "nameserver 9.9.9.9\n");
    assert(lease.size() == 4 && lease[0].lease_ttl_seconds == 900);

    // 2. mDNS query + response parse + cache-flush & TTL expiry
    assert(dns::mdns::is_mdns_name("printer.local"));
    assert(dns::mdns::is_mdns_name("nas.home.local."));
    assert(!dns::mdns::is_mdns_name("example.com"));

    auto q = dns::mdns::make_mdns_query("printer.local", dns::mdns::RecordType::a, true);
    assert(q.has_value() && q->size() > 12 && (*q)[0] == 0 && (*q)[1] == 0);
    assert(((*q)[q->size() - 2] == 0x80) && ((*q)[q->size() - 1] == 0x01));

    // Craft minimal valid mDNS response for printer.local IN A 192.168.1.50 (cache-flush=true, ttl=60)
    std::vector<std::uint8_t> resp{
        0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        7, 'p', 'r', 'i', 'n', 't', 'e', 'r', 5, 'l', 'o', 'c', 'a', 'l', 0,
        0x00, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192, 168, 1, 50
    };
    auto rrs = dns::mdns::parse_mdns_response(resp);
    assert(rrs && rrs->size() == 1 && (*rrs)[0].cache_flush && (*rrs)[0].ttl == 60);
    assert((*rrs)[0].address && (*rrs)[0].address->bytes[3] == 50);

    dns::mdns::MdnsCache cache;
    cache.ingest(*rrs, 1000);
    assert(cache.lookup("printer.local.", 1, 1059).size() == 1);
    assert(cache.lookup("printer.local", 1, 1060).empty());
    assert(cache.prune_expired(1060) == 1 && cache.size() == 0);

    std::println("LAN DNS unit tests (DHCP Option6/leases + mDNS RFC6762) passed");
    return 0;
}
