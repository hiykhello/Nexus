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

    // 1b. Multi-block dhclient.leases keeps only the latest lease per interface and respects interface_filter
    constexpr std::string_view multi_blocks =
        "lease {\n"
        "  interface \"eth0\";\n"
        "  option domain-name-servers 192.168.1.1;\n"
        "}\n"
        "lease {\n"
        "  interface \"wlan0\";\n"
        "  option domain-name-servers 172.16.0.1;\n"
        "}\n"
        "lease {\n"
        "  interface \"eth0\";\n"
        "  option domain-name-servers 10.0.0.1, 10.0.0.2;\n"
        "}\n";
    auto all_latest = dns::parse_dhcp_lease_text(multi_blocks);
    assert(all_latest.size() == 3);
    auto eth0_only = dns::parse_dhcp_lease_text(multi_blocks, "eth0");
    assert(eth0_only.size() == 2 && eth0_only[0].address.bytes[0] == 10 && eth0_only[0].address.bytes[3] == 1 &&
           eth0_only[1].address.bytes[3] == 2);
    auto wlan0_only = dns::parse_dhcp_lease_text(multi_blocks, "wlan0");
    assert(wlan0_only.size() == 1 && wlan0_only[0].address.bytes[0] == 172);
    assert(dns::parse_dhcp_lease_text(multi_blocks, "missing0").empty());

    // 1b2. Nested ISC lease6 { ia-na { iaaddr { ... } } option dhcp6.name-servers ...; } does not overwrite IPv4 lease
    constexpr std::string_view nested_v6 =
        "lease {\n"
        "  interface \"eth0\";\n"
        "  option domain-name-servers 10.0.0.1;\n"
        "}\n"
        "lease6 {\n"
        "  interface \"eth0\";\n"
        "  ia-na 01:02:03:04 {\n"
        "    iaaddr 2001:db8::10 {\n"
        "      preferred-life 3600;\n"
        "    }\n"
        "  }\n"
        "  option dhcp6.name-servers 2001:4860:4860::8888;\n"
        "}\n";
    auto dual = dns::parse_dhcp_lease_text(nested_v6, "eth0");
    assert(dual.size() == 2 && dual[0].address.size == 4 && dual[1].address.size == 16);

    // 1c. discover_dhcp_dns_servers directory filtering avoids cross-interface leakage
    {
        auto tmp = std::filesystem::temp_directory_path() / "nexus_lan_dns_dhcp_test";
        std::error_code ec;
        std::filesystem::remove_all(tmp, ec);
        std::filesystem::create_directories(tmp, ec);
        { std::ofstream(tmp / "eth0") << "DNS=10.10.0.1\n"; }
        { std::ofstream(tmp / "wlan0") << "DNS=172.20.0.1\n"; }
        { std::ofstream(tmp / "999999") << "DNS=192.168.99.1\n"; }
        std::string dir_str = tmp.string();
        std::array<std::string_view, 1> paths{dir_str};
        auto scoped = dns::discover_dhcp_dns_servers(paths, "eth0");
        std::filesystem::remove_all(tmp, ec);
        assert(scoped.size() == 1 && scoped[0].address.bytes[0] == 10 && scoped[0].address.bytes[1] == 10);
    }

    // 2. mDNS query + response parse + cache-flush & TTL expiry
    assert(dns::mdns::is_mdns_name("printer.local"));
    assert(dns::mdns::is_mdns_name("nas.home.local."));
    assert(!dns::mdns::is_mdns_name("example.com"));
    assert(dns::mdns::same_name("Printer.local.", "printer.LOCAL"));
    assert(!dns::mdns::same_name("printer.local", "other.local"));

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
