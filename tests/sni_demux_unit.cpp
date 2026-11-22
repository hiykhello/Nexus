#include <cassert>

import std;
import proxy.sni_demux;

namespace {
    auto build_client_hello(std::string_view sni, std::initializer_list<std::string_view> alpns) -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> ext;
        if (!sni.empty()) {
            std::uint16_t list_len = static_cast<std::uint16_t>(1 + 2 + sni.size());
            std::uint16_t ext_len = static_cast<std::uint16_t>(2 + list_len);
            ext.insert(ext.end(), {0x00, 0x00, static_cast<std::uint8_t>(ext_len >> 8), static_cast<std::uint8_t>(ext_len)});
            ext.insert(ext.end(), {static_cast<std::uint8_t>(list_len >> 8), static_cast<std::uint8_t>(list_len), 0x00});
            ext.insert(ext.end(), {static_cast<std::uint8_t>(sni.size() >> 8), static_cast<std::uint8_t>(sni.size())});
            ext.insert(ext.end(), sni.begin(), sni.end());
        }
        if (alpns.size() > 0) {
            std::vector<std::uint8_t> alist;
            for (auto p : alpns) {
                alist.push_back(static_cast<std::uint8_t>(p.size()));
                alist.insert(alist.end(), p.begin(), p.end());
            }
            std::uint16_t list_len = static_cast<std::uint16_t>(alist.size());
            std::uint16_t ext_len = static_cast<std::uint16_t>(2 + list_len);
            ext.insert(ext.end(), {0x00, 0x10, static_cast<std::uint8_t>(ext_len >> 8), static_cast<std::uint8_t>(ext_len)});
            ext.insert(ext.end(), {static_cast<std::uint8_t>(list_len >> 8), static_cast<std::uint8_t>(list_len)});
            ext.insert(ext.end(), alist.begin(), alist.end());
        }

        std::vector<std::uint8_t> hello;
        hello.insert(hello.end(), {0x03, 0x03}); // TLS 1.2 legacy version
        hello.resize(hello.size() + 32, 0x11);   // random
        hello.push_back(0x00);                   // empty session_id
        hello.insert(hello.end(), {0x00, 0x02, 0x13, 0x01}); // TLS_AES_128_GCM_SHA256
        hello.insert(hello.end(), {0x01, 0x00}); // null compression
        hello.push_back(static_cast<std::uint8_t>(ext.size() >> 8));
        hello.push_back(static_cast<std::uint8_t>(ext.size()));
        hello.insert(hello.end(), ext.begin(), ext.end());

        std::vector<std::uint8_t> out;
        std::size_t hs_len = hello.size();
        std::size_t rec_len = hs_len + 4;
        out.insert(out.end(), {0x16, 0x03, 0x01, static_cast<std::uint8_t>(rec_len >> 8), static_cast<std::uint8_t>(rec_len)});
        out.insert(out.end(), {0x01, static_cast<std::uint8_t>(hs_len >> 16), static_cast<std::uint8_t>(hs_len >> 8), static_cast<std::uint8_t>(hs_len)});
        out.insert(out.end(), hello.begin(), hello.end());
        return out;
    }
}

int main() {
    auto proxy_hello = build_client_hello("proxy.edge.example", {"h2", "http/1.1"});
    auto web_hello = build_client_hello("panel.edge.example", {"http/1.1"});
    auto site_hello = build_client_hello("static.other.com", {"h2"});

    proxy::SniDemuxRouter router;
    router.add_rule({"proxy.edge.example", "h2", proxy::DemuxRole::proxy_inbound, "127.0.0.1:10443"});
    router.add_rule({"*.edge.example", "", proxy::DemuxRole::web_console, "127.0.0.1:9090"});
    router.set_fallback(proxy::DemuxRole::https_site, "127.0.0.1:8443");

    auto d1 = router.route(proxy_hello);
    assert(d1.matched_rule && d1.role == proxy::DemuxRole::proxy_inbound && d1.target_upstream == "127.0.0.1:10443");
    assert(d1.selected_alpn == "h2" && d1.passthrough_bytes.size() == proxy_hello.size());

    auto d2 = router.route(web_hello);
    assert(d2.matched_rule && d2.role == proxy::DemuxRole::web_console && d2.target_upstream == "127.0.0.1:9090");

    auto d3 = router.route(site_hello);
    assert(!d3.matched_rule && d3.role == proxy::DemuxRole::https_site && d3.target_upstream == "127.0.0.1:8443");

    // Partial ClientHello -> incomplete
    auto partial = proxy::inspect_client_hello(std::span(proxy_hello).first(proxy_hello.size() - 4));
    assert(partial.status == proxy::SniPeekStatus::incomplete);

    // Non-TLS HTTP -> non_tls & fallback
    std::vector<std::uint8_t> http_get{'G', 'E', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P'};
    auto d4 = router.route(http_get);
    assert(!d4.matched_rule && d4.role == proxy::DemuxRole::https_site && d4.passthrough_bytes.size() == http_get.size());
    assert(proxy::inspect_client_hello(http_get).status == proxy::SniPeekStatus::non_tls);

    // Malformed TLS record length -> malformed & safe
    std::vector<std::uint8_t> bad{0x16, 0x03, 0x01, 0xff, 0xff, 0x01};
    assert(proxy::inspect_client_hello(bad).status == proxy::SniPeekStatus::malformed);

    std::println("L4 SNI demux unit tests passed");
    return 0;
}
