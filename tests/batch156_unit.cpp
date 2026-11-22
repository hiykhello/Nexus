#include <cassert>

import std;
import endpoint.on_demand;
import platform.neighbor_mac;
import platform.netns_config;
import rules;

int main() {
    // 1. Endpoint on-demand sleep/wake & queue cap
    {
        endpoint::on_demand::Controller ctrl({
            .idle_timeout = std::chrono::seconds{10},
            .wake_backoff = std::chrono::seconds{3},
            .max_queued_packets = 2,
        }, 1000);
        assert(ctrl.state() == endpoint::on_demand::State::sleeping);
        assert(ctrl.on_outbound_packet(1050, 64) == endpoint::on_demand::WakeAction::initiate_wake);
        assert(ctrl.state() == endpoint::on_demand::State::waking);
        assert(ctrl.on_outbound_packet(1060, 64) == endpoint::on_demand::WakeAction::queued);
        assert(ctrl.on_outbound_packet(1070, 64) == endpoint::on_demand::WakeAction::dropped);
        assert(ctrl.on_tunnel_up(1200) == 2);
        assert(ctrl.state() == endpoint::on_demand::State::active);
        assert(ctrl.on_outbound_packet(5000, 128) == endpoint::on_demand::WakeAction::pass);
        assert(ctrl.tick(14999) == endpoint::on_demand::State::active);
        assert(ctrl.tick(15000) == endpoint::on_demand::State::sleeping);
        assert(ctrl.stats().sleep_transitions == 1 && ctrl.stats().wake_transitions == 1);

        // Cooldown after tunnel error prevents immediate tight wake loop
        assert(ctrl.on_outbound_packet(16000, 64) == endpoint::on_demand::WakeAction::initiate_wake);
        ctrl.on_tunnel_down(16100, true);
        assert(ctrl.state() == endpoint::on_demand::State::cooldown);
        assert(ctrl.on_outbound_packet(17000, 64) == endpoint::on_demand::WakeAction::dropped);
        assert(ctrl.on_outbound_packet(19100, 64) == endpoint::on_demand::WakeAction::initiate_wake);
    }

    // 2. Neighbor MAC ARP lookup -> gateway / source-mac-address rule matching
    {
        constexpr std::string_view kArpSample =
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n"
            "192.168.1.2      0x1         0x0         00:00:00:00:00:00     *        eth0\n"
            "10.0.0.5         0x1         0x2         12:34:56:78:9a:bc     *        wlan0\n";
        auto entries = platform::neighbor_mac::parse_proc_net_arp(kArpSample);
        assert(entries.size() == 2);
        platform::neighbor_mac::NeighborTable tbl;
        tbl.replace_entries(std::move(entries));
        auto gw_mac = tbl.lookup("192.168.1.1", "eth0");
        auto lan_mac = tbl.lookup("10.0.0.5");
        assert(gw_mac.has_value() && lan_mac.has_value());
        assert(!tbl.lookup("192.168.1.2").has_value());

        rules::RuleSet set;
        set.version = 2;
        set.rules.push_back({.type = "source-mac", .value = "12:34:56:78:9a:bc"});
        set.rules.push_back({.type = "gateway-mac", .value = "aa:bb:cc:dd:ee:ff"});
        auto matcher = *rules::Matcher::compile(set);
        rules::IngressMetadata meta{.source_mac = lan_mac, .gateway_mac = gw_mac};
        auto m1 = matcher.match(meta.apply(rules::MatchInput{}));
        assert(m1 && *m1 == std::optional<std::size_t>{0});

        rules::RuleSet gw_only;
        gw_only.version = 2;
        gw_only.rules.push_back({.type = "gateway-mac", .value = "aa:bb:cc:dd:ee:ff"});
        auto gw_matcher = *rules::Matcher::compile(gw_only);
        auto m2 = gw_matcher.match(meta.apply(rules::MatchInput{}));
        assert(m2 && *m2 == std::optional<std::size_t>{0});
    }

    // 3. Declarative network-namespaces validation & reconciliation plan
    {
        assert(!platform::netns::validate_name("../escape"));
        assert(!platform::netns::validate_name("bad/slash"));
        assert(platform::netns::validate_name("edge-wan0"));

        std::vector<platform::netns::NamespaceSpec> cur{
            {.name = "stale-ns", .interfaces = {"eth9"}},
            {.name = "corp", .interfaces = {"eth1"}},
        };
        std::vector<platform::netns::NamespaceSpec> want{
            {.name = "corp", .interfaces = {"eth1", "wg0"}, .routes = {{"10.20.0.0/16", "10.0.0.1", 100}}},
            {.name = "guest", .interfaces = {"wlan1"}},
        };
        assert(platform::netns::validate_plan(want).has_value());
        auto plan = platform::netns::plan_reconcile(want, cur);
        assert(!plan.empty());
        assert(plan.front().kind == platform::netns::PlanAction::Kind::delete_ns && plan.front().ns_name == "stale-ns");
        assert(std::ranges::any_of(plan, [](auto const& a) {
            return a.kind == platform::netns::PlanAction::Kind::create_ns && a.ns_name == "guest";
        }));
    }

    std::println("batch156 unit tests (on-demand / source-mac / netns) passed");
    return 0;
}
