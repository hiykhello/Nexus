import std;
import wireguard.routing;

namespace {
    using namespace wireguard::routing;
    constexpr PeerHandle a{0,1},b{1,1},c{2,1};
    auto v4(std::array<std::uint8_t,4> address,std::uint8_t bits) -> Prefix {
        Prefix result{4,{},bits}; std::ranges::copy(address,result.address.begin()); return result;
    }
    auto v6(std::array<std::uint8_t,16> address,std::uint8_t bits) -> Prefix { return {6,address,bits}; }
    auto query(auto const& table,Prefix const& address) -> std::optional<PeerHandle> {
        return table.lookup(address.family,std::span(address.address).first(address.family==4 ? 4 : 16));
    }
    auto permitted(SourcePolicyView const& policy,Prefix const& address) -> bool {
        return policy.permits(address.family,std::span(address.address).first(address.family==4 ? 4 : 16));
    }
    auto defaults_and_validation() -> bool {
        RouteTable<3,8> table;
        auto local=v4({10,42,0,1},32);
        SourcePolicyView disabled;
        if (disabled.enabled() || !permitted(disabled,local) || table.view(a).permits(4,std::span(local.address).first(4))) return false;
        if (table.activate({3,1}) || table.activate({0,0}) || !table.activate(a) || !table.activate(a) || table.status().peers!=1) return false;
        if (!table.view(a).enabled() || permitted(table.view(a),local) || query(table,local)) return false;
        auto bad=local; bad.bits=33;
        if (valid_prefix(bad) || table.assign(a,bad) || table.status().prefixes) return false;
        bad=local; bad.bits=24;
        if (valid_prefix(bad) || prefix_contains(bad,4,std::span(local.address).first(4)) || table.assign(a,bad)) return false;
        bad=v4({},0); bad.address[4]=1;
        if (valid_prefix(bad) || table.assign(a,bad)) return false;
        bad=v6({},129);
        if (valid_prefix(bad) || table.assign(a,bad)) return false;
        if (!table.assign(a,v4({},0)) || query(table,local)!=a || !permitted(table.view(a),local)) return false;
        std::array<std::uint8_t,16> destination{0x20,1,0x0d,0xb8};
        if (table.lookup(6,destination) || table.lookup(4,destination) || table.lookup(3,std::span(destination).first(4))) return false;
        if (!table.assign(a,v6({},0)) || table.lookup(6,destination)!=a || !table.view(a).permits(6,destination)) return false;
        if (!table.erase(a) || table.activate(a) || table.valid(a) || table.lookup(6,destination) || table.status().prefixes || table.status().peers) return false;
        return !table.view(a).permits(6,destination) && !table.assign(a,v6({},0));
    }
    auto ipv4_overlap_and_exact_updates() -> bool {
        RouteTable<3,8> table;
        if (!table.activate(a) || !table.activate(b) || !table.activate(c)) return false;
        auto defaults=v4({},0),wide=v4({10,0,0,0},8),narrow=v4({10,42,0,0},16),host=v4({10,42,7,9},32);
        if (!table.assign(a,defaults) || !table.assign(b,wide) || !table.assign(c,narrow) || !table.assign(a,host)) return false;
        if (query(table,v4({203,0,113,1},32))!=a || query(table,v4({10,43,1,1},32))!=b || query(table,v4({10,42,8,1},32))!=c || query(table,host)!=a) return false;
        if (!permitted(table.view(a),host) || permitted(table.view(b),host) || permitted(table.view(c),host) || permitted(table.view(a),v4({10,42,8,1},32))) return false;
        // Exact reassignment wins over the former owner, even when a stale
        // configuration cleanup later tries to remove the same prefix.
        if (!table.assign(b,host) || query(table,host)!=b || table.status().prefixes!=4) return false;
        auto not_owner=table.unassign(a,host);
        if (not_owner || not_owner.error()!=RouteError::not_owner || query(table,host)!=b) return false;
        if (!table.unassign(b,host) || query(table,host)!=c || table.status().prefixes!=3) return false;
        if (!table.erase(c) || query(table,host)!=b || !table.erase(b) || query(table,host)!=a || !table.unassign(a,defaults) || query(table,host)) return false;
        return !table.status().prefixes;
    }
    auto ipv6_and_non_byte_prefixes() -> bool {
        RouteTable<3,8> table;
        if (!table.activate(a) || !table.activate(b) || !table.activate(c) || !table.assign(a,v6({},0))) return false;
        auto p33=v6({0x20,1,0x0d,0xb8,0x80},33);
        auto p65=v6({0x20,1,0x0d,0xb8,0x80,0,0,0,0x80},65);
        auto p128=v6({0x20,1,0x0d,0xb8,0x80,0,0,0,0x80,0,0,0,0,0,0,1},128);
        if (!table.assign(b,p33) || !table.assign(c,p65) || !table.assign(b,p128)) return false;
        if (query(table,p128)!=b || query(table,v6({0x20,1,0x0d,0xb8,0x80,0,0,0,0x80,0,0,0,0,0,0,2},128))!=c ||
            query(table,v6({0x20,1,0x0d,0xb8,0x80,0,0,0,0x7f},128))!=b || query(table,v6({0x20,1,0x0d,0xb8,0x7f},128))!=a) return false;
        if (!permitted(table.view(b),p128) || permitted(table.view(c),p128) || !table.assign(c,p128) || query(table,p128)!=c) return false;
        // IPv4 /1 checks the high bit; it must not affect the IPv6 defaults.
        auto high=v4({128,0,0,0},1);
        if (!table.assign(b,high) || query(table,v4({255,255,255,255},32))!=b || query(table,v4({127,255,255,255},32))) return false;
        auto invalid=p65; invalid.address[8]=0x81;
        if (table.assign(a,invalid) || !table.unassign(c,p128) || query(table,p128)!=c) return false;
        return table.status().prefixes==4;
    }
    auto generation_tombstones() -> bool {
        RouteTable<3,8> table;
        auto defaults=v4({},0),specific=v4({10,42,0,0},16),host=v4({10,42,0,1},32);
        if (!table.activate(a) || !table.activate(b) || !table.assign(a,defaults) || !table.assign(b,specific)) return false;
        auto old_view=table.view(b);
        if (!permitted(old_view,host) || !table.erase(b) || permitted(old_view,host) || query(table,host)!=a || table.activate(b) || table.erase(b)) return false;
        PeerHandle b2{b.slot,2};
        if (!table.activate(b2) || table.valid(b) || table.assign(b,specific) || table.unassign(b,defaults) || !table.assign(b2,specific)) return false;
        if (permitted(old_view,host) || query(table,host)!=b2 || table.erase(b) || table.activate(b) || query(table,host)!=b2) return false;
        // A higher generation may replace an active slot in one operation;
        // every old route is removed before the new generation is published.
        PeerHandle b3{b.slot,3}; auto b2_view=table.view(b2);
        if (!table.activate(b3) || table.valid(b2) || permitted(b2_view,host) || query(table,host)!=a || table.status().prefixes!=1) return false;
        if (!table.assign(b3,specific) || table.erase(b2) || query(table,host)!=b3 || !permitted(table.view(b3),host)) return false;
        RouteTable<1,1> exhausted; PeerHandle last{0,std::numeric_limits<std::uint64_t>::max()};
        if (!exhausted.activate(last) || !exhausted.assign(last,defaults) || !exhausted.erase(last) || exhausted.activate(last) || exhausted.activate(a)) return false;
        return table.status().peers==2 && !exhausted.status().prefixes && !exhausted.status().peers;
    }
    auto capacity_failure_and_slot_reuse() -> bool {
        RouteTable<3,3> table;
        if (!table.activate(a) || !table.activate(b) || !table.activate(c)) return false;
        auto first=v4({},0),second=v4({10,0,0,0},8),third=v6({},0),extra=v4({192,0,2,0},24);
        if (!table.assign(a,first) || !table.assign(b,second) || !table.assign(c,third)) return false;
        auto before=table.status(); auto full=table.assign(b,extra);
        if (full || full.error()!=RouteError::full || table.status().prefixes!=before.prefixes || table.status().peers!=before.peers ||
            query(table,v4({192,0,2,1},32))!=a || query(table,v4({10,0,0,1},32))!=b || query(table,v6({0x20,1},128))!=c) return false;
        if (!table.assign(a,second) || query(table,v4({10,0,0,1},32))!=a || table.status().prefixes!=3) return false;
        if (!table.unassign(a,second) || !table.assign(b,extra) || table.status().prefixes!=3 || query(table,v4({192,0,2,1},32))!=b) return false;
        if (!table.erase(b) || !table.assign(c,second) || table.status().prefixes!=3 || query(table,v4({10,0,0,1},32))!=c) return false;
        if (!table.erase(c) || table.status().prefixes!=1 || !table.assign(a,extra) || !table.assign(a,third) || table.status().prefixes!=3) return false;
        auto bad=extra; bad.address[3]=1;
        if (table.assign(a,bad) || table.status().prefixes!=3 || query(table,v4({192,0,2,1},32))!=a) return false;
        return true;
    }
    auto every_prefix_boundary() -> bool {
        RouteTable<3,2> table;
        if (!table.activate(a) || !table.activate(b)) return false;
        for (auto family:{std::uint8_t{4},std::uint8_t{6}}) {
            auto limit=family==4 ? 32u : 128u;
            Prefix defaults{family,{},0}; if (!table.assign(a,defaults)) return false;
            for (unsigned bits=1;bits<=limit;++bits) {
                Prefix prefix{family,{},static_cast<std::uint8_t>(bits)};
                for (unsigned bit=0;bit<bits;++bit) if ((bit*5+3)%11<5) prefix.address[bit/8]|=static_cast<std::uint8_t>(1u<<(7-bit%8));
                auto inside=prefix;
                for (unsigned bit=bits;bit<limit;++bit) if (bit%3) inside.address[bit/8]|=static_cast<std::uint8_t>(1u<<(7-bit%8));
                auto outside=inside; outside.address[(bits-1)/8]^=static_cast<std::uint8_t>(1u<<(7-(bits-1)%8));
                if (!table.assign(b,prefix) || query(table,inside)!=b || query(table,outside)!=a ||
                    !permitted(table.view(b),inside) || permitted(table.view(a),inside) || permitted(table.view(b),outside)) return false;
                if (!table.unassign(b,prefix)) return false;
            }
            if (!table.unassign(a,defaults) || table.status().prefixes) return false;
        }
        return true;
    }
    auto default_capacity_1024() -> bool {
        RouteTable<> table;
        if (!table.activate(a) || !table.activate(b)) return false;
        auto route=[](unsigned index) { return v4({10,42,static_cast<std::uint8_t>(index>>8),static_cast<std::uint8_t>(index)},32); };
        for (unsigned i=0;i<1024;++i) if (!table.assign(a,route(i))) return false;
        auto extra=v4({10,43,0,1},32);
        auto full=table.assign(b,extra);
        if (full || full.error()!=RouteError::full || table.status().prefixes!=1024 || table.status().peers!=2 || query(table,extra)) return false;
        for (unsigned i=0;i<1024;++i) if (query(table,route(i))!=a) return false;
        if (!table.assign(b,route(511)) || table.status().prefixes!=1024 || query(table,route(511))!=b || !table.erase(b)) return false;
        if (query(table,route(511)) || table.status().prefixes!=1023 || !table.assign(a,extra) || table.status().prefixes!=1024) return false;
        if (!table.erase(a) || table.status().prefixes || table.status().peers) return false;
        PeerHandle a2{a.slot,2}; if (!table.activate(a2)) return false;
        for (unsigned i=0;i<1024;++i) if (!table.assign(a2,route(i))) return false;
        if (table.assign(a,extra) || table.erase(a) || table.status().prefixes!=1024) return false;
        for (unsigned i=0;i<1024;++i) if (query(table,route(i))!=a2) return false;
        return true;
    }
}

auto main() -> int {
    if (!defaults_and_validation()) { std::println("WireGuard routing defaults/validation failed"); return 1; }
    if (!ipv4_overlap_and_exact_updates()) { std::println("WireGuard routing IPv4 LPM/exact reassignment failed"); return 2; }
    if (!ipv6_and_non_byte_prefixes()) { std::println("WireGuard routing IPv6/non-byte prefixes failed"); return 3; }
    if (!generation_tombstones()) { std::println("WireGuard routing peer generation/tombstones failed"); return 4; }
    if (!capacity_failure_and_slot_reuse()) { std::println("WireGuard routing capacity rollback/slot reuse failed"); return 5; }
    if (!every_prefix_boundary()) { std::println("WireGuard routing every IPv4/IPv6 prefix boundary failed"); return 6; }
    if (!default_capacity_1024()) { std::println("WireGuard routing 1024-slot full/retire/refill failed"); return 7; }
    std::println("WireGuard fixed global LPM routing, exact owner update, source policy, peer tombstones and capacity rollback passed; sizeof table32/1024={} view={}",sizeof(RouteTable<>),sizeof(SourcePolicyView));
}
