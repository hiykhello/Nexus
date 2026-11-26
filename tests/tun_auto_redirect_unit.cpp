import std;
import config;
import platform.nftables;

namespace {
    namespace nft=platform::nftables;
    auto check(bool good,std::string_view label) -> void {
        if (!good) throw std::runtime_error(std::string(label));
    }
    template<class T> auto read(std::span<std::uint8_t const> bytes,std::size_t pos) -> T {
        std::array<std::uint8_t,sizeof(T)> storage;
        check(pos+storage.size()<=bytes.size(),"field bounds");
        std::ranges::copy(bytes.subspan(pos,storage.size()),storage.begin());
        return std::bit_cast<T>(storage);
    }
    auto commands(nft::Transaction const& transaction) -> std::vector<std::uint16_t> {
        std::vector<std::uint16_t> result;
        auto sequence=std::uint32_t(129);
        for (auto pos=std::size_t{};pos<transaction.bytes.size();) {
            auto bytes=std::span(transaction.bytes).subspan(pos);
            auto size=read<std::uint32_t>(bytes,0);
            auto type=read<std::uint16_t>(bytes,4);
            auto flags=read<std::uint16_t>(bytes,6);
            check(size>=20 && size<=bytes.size() && size%4==0,"aligned netlink length");
            check(read<std::uint32_t>(bytes,8)==sequence++,"netlink sequence");
            check(bool(flags&1),"request flag");
            if (type==16 || type==17)
                check(bytes[16]==0 && bytes[18]==0 && bytes[19]==10,"batch fence family and subsystem");
            else check(bytes[16]==1 && (flags&4),"inet operation with ACK");
            result.push_back(type);
            pos+=size;
        }
        check(sequence==transaction.end,"sequence after end");
        return result;
    }
    auto wire() -> void {
        constexpr auto table="nexus_auto_redirect_123";
        nft::Prefix private_ip{4,8,{10}};
        nft::Redirect redirect{.port=32123,.ipv4=true,.ipv6=true,.intercept_dns=true,.socket_mark=42,
            .excludes=std::span(&private_ip,1)};
        auto install=nft::encode(table,&redirect,129);
        check(install.has_value(),"encode install");
        auto result=commands(*install);
        check(result.front()==16 && result[1]==0xa00 && result.back()==17,"creation transaction fences");
        check(std::ranges::count(result,0xa03)==2 && std::ranges::count(result,0xa06)>=12,"both chains and rules");
        auto removal=nft::encode(table,nullptr,129);
        check(removal && commands(*removal)==std::vector<std::uint16_t>{16,0xa02,17},"single atomic DELTABLE");
        check(!nft::encode("inet_filter",nullptr,129),"foreign name rejected");
        redirect.port=0;
        check(!nft::encode(table,&redirect,129),"absent listener rejected");

        // Verify prerouting orders listener-port guard -> protected/FakeIP -> intercept_dns -> local_destinations -> excludes
        nft::Prefix local_ip{4,32,{192,168,1,1}};
        nft::Prefix fake_ip{4,29,{198,18,0,0}};
        nft::Redirect ordered{.port=32123,.ipv4=true,.ipv6=true,.intercept_dns=true,.socket_mark=42,
            .excludes=std::span(&private_ip,1),.protected_destinations=std::span(&fake_ip,1),
            .local_destinations=std::span(&local_ip,1)};
        auto enc_ordered=nft::encode(table,&ordered,129);
        check(enc_ordered.has_value(),"encode ordered prerouting");
        auto contains_seq=[](std::span<std::uint8_t const> hay, std::span<std::uint8_t const> needle) {
            return std::ranges::search(hay,needle).begin()!=hay.end();
        };
        auto contains_str=[&](std::span<std::uint8_t const> hay, std::string_view s) {
            return contains_seq(hay,{reinterpret_cast<std::uint8_t const*>(s.data()),s.size()});
        };
        std::size_t guard_idx=999, fake_idx=999, dns_idx=999, local_idx=999, excl_idx=999, rule_idx=0;
        constexpr std::array<std::uint8_t,4> local_b{192,168,1,1}, fake_b{198,18,0,0}, excl_b{10,0,0,0};
        constexpr std::array<std::uint8_t,2> port_b{0x7d,0x7b}, dns_b{0,53};
        for (std::size_t pos=0;pos<enc_ordered->bytes.size();) {
            auto msg=std::span(enc_ordered->bytes).subspan(pos);
            auto size=read<std::uint32_t>(msg,0);
            auto type=read<std::uint16_t>(msg,4);
            auto body=msg.first(size);
            if (type==0xa06 && contains_str(body,"prerouting")) {
                bool is_redir=contains_str(body,std::string_view("redir\0",6));
                if (!is_redir && contains_seq(body,local_b) && contains_seq(body,port_b)) guard_idx=rule_idx;
                else if (is_redir && contains_seq(body,fake_b)) fake_idx=rule_idx;
                else if (is_redir && contains_seq(body,dns_b)) dns_idx=rule_idx;
                else if (!is_redir && contains_seq(body,local_b)) local_idx=rule_idx;
                else if (!is_redir && contains_seq(body,excl_b)) excl_idx=rule_idx;
                ++rule_idx;
            }
            pos+=size;
        }
        check(guard_idx<fake_idx && fake_idx<dns_idx && dns_idx<local_idx && local_idx<excl_idx,
            "prerouting rule order: port guard < fakeip < dns < local_destinations < excludes");

        // Self-port 53 skips intercept_dns rule to prevent redirect loop
        nft::Redirect p32123{.port=32123,.ipv4=true,.ipv6=false,.intercept_dns=true,.socket_mark=42};
        nft::Redirect p53{.port=53,.ipv4=true,.ipv6=false,.intercept_dns=true,.socket_mark=42};
        auto e32123=nft::encode(table,&p32123,129), e53=nft::encode(table,&p53,129);
        check(e32123 && e53 &&
            std::ranges::count(commands(*e53),0xa06)+2==std::ranges::count(commands(*e32123),0xa06),
            "port 53 skips intercept_dns to avoid self-redirect loop");
    }

    auto configuration() -> void {
        auto parse=[](std::string_view fields) {
            return config::parse_kdl(std::format(R"kdl(schema-version 1
role "client"
inbounds {{
    inbound "tun" type="tun" {{
        inet4-address "198.51.100.1/32"
        {}
    }}
}}
outbounds {{ outbound "direct" type="direct"; }}
routing {{ default-outbound "direct"; }}
)kdl",fields));
        };
        auto enabled=parse("auto-route #true; auto-redirect #true");
        check(enabled && enabled->inbounds[0].tun->strict_route && enabled->inbounds[0].tun->socket_mark,
            "auto-redirect implies supervised strict route");
        auto disabled=parse("auto-route #true");
        check(disabled && !disabled->inbounds[0].tun->auto_redirect,"opt in only");
        for (auto spec:{"auto-redirect #true","auto-route #true; auto-redirect #true; device-fd 4",
             "auto-route #true; auto-redirect #true; strict-route #false",
             "auto-route #true; auto-redirect #true; connect-ip-outbound \"peer\"",
             "auto-route #true; auto-redirect #true; auto-redirect #false","auto-redirect \"true\""})
            check(!parse(spec),spec);

        // Wave 30D: auto-redirect combined with route-address-set, route-address, TPROXY mark, MAC filters, gso
        auto combined=config::parse_kdl(R"kdl(schema-version 1
role "client"
inbounds {
    inbound "tun" type="tun" {
        inet4-address "198.51.100.1/32"
        inet6-address "2001:db8:1::1/128"
        auto-route #true
        auto-redirect #true
        auto-redirect-tproxy-mark 0x4444
        auto-redirect-tproxy-port 15444
        include-mac-address "aa:bb:cc:dd:ee:01"
        exclude-mac-address "11-22-33-44-55-66"
        route-address "192.0.2.0/24"
        route-address "192.0.2.42/24"
        route-address-set "rs"
        gso #true
    }
}
outbounds { outbound "direct" type="direct"; }
routing {
    rule-set "rs" format="kdl" path="rs.kdl"
    default-outbound "direct"
}
)kdl");
        check(combined.has_value(),"auto-redirect + route-address-set + route-address + tproxy-mark + MAC + gso accepted");
        auto const& ct=*combined->inbounds[0].tun;
        check(ct.gso && ct.route_includes.size()==1 && ct.route_address_sets.size()==1 &&
            ct.extra.auto_redirect_tproxy_mark==0x4444u && ct.extra.auto_redirect_tproxy_port==15444u &&
            ct.extra.include_mac_addresses.size()==1 && ct.extra.include_mac_addresses[0][5]==0x01u &&
            ct.extra.exclude_mac_addresses.size()==1 && ct.extra.exclude_mac_addresses[0][0]==0x11u,
            "parsed Wave 30D TUN fields and deduplicated equivalent route-address CIDRs");
        check(!parse("auto-route #true; include-mac-address \"aa:bb:cc:dd:ee:01\""),"MAC filter requires auto-redirect");
        check(!parse("auto-route #true; auto-redirect #true; include-mac-address \"bad\""),"invalid MAC rejected");
        check(!parse("auto-route #true; auto-redirect-tproxy-mark 0x4444"),"tproxy-mark requires auto-redirect");
        check(!parse("auto-route #true; auto-redirect #true; auto-redirect-tproxy-mark 0"),"zero tproxy-mark rejected");
        check(!parse("auto-route #true; auto-redirect-tproxy-port 15444"),"tproxy-port requires auto-redirect");
        check(!parse("auto-route #true; auto-redirect #true; auto-redirect-tproxy-port 0"),"zero tproxy-port rejected");

        // Wave 30D: include-package & mutual exclusion with exclude-package & >64 packages/CIDRs
        std::string pkgs;
        for (int i=0;i<80;++i) pkgs+=std::format("include-package \"com.example.app{}\"\n",i);
        auto inc_pkg=parse(pkgs);
        check(inc_pkg && inc_pkg->inbounds[0].tun->include_packages.size()==80,"include-package supports >64 up to 256");
        check(!parse("include-package \"com.example.a\"; exclude-package \"com.example.b\""),"include/exclude-package mutually exclusive");
        check(!parse("auto-route #true; strict-route #true; include-package \"com.example.a\""),"include-package rejected with strict-route");
        check(parse("vnet-hdr #true")->inbounds[0].tun->gso,"vnet-hdr alias sets gso");

        // Wave 30D: >64 direct route-address and route-exclude CIDRs + duplicate CIDR deduplication
        std::string many_cidrs="auto-route #true; strict-route #true\n";
        for (int i=0;i<90;++i) {
            many_cidrs+=std::format("route-address \"198.18.{}.0/24\"\n",i);
            many_cidrs+=std::format("route-exclude \"198.19.{}.0/24\"\n",i);
        }
        many_cidrs+="route-address \"198.18.0.0/24\"\nroute-exclude \"198.19.0.5/24\"\n";
        auto big_cfg=parse(many_cidrs);
        check(big_cfg && big_cfg->inbounds[0].tun->route_includes.size()==90 &&
            big_cfg->inbounds[0].tun->route_excludes.size()==90,">64 route-address/route-exclude parsed and deduplicated");

        // Wave 30D: nftables interval sets (>64 excludes + includes), UDP TPROXY lo-order, iiftype ether, atomic replace
        std::vector<nft::Prefix> big_exc, big_inc;
        for (int i=0;i<80;++i) {
            big_exc.push_back({4,24,{198,19,static_cast<std::uint8_t>(i),0}});
            big_inc.push_back({4,24,{198,18,static_cast<std::uint8_t>(i),0}});
        }
        std::array<std::array<std::uint8_t,6>,1> inc_mac{{{0xaa,0xbb,0xcc,0xdd,0xee,0x01}}};
        std::array<std::array<std::uint8_t,6>,1> exc_mac{{{0x11,0x22,0x33,0x44,0x55,0x66}}};
        nft::Redirect full_rd{
            .port=32123,.ipv4=true,.ipv6=true,.intercept_dns=true,.socket_mark=42,
            .excludes=big_exc,.includes=big_inc,.tproxy_mark=0x4444u,.tproxy_port=15444u,
            .include_macs=inc_mac,.exclude_macs=exc_mac
        };
        auto enc_full=nft::encode("nexus_auto_redirect_w30d",&full_rd,129,false);
        check(enc_full.has_value(),"encode full Wave 30D nftables");
        auto full_cmds=commands(*enc_full);
        check(std::ranges::count(full_cmds,0xa09)==2,"NEWSET emitted for excl_v4 and incl_v4");
        check(std::ranges::count(full_cmds,0xa0c)>=2,"NEWSETELEM emitted for interval sets");
        check(std::ranges::count(full_cmds,0xa03)==4,"4 chains emitted (output, prerouting, tproxy_output, tproxy_prerouting)");
        auto has_bytes=[](std::span<std::uint8_t const> hay, std::string_view needle) {
            auto n=std::span<std::uint8_t const>(reinterpret_cast<std::uint8_t const*>(needle.data()),needle.size());
            return std::ranges::search(hay,n).begin()!=hay.end();
        };
        check(has_bytes(enc_full->bytes,"lookup") && has_bytes(enc_full->bytes,"tproxy") &&
            has_bytes(enc_full->bytes,"incl_v4") && has_bytes(enc_full->bytes,"excl_v4"),
            "nftables encodes lookup sets and tproxy expressions");
        check(std::ranges::search(enc_full->bytes,inc_mac[0]).begin()!=enc_full->bytes.end() &&
            std::ranges::search(enc_full->bytes,exc_mac[0]).begin()!=enc_full->bytes.end(),
            "nftables encodes include/exclude Ethernet MAC bytes");
        // Verify tproxy_prerouting places marked loopback tproxy rule BEFORE iifname=="lo" bypass, and MAC rules guard with iiftype==ARPHRD_ETHER
        std::size_t tp_lo_divert=999, tp_lo_bypass=999, tp_idx=0;
        bool saw_iiftype_guard=false;
        constexpr std::array<std::uint8_t,16> lo_name{'l','o'};
        constexpr std::array<std::uint8_t,4> iiftype_attr{0,0,0,8}; // NFT_META_IIFTYPE (NFT_META_IFTYPE == 8) big-endian u32
        for (std::size_t pos=0;pos<enc_full->bytes.size();) {
            auto msg=std::span(enc_full->bytes).subspan(pos);
            auto size=read<std::uint32_t>(msg,0);
            auto type=read<std::uint16_t>(msg,4);
            auto body=msg.first(size);
            if (type==0xa06 && has_bytes(body,"tproxy_prerouting")) {
                bool is_tp=has_bytes(body,std::string_view("tproxy\0",7));
                bool is_lo=std::ranges::search(body,lo_name).begin()!=body.end();
                if (is_tp && is_lo && tp_lo_divert==999) tp_lo_divert=tp_idx;
                if (!is_tp && is_lo && tp_lo_bypass==999) tp_lo_bypass=tp_idx;
                if (std::ranges::search(body,inc_mac[0]).begin()!=body.end() &&
                    std::ranges::search(body,iiftype_attr).begin()!=body.end()) saw_iiftype_guard=true;
                ++tp_idx;
            }
            pos+=size;
        }
        check(tp_lo_divert<tp_lo_bypass,"tproxy_prerouting marked-lo tproxy precedes iifname==lo bypass");
        check(saw_iiftype_guard,"include_macs rule includes meta iiftype ether guard");
        auto enc_repl=nft::encode("nexus_auto_redirect_w30d",&full_rd,129,true);
        check(enc_repl.has_value(),"encode atomic replace nftables");
        auto repl_cmds=commands(*enc_repl);
        check(repl_cmds.size()>3 && repl_cmds[1]==0xa02 && repl_cmds[2]==0xa00,
            "atomic replace emits DELTABLE then NEWTABLE in one batch");

        // FakeIP IPv4 CIDR validation rejects /31 and /32 while accepting /30
        auto parse_fakeip=[](std::string_view cidr) {
            return config::parse_kdl(std::format(R"kdl(schema-version 1
role "client"
inbounds {{ inbound "s" type="socks5" {{ listen host="127.0.0.1" port=1080; authentication "none"; }}; }}
outbounds {{ outbound "direct" type="direct"; }}
dns {{
    listen host="127.0.0.1" port=1053
    servers {{ server "up" type="udp" host="127.0.0.1" port=5353; }}
    fake-ip server="up" ipv4-pool="{}" state-directory="/tmp/fakeip"
    final "up"
}}
routing {{ default-outbound "direct"; }}
)kdl",cidr));
        };
        check(parse_fakeip("198.18.0.0/30").has_value(),"fake-ip /30 accepted");
        check(!parse_fakeip("198.18.0.0/31").has_value(),"fake-ip /31 rejected");
        check(!parse_fakeip("198.18.0.0/32").has_value(),"fake-ip /32 rejected");
    }
}
int main() {
    wire();
    configuration();
    std::cout << "PASS nftables install and atomic remove encoding, auto-redirect configuration constraints\n";
}
