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
inbound "tun" type="tun" {{
    inet4-address "198.51.100.1/32"
    {}
}}
outbound "direct" type="direct"
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
             "auto-route #true; auto-redirect #true; route-address-set \"rs\"",
             "auto-route #true; auto-redirect #true; auto-redirect #false","auto-redirect \"true\""})
            check(!parse(spec),spec);

        // FakeIP IPv4 CIDR validation rejects /31 and /32 while accepting /30
        auto parse_fakeip=[](std::string_view cidr) {
            return config::parse_kdl(std::format(R"kdl(schema-version 1
role "client"
inbound "s" type="socks5" {{ listen host="127.0.0.1" port=1080; authentication "none"; }}
outbound "direct" type="direct"
dns {{
    listen host="127.0.0.1" port=1053
    server "up" type="udp" host="127.0.0.1" port=5353
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
