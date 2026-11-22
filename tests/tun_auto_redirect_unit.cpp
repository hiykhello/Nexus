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
             "auto-route #true; auto-redirect #true; auto-redirect #false","auto-redirect \"true\""})
            check(!parse(spec),spec);
    }
}
int main() {
    wire();
    configuration();
    std::cout << "PASS nftables install and atomic remove encoding, auto-redirect configuration constraints\n";
}
