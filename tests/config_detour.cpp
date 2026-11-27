import std;
import config;

namespace {
    auto ss(std::string_view name,std::string_view extra={}) -> std::string {
        return std::format(R"(outbound "{}" type="shadowsocks" {{ server host="127.0.0.1" port=443; method "2022-blake3-aes-128-gcm"; key-file "/key"; {} }}
)",name,extra);
    }
    auto parse(std::string nodes,std::string_view extra_top={}) {
        return config::parse_kdl(std::string(R"(schema-version 1
role "client"
inbounds { inbound "in" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
outbounds {
outbound "direct" type="direct"
outbound "block" type="block"
)")+nodes+"}\n"+std::string(extra_top)+R"(routing { final "exit"; }
)");
    }
}
int main() {
    auto middle=R"(outbound "middle" type="vless" {
server host="middle.test" port=443
detour "front"
authentication { uuid-file "/uuid"; }
tls { server-name "middle.test"; ca-file "/ca"; verify #true; }
}
)";
    // Forward references cross the parser's protocol-specific index ranges.
    auto result=parse(ss("exit","detour \"middle\";")+middle+ss("front"));
    if (!result || result->default_outbound!=3 || result->vless_outbounds[0].config.detour_index!=4 ||
        result->shadowsocks_outbounds[0].config.detour_index!=2 || !result->vless || result->vless->detour_index!=4) return 1;
    auto direct=parse(ss("exit","detour \"direct\";"));
    if (!direct || direct->shadowsocks_outbounds[0].config.detour_index!=0) return 2;
    for (auto extra:{"detour \"missing\";", "detour \"block\";", "detour \"exit\";", "detour 2;",
                    "detour \"direct\"; detour \"direct\";", "detour \"direct\" x=1;", "detour \"direct\" { x; };"})
        if (parse(ss("exit",extra))) return 3;
    if (parse(ss("exit","detour \"middle\";")+middle+ss("front","detour \"exit\";"))) return 4;
    if (parse(ss("exit")+ss("orphan"))) return 5;
    std::string chain=ss("exit","detour \"n1\";");
    for (unsigned i=1;i<16;++i)
        chain+=ss(std::format("n{}",i),i==15 ? "" : std::format("detour \"n{}\";",i+1));
    if (!parse(chain) || parse(chain+ss("overflow","detour \"exit\";"))) return 6;
    auto dns=R"(dns { servers { server "boot" type="udp" host="127.0.0.1"; }; }
)";
    auto with_dns=parse(std::string(middle)+ss("front")+
        R"(outbound "exit" type="shadowsocks" { server host="exit.test" port=443; bootstrap-resolver "boot"; detour "middle"; method "2022-blake3-aes-128-gcm"; key-file "/key"; }
)",dns);
    if (!with_dns || with_dns->shadowsocks_outbounds[1].config.bootstrap_index!=0) return 7;
    std::println("Detour configuration references, mixed chains, bounds and cycles passed");
}
