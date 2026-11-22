import std;
import proxy;

#ifdef NEXUS_TEST_DNS_SHARED_ACCESS
extern "C" void nexus_test_dns_shared_access(void const*) noexcept {}
#endif

auto main(int argc,char** argv) -> int {
    if (argc!=7 && argc!=8) return 1;
    auto ss_port=std::stoul(argv[1]), vless_port=std::stoul(argv[2]);
    auto order=std::stoul(argv[5]), workers=std::stoul(argv[6]);
    if (!ss_port || ss_port>65535 || !vless_port || vless_port>65535 || order>1 || workers<1 || workers>2) return 2;
    std::array<std::uint8_t,16> key{};
    for (std::size_t i=0;i<key.size();++i) key[i]=static_cast<std::uint8_t>(i);
    auto server=proxy::Server::create();
    if (!server) return 3;
    auto add_ss=[&] { return (*server)->add_shadowsocks("127.0.0.1",static_cast<std::uint16_t>(ss_port),key); };
    auto add_vless=[&] { return (*server)->add_vless("127.0.0.1",static_cast<std::uint16_t>(vless_port),argv[3],"cover.example",argv[4]); };
    auto first=order ? add_vless() : add_ss();
    auto second=order ? add_ss() : add_vless();
    if (!first || !second || *first!=2 || *second!=3) return 4;
    auto ss_index=order ? *second : *first;
    auto vless_index=order ? *first : *second;
    if (argc==8) {
        if (std::string_view(argv[7])!="reverse") return 7;
        std::swap(ss_index,vless_index);
    }
    constexpr auto rule="schema-version 1\nkind \"predicate\"\nrule type=\"ip-cidr\" value=\"127.0.0.2/32\"\n";
    proxy::IndexedRouteRule routes[]{{rule,proxy::RuleFormat::kdl,ss_index}};
    if (!(*server)->set_indexed_routes(routes,vless_index)) return 5;
    auto port=(*server)->start(0,proxy::Inbound::socks5,workers);
    if (!port) return 6;
    std::atomic_bool stopped=false;
    std::jthread control([&] { std::string line; std::getline(std::cin,line); stopped=true; });
    std::cout << *port << std::endl;
    while (!stopped && (*server)->healthy()) (*server)->poll(std::chrono::milliseconds(20));
    (*server)->stop();
    return 0;
}
