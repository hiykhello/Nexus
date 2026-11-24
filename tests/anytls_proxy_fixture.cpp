import std;
import relay;
using namespace std::chrono_literals;
auto main(int argc,char** argv) -> int {
    if (argc!=7 && argc!=8) return 64;
    auto number=[](char const* text) -> unsigned {
        unsigned value=0; auto end=text+std::char_traits<char>::length(text); auto parsed=std::from_chars(text,end,value);
        return parsed.ec==std::errc{} && parsed.ptr==end ? value : 0;
    };
    auto peer=number(argv[1]),workers=number(argv[4]),idle=number(argv[5]),maximum=number(argv[6]);
    if (!peer || peer>65535 || !workers || workers>2 || idle>maximum || !maximum || maximum>256) return 64;
    auto created=relay::Server::create(); if (!created) return 65;
    auto& server=**created;
    std::optional<std::size_t> lower;
    if (argc==8) {
        auto port=number(argv[7]); if (!port || port>65535) return 64;
        auto added=server.add_trojan("127.0.0.1",port,argv[2],"localhost",argv[3]);
        if (!added) { std::cerr<<added.error()<<std::endl; return 66; }
        lower=*added;
    }
    auto outbound=server.add_anytls("127.0.0.1",peer,argv[2],"localhost",argv[3],relay::TlsKeyExchange::x25519,{},3000,{},
        {.max_sessions=maximum,.min_idle=idle,.idle_timeout=100ms,.check_interval=10ms});
    if (!outbound) { std::cerr<<outbound.error()<<std::endl; return 67; }
    if (lower) {
        std::array detours{relay::OutboundDetour{*outbound,*lower}};
        if (!server.set_outbound_detours(detours)) return 68;
    }
    if (!server.set_indexed_routes({},*outbound)) return 69;
    auto port=server.start(0,relay::Inbound::socks5,workers);
    if (!port) { std::cerr<<port.error().message()<<std::endl; return 70; }
    std::atomic_int command=0;
    std::jthread control([&] {
        std::string line;
        while (std::getline(std::cin,line)) {
            if (line=="r") command=1;
            else { command=2; return; }
        }
        command=2;
    });
    std::cout<<*port<<std::endl;
    for (;;) {
        server.poll(5ms);
        auto current=command.exchange(0);
        if (!server.healthy()) { server.stop(); std::_Exit(71); }
        if (current) {
            server.stop();
            if (current==2) return 0;
            port=server.start(0,relay::Inbound::socks5,workers);
            if (!port) std::_Exit(72);
            std::cout<<*port<<std::endl;
        }
    }
}
