#include <csignal>
import std;
import relay;
namespace { volatile std::sig_atomic_t stopped=0; void stop(int) { stopped=1; } }
auto main(int argc,char** argv) -> int {
    if (argc<4 || argc>6) return 1;
    auto inbound=std::stoul(argv[1]), upstream=std::stoul(argv[2]), size=std::stoul(argv[3]);
    auto workers=argc>=5 ? std::stoul(argv[4]) : 1;
    auto legacy=argc==6 && std::string_view(argv[5])=="legacy";
    if (argc==6 && !legacy) return 1;
    if (inbound>65535 || upstream>65535 || (size!=16 && size!=32) || workers<1 || workers>16) return 2;
    std::array<std::uint8_t,32> psk{}; for (std::size_t i=0;i<size;++i) psk[i]=static_cast<std::uint8_t>(i);
    auto server=relay::Server::create(); if (!server) return 3;
    if ((*server)->add_shadowsocks("127.0.0.1",static_cast<std::uint16_t>(upstream),std::span{psk}.first(15))) return 6;
    auto index=(*server)->add_shadowsocks("127.0.0.1",static_cast<std::uint16_t>(upstream),std::span{psk}.first(size));
    if (!index) return 4;
    if (legacy) {
        if (!(*server)->set_block_rules("schema-version 2\nkind \"predicate\"\n",relay::RuleFormat::kdl)) return 4;
    } else if (!(*server)->set_indexed_routes({},*index)) return 4;
    auto port=(*server)->start(static_cast<std::uint16_t>(inbound),relay::Inbound::socks5,workers); if (!port) return 5;
    if ((*server)->add_shadowsocks("127.0.0.1",static_cast<std::uint16_t>(upstream),std::span{psk}.first(size))) return 7;
    std::signal(SIGTERM,stop); std::signal(SIGINT,stop);
    std::cout << *port << std::endl;
    while (!stopped && (*server)->healthy()) (*server)->poll(std::chrono::milliseconds(20));
    (*server)->stop(); return 0;
}
