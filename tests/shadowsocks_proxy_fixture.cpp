#include <csignal>
import std;
import nexus.proxy;
namespace { volatile std::sig_atomic_t stopped=0; void stop(int) { stopped=1; } }
auto main(int argc,char** argv) -> int {
    if (argc!=4) return 1;
    auto inbound=std::stoul(argv[1]), upstream=std::stoul(argv[2]), size=std::stoul(argv[3]);
    if (inbound>65535 || upstream>65535 || (size!=16 && size!=32)) return 2;
    std::array<std::uint8_t,32> psk{}; for (std::size_t i=0;i<size;++i) psk[i]=static_cast<std::uint8_t>(i);
    auto server=nexus::proxy::Server::create(); if (!server) return 3;
    if ((*server)->add_shadowsocks("127.0.0.1",static_cast<std::uint16_t>(upstream),std::span{psk}.first(15))) return 6;
    auto index=(*server)->add_shadowsocks("127.0.0.1",static_cast<std::uint16_t>(upstream),std::span{psk}.first(size));
    if (!index || !(*server)->set_indexed_routes({},*index)) return 4;
    auto port=(*server)->start(static_cast<std::uint16_t>(inbound)); if (!port) return 5;
    if ((*server)->add_shadowsocks("127.0.0.1",static_cast<std::uint16_t>(upstream),std::span{psk}.first(size))) return 7;
    std::signal(SIGTERM,stop); std::signal(SIGINT,stop);
    std::cout << *port << std::endl;
    while (!stopped && (*server)->healthy()) (*server)->poll(std::chrono::milliseconds(20));
    (*server)->stop(); return 0;
}
