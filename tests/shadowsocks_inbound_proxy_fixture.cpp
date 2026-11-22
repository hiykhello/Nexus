#include <csignal>
import std;
import proxy;
namespace { volatile std::sig_atomic_t stopped=0,restart=0; void stop(int) { stopped=1; } void restart_server(int) { restart=1; } }
auto main(int argc,char** argv) -> int {
    if (argc!=3) return 1;
    auto size=std::stoul(argv[1]),workers=std::stoul(argv[2]);
    if ((size!=16 && size!=32) || workers<1 || workers>16) return 2;
    std::array<std::uint8_t,32> key{}; for (std::size_t i=0;i<size;++i) key[i]=static_cast<std::uint8_t>(i);
    auto server=proxy::Server::create(); if (!server) return 3;
    if ((*server)->prepare_shadowsocks_inbound(std::span{key}.first(15))) return 4;
    if (!(*server)->prepare_shadowsocks_inbound(std::span{key}.first(size))) return 5;
    auto port=(*server)->start(0,proxy::Inbound::shadowsocks,workers); if (!port) return 6;
    if ((*server)->prepare_shadowsocks_inbound(std::span{key}.first(size))) return 7;
    auto second=proxy::Server::create(); if (!second) return 9;
    if (!(*second)->prepare_shadowsocks_inbound(std::span{key}.first(size))) return 10;
    auto second_port=(*second)->start(0,proxy::Inbound::shadowsocks,2); if (!second_port) return 11;
    std::signal(SIGTERM,stop); std::signal(SIGINT,stop); std::signal(SIGUSR1,restart_server); std::cout << *port << " " << *second_port << std::endl;
    while (!stopped && (*server)->healthy() && (*second)->healthy()) {
        (*server)->poll(std::chrono::milliseconds(20)); (*second)->poll(std::chrono::milliseconds(20));
        if (restart) {
            restart=0; (*server)->stop();
            auto again=(*server)->start(*port,proxy::Inbound::shadowsocks,workers);
            if (!again || *again!=*port) return 12;
            std::cout << "restarted" << std::endl;
        }
    }
    (*second)->stop();
    (*server)->stop();
    if ((*server)->prepare_shadowsocks_inbound(std::span{key}.first(size))) return 8;
    return 0;
}
