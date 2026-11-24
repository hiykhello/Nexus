#include <cstdio>
import std;
import relay;
int main(int argc,char** argv) {
    if (argc!=2) return 1;
    auto port=std::strtoul(argv[1],nullptr,10); if (!port || port>65535) return 2;
    auto server=relay::Server::create(); if (!server) return 3;
    std::array<std::uint8_t,16> key{}; for (std::uint8_t i=0;i<key.size();++i) key[i]=i;
    if (!(*server)->add_shadowsocks("127.0.0.1",static_cast<std::uint16_t>(port),key,{},true) ||
        !(*server)->set_indexed_routes({},2)) return 4;
    auto listening=(*server)->start(0); if (!listening) return 5;
    std::println("{}",*listening); std::fflush(stdout);
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(20);
    while (std::chrono::steady_clock::now()<deadline && (*server)->healthy()) (*server)->poll(std::chrono::milliseconds(5));
    (*server)->stop();
}
