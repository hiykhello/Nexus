#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import crypto;
import hysteria2.credential;
import proxy;
import proxy.hysteria2_host;
import tls.server_credential;

namespace p=proxy;namespace h=hysteria2;
auto read(std::string_view name) -> std::vector<std::uint8_t> {
    std::ifstream file(std::string(name),std::ios::binary);
    if(!file)throw std::runtime_error("cannot open credential");
    return {std::istreambuf_iterator<char>(file),std::istreambuf_iterator<char>()};
}
auto main(int argc,char** argv) -> int {
    if(argc!=3 && !(argc==4 && std::string_view(argv[3])=="active"))return 1;
    try {
        auto cert=read(argv[1]),key=read(argv[2]);
        auto credential=tls::ServerCredential::create_file_contents(cert,key);::crypto::cleanse(key);
        std::string password_text="test-password";
        auto password=h::Password::create(std::span(reinterpret_cast<std::uint8_t const*>(password_text.data()),password_text.size()));
        if(!credential || !password)return 2;
        std::array<h::Password,1> passwords{std::move(*password)};std::array<std::string,1> names{"user"};
        p::SharedDnsGeneration generation(1,2);p::Server parent;
        if(!parent.bind_shared_dns(generation,0,0))return 3;generation.seal();
        p::Hysteria2Host host(parent,*credential,passwords,names);
        if(argc==4) {
            std::uint16_t port=0;
            unsigned round=0;
            for(unsigned workers:{1u,2u,1u}) {
                auto started=host.start(port,false,workers);
                if(!started || !host.healthy() || (port && *started!=port))return 13;
                port=*started;std::cout << "READY " << port << " " << workers << std::endl;
                char command=0;if(!std::cin.get(command) || command!='S')return 14;
                host.stop();
                if(!host.healthy() || host.failure())return 15;
                std::cout << "STOPPED" << std::endl;
                if(++round<3) {
                    char resume=0;if(!std::cin.get(resume) || resume!='R')return 16;
                }
            }
            return 0;
        }
        auto port=host.start(0,false,1);if(!port || !host.healthy())return 4;
        host.stop();
        for(unsigned workers:{1u,2u,1u}) {
            auto restarted=host.start(*port,false,workers);if(!restarted || *restarted!=*port || !host.healthy())return 5;
            host.stop();
        }
        int fd=::socket(AF_INET,SOCK_DGRAM,0);if(fd<0)return 6;
        sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons(*port);
        if(::bind(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))){::close(fd);return 7;}
        auto blocked=host.start(*port,false,1);::close(fd);
        if(blocked || !std::holds_alternative<std::error_code>(blocked.error()) ||
           std::get<std::error_code>(blocked.error())!=std::errc::address_in_use)return 8;
        auto retry=host.start(*port,false,1);if(!retry || *retry!=*port || !host.healthy())return 9;
        host.stop();
        fd=::socket(AF_INET,SOCK_DGRAM,0);if(fd<0)return 10;
        auto bound=::bind(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address));::close(fd);if(bound)return 11;
        std::println("Hy2 shared DNS: single/multi-worker restart, bind failure retry and port release passed");
    } catch(std::exception const& error) {std::cerr << "Hy2 host restart: " << error.what() << '\n';return 12;}
}
