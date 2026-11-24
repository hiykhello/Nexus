#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import relay;

using namespace std::chrono_literals;
namespace p = relay;

// Exercise the production reader owned by a Server bound to a caller-owned
// DNS generation. The second server stays alive across the first's restarts.
auto handshake(p::Server& server,std::uint16_t port,std::string_view name={},std::uint16_t target=0) -> bool {
    std::atomic<bool> done=false,passed=false;
    std::thread client([&] {
        int fd=::socket(AF_INET,SOCK_STREAM,0);
        if(fd<0){done=true;return;}
        timeval limit{3,0};(void)::setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&limit,sizeof(limit));
        sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons(port);
        std::array<unsigned char,3> input{5,1,0};std::array<unsigned char,2> output{};
        if(::connect(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0 &&
           ::send(fd,input.data(),input.size(),MSG_NOSIGNAL)==static_cast<ssize_t>(input.size()) &&
           ::recv(fd,output.data(),output.size(),MSG_WAITALL)==static_cast<ssize_t>(output.size()) &&
           output==std::array<unsigned char,2>{5,0}) {
            if(name.empty())passed=true;
            else {
                std::vector<unsigned char> request{5,1,0,3,static_cast<unsigned char>(name.size())};
                request.insert(request.end(),name.begin(),name.end());request.push_back(target>>8);request.push_back(target&255);
                std::array<unsigned char,10> reply{};std::array<unsigned char,4> answer{};
                if(::send(fd,request.data(),request.size(),MSG_NOSIGNAL)==static_cast<ssize_t>(request.size()) &&
                   ::recv(fd,reply.data(),reply.size(),MSG_WAITALL)==static_cast<ssize_t>(reply.size()) && reply[1]==0 &&
                   ::send(fd,"ping",4,MSG_NOSIGNAL)==4 && ::recv(fd,answer.data(),answer.size(),MSG_WAITALL)==4 &&
                   answer==std::array<unsigned char,4>{'p','i','n','g'})passed=true;
            }
        }
        ::close(fd);done=true;
    });
    auto deadline=std::chrono::steady_clock::now()+5s;
    while(!done && std::chrono::steady_clock::now()<deadline)server.poll(20ms);
    client.join();server.poll(20ms);return passed;
}

auto main(int argc,char** argv) -> int {
    if(argc!=1 && argc!=3)return 10;
    auto dns_port=argc==3 ? static_cast<std::uint16_t>(std::stoul(argv[1])) : 0;
    auto target=argc==3 ? static_cast<std::uint16_t>(std::stoul(argv[2])) : 0;
    try {
        p::SharedDnsGeneration generation(2,4);p::Server first,second;
        if(dns_port) {
            p::DnsRouting routing; p::DnsServer upstream;upstream.address[0]=127;upstream.address[3]=1;upstream.port=dns_port;
            routing.servers.push_back(upstream);routing.strategy=p::DnsStrategy::ipv4_only;
            if(!first.set_dns_routing(routing) || !second.set_dns_routing(routing))return 11;
        }
        if(!first.bind_shared_dns(generation,0,0) || !second.bind_shared_dns(generation,1,2))return 1;
        generation.seal();
        auto a=first.start(0,p::Inbound::socks5,1);auto b=second.start(0,p::Inbound::socks5,1);
        if(!a || !b || !handshake(first,*a) || !handshake(second,*b))return 2;
        if(dns_port && (!handshake(first,*a,"first.test",target) || !handshake(second,*b,"second.test",target)))return 12;
        first.stop();
        if(dns_port) {
            std::cout << "DNS initial stage complete" << std::endl;
            char proceed=0;if(!std::cin.get(proceed) || proceed!='G')return 16;
        }
        if(!second.healthy() || !handshake(second,*b))return 3;
        if(dns_port && !handshake(second,*b,"first.test",target))return 13;
        for(unsigned workers:{1u,2u,1u}) {
            a=first.start(0,p::Inbound::socks5,workers);
            if(!a || !first.healthy() || !handshake(first,*a) || !handshake(second,*b))return 4;
            if(dns_port && !handshake(first,*a,"first.test",target))return 14;
            first.stop();
        }
        int fd=::socket(AF_INET,SOCK_STREAM,0);if(fd<0)return 5;
        sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        socklen_t size=sizeof(address);
        if(::bind(fd,reinterpret_cast<sockaddr*>(&address),size) || ::listen(fd,1) ||
           ::getsockname(fd,reinterpret_cast<sockaddr*>(&address),&size)){::close(fd);return 6;}
        auto blocked=first.start(ntohs(address.sin_port),p::Inbound::socks5,1);::close(fd);
        if(blocked || first.healthy() || !handshake(second,*b))return 7;
        a=first.start(0,p::Inbound::socks5,1);
        if(!a || !handshake(first,*a) || !handshake(second,*b))return 8;
        if(dns_port && !handshake(first,*a,"first.test",target))return 15;
        first.stop();second.stop();
        if(dns_port)std::println("DNS restart stage complete");
        std::println("shared DNS readers: single/multi-worker restart, bind failure retry, and independent server passed");
    } catch(std::exception const& error) {std::cerr << "shared DNS restart: " << error.what() << '\n';return 9;}
}
