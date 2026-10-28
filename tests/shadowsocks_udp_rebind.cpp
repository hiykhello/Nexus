#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.shadowsocks.udp_packet;
namespace s=nexus::shadowsocks;
struct Socket { int fd; explicit Socket(int family=AF_INET) : fd(::socket(family,SOCK_DGRAM|SOCK_CLOEXEC,0)) {} ~Socket() { if (fd>=0) ::close(fd); } };
int main(int argc,char** argv) {
    if (argc!=3 && argc!=4 && argc!=5) return 1;
    Socket first,second,target;
    sockaddr_in local{}; local.sin_family=AF_INET; local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    for (auto fd : {first.fd,second.fd,target.fd}) {
        auto bind_address=local;
        if (argc==4 && (std::string_view(argv[3])=="reconfigure" || std::string_view(argv[3])=="blocked" ||
                         std::string_view(argv[3])=="unsupported") && fd==target.fd)
            bind_address.sin_addr.s_addr=htonl(INADDR_ANY);
        if (fd<0 || ::bind(fd,reinterpret_cast<sockaddr*>(&bind_address),sizeof(bind_address))) return 2;
    }
    socklen_t len=sizeof(local); if (::getsockname(target.fd,reinterpret_cast<sockaddr*>(&local),&len)) return 3;
    auto port=ntohs(local.sin_port);
    sockaddr_in listener{}; listener.sin_family=AF_INET; listener.sin_addr.s_addr=htonl(INADDR_LOOPBACK); listener.sin_port=htons(std::atoi(argv[1]));
    for (auto fd : {first.fd,second.fd}) if (::connect(fd,reinterpret_cast<sockaddr*>(&listener),sizeof(listener))) return 4;
    std::array<std::uint8_t,32> key{}; std::iota(key.begin(),key.end(),0); auto psk=std::span{key}.first(std::atoi(argv[2]));
    auto wall=[] { return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()); };
    s::UdpPacket packet{{1,2,3,4,5,6,7,8},0,wall(),{}, {1,127,0,0,1,static_cast<std::uint8_t>(port>>8),static_cast<std::uint8_t>(port)}, {1}};
    auto encode=[&] { packet.timestamp=wall(); return *s::encode_udp_packet(psk,s::UdpDirection::client,packet,{}); };
    auto send_wire=[](int fd,std::vector<std::uint8_t> const& wire) { return ::send(fd,wire.data(),wire.size(),0)==static_cast<ssize_t>(wire.size()); };
    auto read_target=[&](std::uint8_t expected,sockaddr_in& relay) {
        pollfd p{target.fd,POLLIN,0}; if (::poll(&p,1,1000)!=1) return false;
        std::array<std::uint8_t,64> buf{}; socklen_t n=sizeof(relay);
        return ::recvfrom(target.fd,buf.data(),buf.size(),0,reinterpret_cast<sockaddr*>(&relay),&n)==1 && buf[0]==expected;
    };
    auto no_data=[](int fd,int ms) { pollfd p{fd,POLLIN,0}; return ::poll(&p,1,ms)==0; };
    auto reply=[&](sockaddr_in const& relay,std::uint8_t payload,int fd) {
        if (::sendto(target.fd,&payload,1,0,reinterpret_cast<sockaddr const*>(&relay),sizeof(relay))!=1) return false;
        pollfd p{fd,POLLIN,0}; if (::poll(&p,1,1000)!=1) return false;
        std::array<std::uint8_t,1024> buffer{}; auto n=::recv(fd,buffer.data(),buffer.size(),0);
        if (n<=0) return false;
        auto decoded=s::decode_udp_packet(psk,s::UdpDirection::server,std::span{buffer}.first(n),wall(),packet.session_id);
        return decoded && decoded->payload==std::vector<std::uint8_t>{payload};
    };
    if (argc==5 && (std::string_view(argv[3])=="multi" || std::string_view(argv[3])=="multi6")) {
        Socket second6(AF_INET6); int second_fd=second.fd;
        if (std::string_view(argv[3])=="multi6") {
            sockaddr_in6 address{}; address.sin6_family=AF_INET6; address.sin6_addr=in6addr_loopback;
            address.sin6_port=htons(static_cast<std::uint16_t>(std::atoi(argv[4])));
            if (second6.fd<0 || ::connect(second6.fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))) return 50;
            second_fd=second6.fd;
        } else {
            listener.sin_port=htons(static_cast<std::uint16_t>(std::atoi(argv[4])));
            if (::connect(second.fd,reinterpret_cast<sockaddr*>(&listener),sizeof(listener))) return 50;
        }
        sockaddr_in relay{}; auto initial=encode();
        if (!send_wire(first.fd,initial) || !read_target(1,relay)) return 51;
        if (!send_wire(second_fd,initial) || !no_data(target.fd,100) || !reply(relay,11,first.fd)) return 52;
        packet.packet_id=1; packet.payload={2};
        if (!send_wire(second_fd,encode()) || !read_target(2,relay) || !reply(relay,12,second_fd)) return 53;
        if (!send_wire(first.fd,initial) || !no_data(target.fd,100) || !reply(relay,13,second_fd)) return 54;
        std::println("SS-2022 UDP multiple listeners share replay and reply routing");
        return 0;
    }
    if (argc==4 && std::string_view(argv[3])=="system-stall") {
        packet.address={3,16,'n','e','x','u','s','-','d','e','l','a','y','.','t','e','s','t',0,80};
        return send_wire(first.fd,encode()) ? 0 : 61;
    }
    if (argc==4 && std::string_view(argv[3])=="system") {
        packet.address={3,9,'l','o','c','a','l','h','o','s','t',static_cast<std::uint8_t>(port>>8),static_cast<std::uint8_t>(port)};
        sockaddr_in relay{};
        if (!send_wire(first.fd,encode()) || !read_target(1,relay) || !reply(relay,12,first.fd)) return 60;
        return 0;
    }
    if (argc==4 && std::string_view(argv[3])=="blocked") {
        packet.session_id[0]=9;
        packet.address[4]=2;
        return send_wire(first.fd,encode()) && no_data(target.fd,250) ? 0 : 62;
    }
    if (argc==4 && std::string_view(argv[3])=="unsupported") {
        sockaddr_in relay{};
        if (!send_wire(first.fd,encode()) || !read_target(1,relay) || !reply(relay,11,first.fd)) return 80;
        packet.packet_id=1; packet.address[4]=2; packet.payload={2};
        if (!send_wire(first.fd,encode()) || !no_data(target.fd,250)) return 81;
        packet.packet_id=2; packet.address[4]=1; packet.payload={3};
        if (!send_wire(first.fd,encode()) || !read_target(3,relay) || !reply(relay,13,first.fd)) return 82;
        return 0;
    }
    if (argc==4 && std::string_view(argv[3])=="expiry") {
        sockaddr_in relay{};
        if (!send_wire(first.fd,encode()) || !read_target(1,relay)) return 40;
        packet.session_id[0]=2; packet.payload={2};
        if (!send_wire(second.fd,encode()) || !no_data(target.fd,150)) return 41;
        std::this_thread::sleep_for(std::chrono::seconds(63));
        if (!send_wire(second.fd,encode()) || !read_target(2,relay) || !reply(relay,12,second.fd)) return 42;
        std::println("SS-2022 UDP automatic session expiry passed");
        return 0;
    }
    if (argc==4 && std::string_view(argv[3])=="reconfigure") {
        sockaddr_in relay{}; auto initial=encode();
        if (!send_wire(first.fd,initial) || !read_target(1,relay)) return 70;
        std::cout << "ready\n" << std::flush;
        unsigned new_port=0; if (!(std::cin>>new_port) || new_port>65535) return 71;
        listener.sin_port=htons(static_cast<std::uint16_t>(new_port));
        if (::connect(first.fd,reinterpret_cast<sockaddr*>(&listener),sizeof(listener))) return 72;
        if (!send_wire(first.fd,initial) || !no_data(target.fd,100)) return 73;
        packet.packet_id=1; packet.address[4]=2; packet.payload={2};
        if (!send_wire(first.fd,encode()) || !no_data(target.fd,150)) return 74;
        packet.packet_id=2; packet.address[4]=1; packet.payload={3};
        if (!send_wire(first.fd,encode()) || !read_target(3,relay) || !reply(relay,13,first.fd)) return 75;
        return 0;
    }
    if (argc==4 && std::string_view(argv[3])=="restart") {
        sockaddr_in relay{}; auto initial=encode();
        if (!send_wire(first.fd,initial) || !read_target(1,relay)) return 30;
        auto numeric=packet.address;
        packet.packet_id=1; packet.address={3,6,'a','.','t','e','s','t',static_cast<std::uint8_t>(port>>8),static_cast<std::uint8_t>(port)};
        auto pending=encode();
        if (!send_wire(first.fd,pending)) return 35;
        packet.address=numeric;
        std::cout << "ready\n" << std::flush;
        unsigned new_port=0; if (!(std::cin>>new_port) || new_port>65535) return 31;
        listener.sin_port=htons(static_cast<std::uint16_t>(new_port));
        if (::connect(first.fd,reinterpret_cast<sockaddr*>(&listener),sizeof(listener))) return 32;
        if (!send_wire(first.fd,initial) || !send_wire(first.fd,pending) || !no_data(target.fd,150)) return 33;
        packet.packet_id=2; packet.payload={2};
        if (!send_wire(first.fd,encode()) || !read_target(2,relay) || !reply(relay,12,first.fd)) return 34;
        std::println("SS-2022 UDP listener replacement retained replay state");
        return 0;
    }
    if (argc==4 && std::string_view(argv[3])=="capacity") {
        sockaddr_in relay1{},relay2{},relay_again{};
        auto first_wire=encode();
        if (!send_wire(first.fd,first_wire) || !read_target(1,relay1)) return 20;
        packet.session_id[0]=2; packet.payload={2};
        if (!send_wire(second.fd,encode()) || !read_target(2,relay2)) return 21;
        if (relay1.sin_port==relay2.sin_port) return 22;
        packet.session_id[0]=3; packet.payload={3};
        if (!send_wire(first.fd,encode()) || !no_data(target.fd,150)) return 23;
        packet.session_id[0]=1; packet.packet_id=1; packet.payload={4};
        if (!send_wire(first.fd,encode()) || !read_target(4,relay_again) || relay_again.sin_port!=relay1.sin_port) return 24;
        if (!reply(relay1,11,first.fd)) return 25;
        packet.session_id[0]=2; packet.packet_id=1; packet.payload={5};
        if (!send_wire(second.fd,encode()) || !read_target(5,relay_again) || relay_again.sin_port!=relay2.sin_port) return 26;
        if (!reply(relay2,12,second.fd)) return 27;
        std::println("SS-2022 UDP listener session capacity passed");
        return 0;
    }
    auto initial=encode(); if (!send_wire(first.fd,initial)) return 5;
    sockaddr_in relay{}; if (!read_target(1,relay)) return 6;
    // Replayed and corrupted packets from a different source cannot redirect replies.
    if (!send_wire(second.fd,initial)) return 7;
    packet.packet_id=1; packet.payload={2}; auto valid=encode(); auto forged=valid; forged.back()^=1;
    if (!send_wire(second.fd,forged)) return 8;
    auto old=packet; old.timestamp=wall()-31;
    auto stale=*s::encode_udp_packet(psk,s::UdpDirection::client,old,{});
    if (!send_wire(second.fd,stale)) return 15;
    if (!no_data(target.fd,100)) return 9;
    if (!reply(relay,11,first.fd) || !no_data(second.fd,100)) return 10;
    // A valid fresh packet from the second address rebinds the existing relay.
    auto original_relay=relay;
    if (!send_wire(second.fd,valid) || !read_target(2,relay) ||
        relay.sin_port!=original_relay.sin_port || relay.sin_addr.s_addr!=original_relay.sin_addr.s_addr) return 11;
    if (!reply(relay,12,second.fd) || !no_data(first.fd,100)) return 12;
    // Old packets from the first source cannot restore the former endpoint.
    if (!send_wire(first.fd,initial) || !no_data(target.fd,100)) return 13;
    if (!reply(relay,13,second.fd) || !no_data(first.fd,100)) return 14;
    std::println("SS-2022 UDP authenticated rebinding and replay passed");
}
