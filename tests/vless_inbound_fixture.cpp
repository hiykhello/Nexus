#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

import std;
import vless;

int main(int argc, char** argv) {
    if (argc!=4) return 1;
    auto listener=std::atoi(argv[1]);
    auto reject=std::string_view(argv[2])=="reject";
    auto user=vless::parse_user_id("00010203-0405-0607-0809-0a0b0c0d0e0f");
    if (!user) return 2;
    std::array<vless::UserId,1> users{*user};
    auto handshake=vless::ServerHandshake::create(users);
    if (!handshake) return 3;
    auto peer=::accept(listener,nullptr,nullptr);
    if (peer<0) return 4;
    timeval timeout{5,0};
    if (::setsockopt(peer,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))<0) return 5;
    std::vector<std::uint8_t> payload;
    while (handshake->status()==vless::ServerStatus::reading) {
        std::array<std::uint8_t,512> bytes{};
        auto count=::recv(peer,bytes.data(),bytes.size(),0);
        if (count<=0) return 6;
        auto input=std::span(bytes).first(static_cast<std::size_t>(count));
        auto step=handshake->feed(input);
        payload.insert(payload.end(),input.begin()+step.consumed,input.end());
    }
    if (reject) {
        auto result=handshake->status()==vless::ServerStatus::rejected && !handshake->request();
        ::close(peer);
        return result ? 0 : 7;
    }
    auto request=handshake->request();
    auto kind=std::string_view(argv[3]);
    std::vector<std::uint8_t> target;
    auto address_kind=vless::AddressKind::ipv4;
    if (kind=="ipv4") target={203,0,113,5};
    else if (kind=="ipv6") {
        address_kind=vless::AddressKind::ipv6;
        target={0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
    } else if (kind=="domain") {
        address_kind=vless::AddressKind::domain;
        target={'e','x','a','m','p','l','e','.','t','e','s','t'};
    } else return 8;
    if (!request || request->kind!=address_kind || request->port!=443 || request->address!=target) return 8;
    if (std::string_view(argv[2])=="dial-fail") {
        if (handshake->complete_dial(false) || handshake->status()!=vless::ServerStatus::rejected) return 13;
        ::close(peer);
        return 0;
    }
    auto response=handshake->complete_dial(true);
    if (!response || ::send(peer,response->data(),response->size(),MSG_NOSIGNAL)!=2) return 9;
    while (payload.size()<5) {
        std::array<std::uint8_t,512> bytes{};
        auto count=::recv(peer,bytes.data(),bytes.size(),0);
        if (count<=0) return 10;
        payload.insert(payload.end(),bytes.begin(),bytes.begin()+count);
    }
    if (payload!=std::vector<std::uint8_t>{'h','e','l','l','o'}) return 11;
    if (::send(peer,"world",5,MSG_NOSIGNAL)!=5) return 12;
    ::close(peer);
    return 0;
}
