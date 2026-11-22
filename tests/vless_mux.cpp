import std;
import vless;
namespace v=vless;
int main(int argc,char** argv) {
    v::UserId user{}; std::iota(user.begin(),user.end(),std::uint8_t{0});
    for (bool vision : {false,true}) {
        auto wire=v::encode_mux_request(user,vision);
        if (argc==2 && std::string_view(argv[1])=="--vectors") { constexpr char digits[]="0123456789abcdef"; for (auto b:wire) std::cout << digits[b>>4] << digits[b&15]; std::cout << '\n'; continue; }
        for (std::size_t n=0;n<wire.size();++n) if (v::parse_mux_request(std::span(wire).first(n),vision).status!=v::HeaderStatus::incomplete) return 1;
        auto parsed=v::parse_mux_request(wire,vision); if (parsed.status!=v::HeaderStatus::accepted || parsed.consumed!=wire.size() || parsed.user!=user) return 2;
        wire.push_back(99); if (v::parse_mux_request(wire,vision).consumed!=wire.size()-1) return 3;
        if (v::parse_mux_request(wire,!vision).status!=v::HeaderStatus::unsupported) return 4;
        auto handshake=vision ? v::ServerHandshake::create_vision(std::span{&user,1}) : v::ServerHandshake::create(std::span{&user,1});
        if (!handshake || handshake->feed(wire).status!=v::ServerStatus::rejected) return 5;
        auto enabled=vision ? v::ServerHandshake::create_vision(std::span{&user,1}) : v::ServerHandshake::create(std::span{&user,1});
        if (!enabled || !enabled->allow_mux()) return 9;
        for (std::size_t i=0;i+2<wire.size();++i) {
            auto part=enabled->feed(std::span(wire).subspan(i,1));
            if (part.status!=v::ServerStatus::reading || part.consumed!=1) return 10;
        }
        auto tail=enabled->feed(std::span(wire).last(2));
        if (tail.status!=v::ServerStatus::dialing || tail.consumed!=1 || enabled->request() || !enabled->mux_user() || *enabled->mux_user()!=user) return 11;
        if (!enabled->complete_dial(true) || enabled->status()!=v::ServerStatus::established || enabled->allow_mux()) return 12;
        auto other=user; other[0]^=1;
        auto denied=vision ? v::ServerHandshake::create_vision(std::span{&other,1}) : v::ServerHandshake::create(std::span{&other,1});
        if (!denied || !denied->allow_mux() || denied->feed(wire).status!=v::ServerStatus::rejected || denied->mux_user()) return 13;
        auto partial=vision ? v::ServerHandshake::create_vision(std::span{&user,1}) : v::ServerHandshake::create(std::span{&user,1});
        if (!partial || partial->feed(std::span(wire).first(1)).status!=v::ServerStatus::reading || partial->allow_mux()) return 14;
        v::TcpRequest tcp; tcp.user=user; tcp.kind=v::AddressKind::ipv4; tcp.port=443; tcp.address={127,0,0,1};
        auto tcp_wire=vision ? v::encode_vision_tcp_request(tcp) : v::encode_tcp_request(tcp);
        auto tcp_handshake=vision ? v::ServerHandshake::create_vision(std::span{&user,1}) : v::ServerHandshake::create(std::span{&user,1});
        if (!tcp_wire || !tcp_handshake || !tcp_handshake->allow_mux()) return 15;
        auto tcp_result=tcp_handshake->feed(*tcp_wire);
        if (tcp_result.status!=v::ServerStatus::dialing || !tcp_handshake->request() || tcp_handshake->mux_user()) return 16;
        auto refused=vision ? v::ServerHandshake::create_vision(std::span{&user,1}) : v::ServerHandshake::create(std::span{&user,1});
        if (!refused || !refused->allow_mux() || refused->feed(wire).status!=v::ServerStatus::dialing || refused->complete_dial(false) || refused->mux_user()) return 17;
        wire[wire.size()-2]=1; if (v::parse_mux_request(wire,vision).status!=v::HeaderStatus::unsupported) return 6;
    }
    if (argc==2) return 0;
    auto bad=v::encode_mux_request(user,true); bad[18]=0; if (v::parse_mux_request(bad,true).status!=v::HeaderStatus::malformed) return 7;
    auto max=v::encode_mux_request(user,true); max[17]=255; max.insert(max.begin()+20,237,0); max.back()=3;
    if (v::parse_mux_request(max,true).status!=v::HeaderStatus::malformed) return 8;
    std::cout << "VLESS Mux header boundaries, flow and rejection passed\n";
}
