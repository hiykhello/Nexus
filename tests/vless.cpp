import std;
import nexus.vless;
namespace v=nexus::vless;
using Bytes=std::vector<std::uint8_t>;
int main() {
    auto user=v::parse_user_id("00010203-0405-0607-0809-0A0B0C0D0E0f");
    if (!user) return 14;
    for (std::uint8_t i=0;i<16;++i) if ((*user)[i]!=i) return 15;
    for (auto text : {"00010203-0405-0607-0809-0a0b0c0d0e0", "00010203-0405-0607-0809-0a0b0c0d0e0f\n",
                      "00010203_0405-0607-0809-0a0b0c0d0e0f", "00010203-0405-0607-0809-0a0b0c0d0e0g"})
        if (v::parse_user_id(text)) return 16;
    v::TcpRequest request; for (std::uint8_t i=0;i<16;++i) request.user[i]=i;
    request.port=443; request.kind=v::AddressKind::domain;
    request.address=Bytes{'e','x','a','m','p','l','e','.','c','o','m'};
    Bytes expected{0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0,1,1,187,2,11,'e','x','a','m','p','l','e','.','c','o','m'};
    auto encoded=v::encode_tcp_request(request);
    if (!encoded || *encoded!=expected) return 1;
    for (std::size_t i=0;i<encoded->size();++i) if (v::parse_tcp_request(std::span{*encoded}.first(i)).status!=v::HeaderStatus::incomplete) return 2;
    encoded->insert(encoded->end(),{'d','a','t','a'});
    auto decoded=v::parse_tcp_request(*encoded);
    if (decoded.status!=v::HeaderStatus::accepted || decoded.consumed!=expected.size() || !decoded.request || decoded.request->user!=request.user || decoded.request->port!=request.port || decoded.request->address!=request.address || decoded.request->kind!=request.kind) return 3;
    for (auto kind:{v::AddressKind::ipv4,v::AddressKind::ipv6}) {
        request.kind=kind; request.address=Bytes(kind==v::AddressKind::ipv4 ? 4 : 16,42);
        auto bytes=v::encode_tcp_request(request); if (!bytes || bytes->at(21)!=static_cast<std::uint8_t>(kind)) return 4;
        for (std::size_t i=0;i<bytes->size();++i) if (v::parse_tcp_request(std::span{*bytes}.first(i)).status!=v::HeaderStatus::incomplete) return 5;
        auto parsed=v::parse_tcp_request(*bytes); if (parsed.status!=v::HeaderStatus::accepted || parsed.consumed!=bytes->size() || parsed.request->address!=request.address) return 6;
    }
    request.kind=v::AddressKind::domain; request.address=Bytes(255,'a');
    if (!v::encode_tcp_request(request)) return 7;
    request.address.push_back('a'); if (v::encode_tcp_request(request)) return 8;
    request.address={'a',0,'b'}; if (v::encode_tcp_request(request)) return 9;
    request.address={'a'}; request.port=0; if (v::encode_tcp_request(request)) return 10;
    for (auto [index,value,status]:{std::tuple{0u,1u,v::HeaderStatus::unsupported},std::tuple{17u,1u,v::HeaderStatus::unsupported},std::tuple{18u,2u,v::HeaderStatus::unsupported},std::tuple{21u,4u,v::HeaderStatus::unsupported},std::tuple{22u,0u,v::HeaderStatus::malformed},std::tuple{23u,0u,v::HeaderStatus::malformed}}) {
        auto invalid=expected; invalid[index]=static_cast<std::uint8_t>(value);
        if (v::parse_tcp_request(invalid).status!=status) return 11;
    }
    auto invalid=expected; invalid[19]=invalid[20]=0;
    if (v::parse_tcp_request(invalid).status!=v::HeaderStatus::malformed) return 12;
    if (v::parse_response(Bytes{}).status!=v::HeaderStatus::incomplete || v::parse_response(Bytes{0}).status!=v::HeaderStatus::incomplete ||
        v::parse_response(Bytes{1,0}).status!=v::HeaderStatus::unsupported || v::parse_response(Bytes{0,1}).status!=v::HeaderStatus::unsupported ||
        v::parse_response(Bytes{0,0,'x'}).consumed!=2 || v::encode_response()!=std::array<std::uint8_t,2>{0,0}) return 13;
    std::array<v::UserId,2> users{*user,v::UserId{}};
    users[1].fill(0xa5);
    if (v::ServerHandshake::create({}) || v::ServerHandshake::create(std::array<v::UserId,2>{*user,*user}) ||
        v::ServerHandshake::create(std::vector<v::UserId>(65))) return 17;
    for (std::size_t split=0;split<=expected.size();++split) {
        auto server=v::ServerHandshake::create(users);
        if (!server || server->request() || server->complete_dial(true)) return 18;
        auto first=server->feed(std::span(expected).first(split));
        if (first.consumed!=split || first.status!=(split==expected.size() ? v::ServerStatus::dialing : v::ServerStatus::reading)) return 19;
        auto rest=server->feed(std::span(*encoded).subspan(split));
        if (rest.status!=v::ServerStatus::dialing || rest.consumed!=expected.size()-split ||
            !server->request() || server->request()->user!=*user || server->request()->port!=443) return 20;
        auto reply=server->complete_dial(true);
        if (!reply || *reply!=v::encode_response() || server->status()!=v::ServerStatus::established ||
            server->feed(Bytes{'x'}).consumed!=0 || server->complete_dial(true)) return 21;
    }
    auto other=expected; std::ranges::fill(std::span(other).subspan(1,16),0xa5);
    auto allowed=v::ServerHandshake::create(users);
    if (!allowed || allowed->feed(other).status!=v::ServerStatus::dialing || allowed->complete_dial(false) ||
        allowed->status()!=v::ServerStatus::rejected || allowed->request() || allowed->complete_dial(true)) return 22;
    other[1]^=1;
    auto denied=v::ServerHandshake::create(users);
    if (!denied || denied->feed(other).status!=v::ServerStatus::rejected || denied->request() || denied->complete_dial(true)) return 23;
    auto bad=expected; bad[18]=2;
    auto malformed=v::ServerHandshake::create(users);
    if (!malformed || malformed->feed(bad).status!=v::ServerStatus::rejected || malformed->request() ||
        malformed->feed(expected).consumed!=0) return 24;
    v::TcpRequest largest{*user,v::AddressKind::domain,443,Bytes(255,'a')};
    auto maximum=v::encode_tcp_request(largest);
    auto server=v::ServerHandshake::create(users);
    if (!maximum || maximum->size()!=278 || !server || server->feed(*maximum).status!=v::ServerStatus::dialing) return 25;
    auto fragmented=v::ServerHandshake::create(users);
    if (!fragmented || fragmented->feed({}).status!=v::ServerStatus::reading) return 26;
    for (std::size_t i=0;i<expected.size();++i) {
        auto step=fragmented->feed(std::span(expected).subspan(i,1));
        if (step.consumed!=1 || step.status!=(i+1==expected.size() ? v::ServerStatus::dialing : v::ServerStatus::reading)) return 27;
    }
    std::vector<v::UserId> limit(64);
    for (std::size_t i=0;i<limit.size();++i) limit[i][0]=static_cast<std::uint8_t>(i);
    auto full=v::ServerHandshake::create(limit);
    auto last=expected; std::ranges::fill(std::span(last).subspan(1,16),0); last[1]=63;
    if (!full || full->feed(last).status!=v::ServerStatus::dialing) return 28;
    std::cout << "VLESS version 0 TCP header boundaries and rejection passed\n";
}
