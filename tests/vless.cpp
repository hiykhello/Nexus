import std;
import vless;
namespace v=vless;
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
    v::TcpRequest vision_request{*user,v::AddressKind::domain,443,Bytes{'e','x','a','m','p','l','e','.','c','o','m'}};
    auto vision=v::encode_vision_tcp_request(vision_request);
    Bytes addon{18,0x0a,16,'x','t','l','s','-','r','p','r','x','-','v','i','s','i','o','n'};
    auto expected_vision=expected;
    expected_vision.erase(expected_vision.begin()+17);
    expected_vision.insert(expected_vision.begin()+17,addon.begin(),addon.end());
    if (!vision || *vision!=expected_vision) return 29;
    for (std::size_t i=0;i<vision->size();++i)
        if (v::parse_vision_tcp_request(std::span(*vision).first(i)).status!=v::HeaderStatus::incomplete) return 30;
    vision->push_back(42);
    auto parsed_vision=v::parse_vision_tcp_request(*vision);
    if (parsed_vision.status!=v::HeaderStatus::accepted || parsed_vision.consumed!=expected_vision.size() ||
        !parsed_vision.request || parsed_vision.request->address!=vision_request.address ||
        v::parse_tcp_request(*vision).status!=v::HeaderStatus::unsupported) return 31;
    auto with_unknown=expected_vision;
    with_unknown.insert(with_unknown.begin()+36,{0x12,0x02,0x11,0x22,0x18,0x01,0x25,1,2,3,4}); with_unknown[17]+=11;
    if (v::parse_vision_tcp_request(with_unknown).status!=v::HeaderStatus::accepted) return 32;
    auto malformed_vision=expected_vision; malformed_vision[19]=0x7f;
    if (v::parse_vision_tcp_request(malformed_vision).status!=v::HeaderStatus::malformed) return 33;
    malformed_vision=expected_vision; malformed_vision[18]=0;
    if (v::parse_vision_tcp_request(malformed_vision).status!=v::HeaderStatus::malformed) return 34;
    malformed_vision=expected_vision; malformed_vision[20]='z';
    if (v::parse_vision_tcp_request(malformed_vision).status!=v::HeaderStatus::unsupported) return 35;
    auto legacy_server=v::ServerHandshake::create(users);
    if (!legacy_server || legacy_server->feed(expected_vision).status!=v::ServerStatus::rejected) return 36;
    v::TcpRequest max_vision{*user,v::AddressKind::domain,443,Bytes(255,'a')};
    auto max_header=v::encode_vision_tcp_request(max_vision);
    if (!max_header || max_header->size()!=296 || v::parse_vision_tcp_request(*max_header).consumed!=296) return 37;
    auto duplicate=expected_vision;
    duplicate.insert(duplicate.begin()+36,{0x0a,0x01,'x'}); duplicate[17]+=3;
    if (v::parse_vision_tcp_request(duplicate).status!=v::HeaderStatus::unsupported) return 38;
    auto overflow=expected_vision;
    overflow.insert(overflow.begin()+36,{0x18,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x02}); overflow[17]+=11;
    if (v::parse_vision_tcp_request(overflow).status!=v::HeaderStatus::malformed) return 39;
    auto group=expected_vision; group.insert(group.begin()+36,0x1b); ++group[17];
    if (v::parse_vision_tcp_request(group).status!=v::HeaderStatus::unsupported) return 40;
    if (v::ServerHandshake::create_vision({}) || v::ServerHandshake::create_vision(std::array<v::UserId,2>{*user,*user})) return 41;
    auto full_addon=*max_header;
    full_addon.insert(full_addon.begin()+36,{0x12,0xea,0x01});
    full_addon.insert(full_addon.begin()+39,234,0x42); full_addon[17]=255;
    if (full_addon.size()!=533 || v::parse_vision_tcp_request(full_addon).consumed!=533) return 42;
    auto with_tail=full_addon; with_tail.insert(with_tail.end(),{'d','a','t','a'});
    for (std::size_t split=0;split<=full_addon.size();++split) {
        auto handshake=v::ServerHandshake::create_vision(users);
        if (!handshake || handshake->request() || handshake->complete_dial(true)) return 43;
        auto first=handshake->feed(std::span(full_addon).first(split));
        auto second=handshake->feed(std::span(with_tail).subspan(split));
        if (first.consumed!=split || second.consumed!=full_addon.size()-split || second.status!=v::ServerStatus::dialing ||
            !handshake->request() || handshake->request()->user!=*user || handshake->request()->address!=max_vision.address) return 44;
        auto response=handshake->complete_dial(true);
        if (!response || *response!=v::encode_response() || handshake->status()!=v::ServerStatus::established || handshake->feed(Bytes{1}).consumed) return 45;
    }
    auto denied_vision=expected_vision; denied_vision[1]^=0x80;
    auto rejected=v::ServerHandshake::create_vision(users);
    if (!rejected || rejected->feed(denied_vision).status!=v::ServerStatus::rejected || rejected->request() || rejected->complete_dial(true)) return 46;
    auto plain_vision=v::ServerHandshake::create_vision(users);
    if (!plain_vision || plain_vision->feed(expected).status!=v::ServerStatus::rejected) return 47;
    auto failed_vision=v::ServerHandshake::create_vision(users);
    if (!failed_vision || failed_vision->feed(expected_vision).status!=v::ServerStatus::dialing || failed_vision->complete_dial(false) ||
        failed_vision->status()!=v::ServerStatus::rejected || failed_vision->request()) return 48;
    std::cout << "VLESS version 0 TCP header boundaries and rejection passed\n";
}
