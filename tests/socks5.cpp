import std;
import socks5;

namespace s = socks5;

static auto check(bool condition, char const* message) -> bool {
    if (!condition) std::cerr << message << '\n';
    return condition;
}

static auto greeting_tests() -> bool {
    std::vector<std::uint8_t> greeting{5, 3, 2, 0, 3, 0xaa};
    for (std::size_t n = 0; n < 5; ++n) {
        auto result = s::parse_greeting(std::span(greeting).first(n));
        if (!check(result.status == s::Status::incomplete && result.consumed == 0,
                   "partial greeting consumed data")) return false;
    }
    auto result = s::parse_greeting(greeting);
    if (!check(result.status == s::Status::accepted && result.consumed == 5,
               "greeting or trailing payload incorrect")) return false;
    if (!check(s::parse_greeting(greeting, 2).status == s::Status::accepted,
               "password method not selected")) return false;
    if (!check(s::parse_greeting(greeting, 4).status == s::Status::no_acceptable_method,
               "unoffered method selected")) return false;
    greeting[3] = 1;
    result = s::parse_greeting(greeting);
    if (!check(result.status == s::Status::no_acceptable_method && result.consumed == 5,
               "unsupported method accepted")) return false;
    greeting = {5, 0};
    if (!check(s::parse_greeting(greeting).status == s::Status::no_acceptable_method,
               "empty method list accepted")) return false;
    greeting = {4};
    return check(s::parse_greeting(greeting).status == s::Status::invalid_version,
                 "invalid greeting version accepted");
}

static auto request_frame(std::uint8_t type, std::vector<std::uint8_t> address) -> bool {
    std::vector<std::uint8_t> request{5, 1, 0, type};
    if (type == 3) request.push_back(static_cast<std::uint8_t>(address.size()));
    request.insert(request.end(), address.begin(), address.end());
    request.push_back(0x12);
    request.push_back(0x34);
    auto const frame_size = request.size();
    request.push_back(0xee);
    for (std::size_t n = 0; n < frame_size; ++n) {
        auto result = s::parse_request(std::span(request).first(n));
        if (!check(result.status == s::Status::incomplete && result.consumed == 0,
                   "partial request consumed data")) return false;
    }
    auto result = s::parse_request(request);
    return check(result.status == s::Status::accepted && result.command == 1 && result.consumed == frame_size &&
                 result.address_type == type && result.port == 0x1234 &&
                 result.address_length == address.size() &&
                 std::equal(address.begin(), address.end(), result.address.begin()),
                 "request address, port, or payload boundary incorrect");
}

static auto udp_request_tests() -> bool {
    using enum s::Status;
    for (auto type : {1,3,4}) {
        std::vector<std::uint8_t> wire{5,3,0,static_cast<std::uint8_t>(type)};
        if (type==3) wire.insert(wire.end(),{3,'a','b','c'});
        else wire.insert(wire.end(),type==1 ? 4 : 16,0);
        wire.insert(wire.end(),{0,0});
        if (s::parse_request(wire).status!=unsupported_command) return false;
        for (std::size_t i=0;i<wire.size();++i)
            if (s::parse_request(std::span(wire).first(i),true).status!=incomplete) return false;
        auto request=s::parse_request(wire,true);
        if (request.status!=accepted || request.command!=3 || request.address_type!=type ||
            request.port!=0 || request.consumed!=wire.size()) return false;
    }
    return s::parse_request(std::array<std::uint8_t,4>{5,2,0,1},true).status==unsupported_command;
}

static auto invalid_tests() -> bool {
    using enum s::Status;
    struct Case { std::vector<std::uint8_t> bytes; s::Status expected; };
    std::vector<Case> cases{
        {{4}, invalid_version}, {{5, 1, 1, 1}, invalid_reserved},
        {{5, 2, 0, 1}, unsupported_command}, {{5, 3, 0, 1}, unsupported_command},
        {{5, 1, 0, 5}, unsupported_address}, {{5, 1, 0, 3, 0}, invalid_address},
    };
    for (auto const& item : cases) {
        if (!check(s::parse_request(item.bytes).status == item.expected,
                   "invalid request incorrectly classified")) return false;
    }
    return true;
}

static auto udp_tests() -> bool {
    using enum s::Status;
    for (auto [type,length] : {std::pair{1,4}, std::pair{4,16}, std::pair{3,1}, std::pair{3,255}}) {
        std::vector<std::uint8_t> wire{0,0,0,static_cast<std::uint8_t>(type)};
        if (type==3) wire.push_back(static_cast<std::uint8_t>(length));
        for (int i=0;i<length;++i) wire.push_back(static_cast<std::uint8_t>(i));
        wire.push_back(0x12); wire.push_back(0x34);
        auto header=wire.size();
        for (std::size_t n=0;n<header;++n) {
            auto partial=s::parse_udp_datagram(std::span(wire).first(n));
            if (partial || partial.error()!=incomplete) return false;
        }
        auto empty=s::parse_udp_datagram(wire);
        if (!empty || !empty->data.empty()) return false;
        wire.insert(wire.end(),{0,1,255});
        auto decoded=s::parse_udp_datagram(wire);
        if (!decoded || decoded->address_type!=type || decoded->address_length!=length || decoded->port!=0x1234 ||
            decoded->data.data()!=wire.data()+header || !std::ranges::equal(decoded->data,std::array<std::uint8_t,3>{0,1,255})) return false;
        auto encoded=s::encode_udp_datagram(*decoded);
        if (!encoded || *encoded!=wire) return false;
    }
    for (auto [wire,error] : std::vector<std::pair<std::vector<std::uint8_t>,s::Status>>{
             {{1,0,0,1},invalid_reserved}, {{0,1,0,1},invalid_reserved},
             {{0,0,1,1},unsupported_fragment}, {{0,0,0x80,1},unsupported_fragment},
             {{0,0,0,2},unsupported_address}, {{0,0,0,3,0},invalid_address}}) {
        auto parsed=s::parse_udp_datagram(wire);
        if (parsed || parsed.error()!=error) return false;
    }
    s::UdpDatagram invalid;
    if (s::encode_udp_datagram(invalid).error()!=unsupported_address) return false;
    invalid.address_type=1; invalid.address_length=3;
    if (s::encode_udp_datagram(invalid).error()!=invalid_address) return false;
    invalid.address_type=4; invalid.address_length=15;
    if (s::encode_udp_datagram(invalid).error()!=invalid_address) return false;
    invalid.address_type=3; invalid.address_length=0;
    return s::encode_udp_datagram(invalid).error()==invalid_address;
}

static auto udp_association_tests() -> bool {
    using enum s::Status;
    s::UdpPeer tcp{1,{127,0,0,1},4444}, hint{1,{},0};
    auto association=s::UdpAssociation::create(tcp,hint);
    if (!association || association->client_peer()) return false;
    s::UdpPeer first{1,{127,0,0,1},5000}, second{1,{127,0,0,1},5001}, stranger{1,{127,0,0,2},5000};
    std::vector<std::uint8_t> valid{0,0,0,1,1,2,3,4,0,53,'x'}, fragment=valid;
    fragment[2]=1;
    if (association->admit(first,fragment).error()!=unsupported_fragment ||
        association->admit(stranger,valid).error()!=unauthorized_source || association->client_peer()) return false;
    // Malformed traffic did not claim the unknown port.
    auto admitted=association->admit(second,valid);
    if (!admitted || admitted->port!=53 || !std::ranges::equal(admitted->data,std::array<std::uint8_t,1>{'x'}) ||
        association->admit(first,valid).error()!=unauthorized_source || association->client_peer()!=second) return false;
    auto moved=std::move(*association);
    if (association->client_peer() || association->admit(second,valid).error()!=association_closed ||
        moved.client_peer()!=second || !moved.admit(second,valid)) return false;
    moved.close();
    if (moved.client_peer() || moved.admit(second,valid).error()!=association_closed) return false;
    hint=tcp; hint.port=5000;
    auto fixed=s::UdpAssociation::create(tcp,hint);
    if (!fixed || fixed->client_peer() || fixed->admit(second,valid).error()!=unauthorized_source ||
        !fixed->admit(first,valid) || fixed->client_peer()!=first) return false;
    hint.address[3]=2;
    if (s::UdpAssociation::create(tcp,hint).error()!=unauthorized_source) return false;
    hint={4,{},0};
    if (!s::UdpAssociation::create(tcp,hint)) return false;
    first.address[4]=1;
    if (fixed->admit(first,valid).error()!=unauthorized_source) return false;
    s::UdpPeer tcp6{4,{0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},443};
    auto ipv6=s::UdpAssociation::create(tcp6,{1,{},0});
    tcp6.port=6000;
    if (!ipv6 || !ipv6->admit(tcp6,valid)) return false;
    tcp6.address[15]=2;
    return ipv6->admit(tcp6,valid).error()==unauthorized_source;
}

static auto udp_target_tests() -> bool {
    using enum s::Status;
    auto association=s::UdpAssociation::create({1,{127,0,0,1},1},{1,{},0});
    if (!association) return false;
    s::UdpPeer target{1,{192,0,2,1},53}, other=target; other.port=54;
    auto first=association->begin_send(target);
    if (!first || association->accepts_reply(target) || association->begin_send(target).error()!=send_in_progress ||
        association->accepts_reply(other) || !association->finish_send(*first,false) || association->accepts_reply(target) ||
        association->finish_send(*first,true).error()!=stale_send) return false;
    auto success=association->begin_send(target);
    if (!success || !association->finish_send(*success,true) || !association->accepts_reply(target)) return false;
    auto again=association->begin_send(target);
    if (!again || !association->accepts_reply(target) || !association->finish_send(*again,false) ||
        !association->accepts_reply(target)) return false;
    auto pending=association->begin_send(other);
    if (!pending || association->accepts_reply(other)) return false;
    for (std::uint16_t port=100;port<162;++port) {
        auto item=target; item.port=port;
        auto token=association->begin_send(item);
        if (!token || !association->finish_send(*token,true)) return false;
    }
    auto overflow=target; overflow.port=200;
    auto replacement=association->begin_send(overflow);
    if (!replacement || !association->accepts_reply(target) || association->accepts_reply(overflow) ||
        association->begin_send(overflow).error()!=send_in_progress || association->begin_send(target).error()!=send_in_progress ||
        !association->finish_send(*replacement,false) || !association->accepts_reply(target) || association->accepts_reply(overflow)) return false;
    auto retry=association->begin_send(overflow);
    if (!retry || !association->finish_send(*retry,true) || association->accepts_reply(target) ||
        !association->accepts_reply(overflow)) return false;
    auto refreshed=target; refreshed.port=100;
    auto next_oldest=target; next_oldest.port=101;
    auto refresh=association->begin_send(refreshed);
    auto another=target; another.port=201;
    if (!refresh || !association->finish_send(*refresh,true)) return false;
    auto second_replacement=association->begin_send(another);
    if (!second_replacement || !association->finish_send(*second_replacement,true) ||
        !association->accepts_reply(refreshed) || association->accepts_reply(next_oldest) ||
        !association->accepts_reply(another) || !association->finish_send(*pending,false)) return false;
    auto full=s::UdpAssociation::create({1,{127,0,0,1},1},{1,{},0});
    if (!full) return false;
    for (std::uint16_t port=100;port<164;++port) {
        auto item=target; item.port=port;
        if (!full->begin_send(item)) return false;
    }
    if (full->begin_send(overflow).error()!=target_capacity) return false;
    auto separate=s::UdpAssociation::create({1,{127,0,0,1},1},{1,{},0});
    if (!separate) return false;
    auto one=separate->begin_send(target), two=separate->begin_send(other);
    if (!one || !two || !separate->finish_send(*one,false) || !separate->finish_send(*two,true) ||
        separate->accepts_reply(target) || !separate->accepts_reply(other)) return false;
    auto in_flight=association->begin_send(overflow);
    if (!in_flight) return false;
    association->close();
    return !association->accepts_reply(target) && association->finish_send(*in_flight,true).error()==association_closed &&
        association->begin_send(target).error()==association_closed;
}

int main() {
    std::vector<std::uint8_t> ipv6(16);
    for (std::size_t n = 0; n < ipv6.size(); ++n) ipv6[n] = static_cast<std::uint8_t>(n);
    std::vector<std::uint8_t> longest_domain(255, 'x');
    if (!greeting_tests() || !request_frame(1, {127, 0, 0, 1}) ||
        !request_frame(4, ipv6) || !request_frame(3, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}) ||
        !request_frame(3, longest_domain) || !invalid_tests() || !udp_request_tests() || !udp_tests() ||
        !udp_association_tests() || !udp_target_tests()) return 1;
    std::cout << "SOCKS5 greeting, CONNECT and UDP datagram codecs passed\n";
}
