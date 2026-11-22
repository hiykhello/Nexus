import std;
import wireguard;

auto main() -> int {
    using namespace wireguard;
    Initiation initiation; initiation.sender=0x12345678;
    std::iota(initiation.ephemeral.begin(),initiation.ephemeral.end(),0);
    std::iota(initiation.encrypted_static.begin(),initiation.encrypted_static.end(),32);
    std::iota(initiation.encrypted_timestamp.begin(),initiation.encrypted_timestamp.end(),80);
    std::iota(initiation.mac1.begin(),initiation.mac1.end(),108); std::iota(initiation.mac2.begin(),initiation.mac2.end(),124);
    auto wire=encode(initiation);
    if (wire[0]!=1 || wire[1] || wire[2] || wire[3] || wire[4]!=0x78 || wire[7]!=0x12 || wire[147]!=139) return 1;
    auto decoded=parse_initiation(wire);
    if (!decoded || encode(*decoded)!=wire) return 2;
    for (std::size_t size=0;size<wire.size();++size) if (parse_initiation(std::span(wire).first(size))) return 3;
    std::vector<std::uint8_t> extra(wire.begin(),wire.end()); extra.push_back(0);
    if (parse_initiation(extra)) return 4;
    for (std::size_t index=0;index<4;++index) {
        auto bad=wire; bad[index]=255;
        if (parse_initiation(bad)) return 5;
    }
    Response response{0xfedcba98,initiation.sender,initiation.ephemeral,initiation.mac1,initiation.mac2,initiation.mac1};
    auto response_wire=encode(response); auto response_view=parse_response(response_wire);
    if (!response_view || encode(*response_view)!=response_wire || response_wire[4]!=0x98 || response_wire[11]!=0x12 || parse_initiation(response_wire)) return 6;
    CookieReply cookie; cookie.receiver=response.sender; std::iota(cookie.nonce.begin(),cookie.nonce.end(),0);
    std::iota(cookie.encrypted_cookie.begin(),cookie.encrypted_cookie.end(),24);
    auto cookie_wire=encode(cookie); auto cookie_view=parse_cookie(cookie_wire);
    if (!cookie_view || encode(*cookie_view)!=cookie_wire || parse_response(cookie_wire)) return 7;
    auto header=transport_header(0x12345678,0x0102030405060708);
    std::array<std::uint8_t,16> expected{4,0,0,0,0x78,0x56,0x34,0x12,8,7,6,5,4,3,2,1};
    if (header!=expected || parse_transport(header)) return 8;
    std::vector<std::uint8_t> packet(header.begin(),header.end()); packet.resize(32,173);
    auto transport=parse_transport(packet);
    if (!transport || transport->receiver!=0x12345678 || transport->counter!=0x0102030405060708 || transport->ciphertext.data()!=packet.data()+16) return 9;
    auto nonce=transport_nonce(transport->counter);
    if (nonce!=std::array<std::uint8_t,12>{0,0,0,0,8,7,6,5,4,3,2,1}) return 10;
    auto stamp=make_timestamp(0,0);
    if (!stamp || *stamp!=Timestamp{0x40,0,0,0,0,0,0,0x0a,0,0,0,0} || make_timestamp(0,1000000000) || make_timestamp(std::numeric_limits<std::uint64_t>::max(),0)) return 11;
    auto whitened=make_timestamp(1,0x12345678),precise=make_timestamp(1,0x12345678,false);
    if (!whitened || !precise || (*whitened)[8]!=0x12 || (*whitened)[9] || (*precise)[9]!=0x34 || !(*whitened>*stamp)) return 12;
    ReplayWindow replay;
    if (!replay.check(9000) || replay.last() || !replay.commit_authenticated(0) || replay.commit_authenticated(0) || !replay.commit_authenticated(9000) ||
        !replay.commit_authenticated(9000-ReplayWindow::window_size) || replay.commit_authenticated(9000-ReplayWindow::window_size-1) ||
        replay.commit_authenticated(reject_after_messages) || replay.last()!=9000) return 13;
    for (std::uint64_t counter=9001;counter<20000;++counter) {
        if (!replay.commit_authenticated(counter) || replay.commit_authenticated(counter)) return 14;
        if (counter%63==0 && !replay.check(counter+1)) return 15;
    }
    // Compare the actual window with an independent exact set through jumps,
    // duplicates, ring wraps and near-limit counters.
    ReplayWindow tested; std::set<std::uint64_t> seen; std::uint64_t maximum=0;
    std::mt19937_64 random(0x108211);
    for (unsigned i=0;i<50000;++i) {
        auto counter=i%13==0 ? maximum+8192+(random()%10000) : random()%(maximum+100);
        auto expected_accept=counter>=maximum ? !seen.contains(counter) : maximum-counter<=ReplayWindow::window_size && !seen.contains(counter);
        if (tested.check(counter).has_value()!=expected_accept || tested.commit_authenticated(counter).has_value()!=expected_accept) return 16;
        if (expected_accept) { seen.insert(counter); maximum=std::max(maximum,counter); }
        while (!seen.empty() && maximum-*seen.begin()>ReplayWindow::window_size) seen.erase(seen.begin());
    }
    SendCounter sending(reject_after_messages-1);
    if (sending.take()!=reject_after_messages-1 || sending.take() || sending.next()!=reject_after_messages) return 17;
    std::array<std::uint8_t,3> reserved{1,2,3};
    if (ReservedProfile::create(Provider::standard,reserved) || ReservedProfile::create(Provider::warp,std::span(reserved).first(2))) return 18;
    auto warp=ReservedProfile::create(Provider::warp,reserved);
    if (!warp || !warp->apply(wire) || message_type(wire) || warp->restore(wire,false) || wire[1]!=1 || !warp->restore(wire,true) || !parse_initiation(wire)) return 19;
    if (!warp->apply(wire)) return 20;
    wire[3]=4;
    if (!warp->restore(wire,true) || !parse_initiation(wire) || !warp->restore(wire,true)) return 21;
    ReservedProfile standard;
    wire[2]=9;
    if (standard.restore(wire,true) || wire[2]!=9 || !warp->restore(wire,true)) return 22;
    auto malformed=wire; malformed[0]=255; malformed[1]=7;
    auto before=malformed;
    if (warp->restore(malformed,true) || malformed!=before || warp->restore(std::span(wire).first(3),true)) return 23;
    std::println("WireGuard exact wire layouts, TAI64N, replay windows, counters and explicit reserved adaptation passed");
}
