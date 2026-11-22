import std;
import tailscale.control_http;
namespace h=tailscale::control_http;
using Bytes=std::vector<std::uint8_t>;
using namespace std::chrono_literals;
using namespace std::string_view_literals;
namespace {
    std::atomic<std::size_t> allocations=0;
    auto allocate(std::size_t size,std::size_t alignment=0) -> void* {
        ++allocations;size=std::max(std::size_t{1},size);
        if (alignment && size>std::numeric_limits<std::size_t>::max()-(alignment-1)) throw std::bad_alloc();
        auto value=alignment ? std::aligned_alloc(alignment,((size+alignment-1)/alignment)*alignment) : std::malloc(size);
        if (!value) throw std::bad_alloc();return value;
    }
}
auto operator new(std::size_t size) -> void* {return allocate(size);}
auto operator new[](std::size_t size) -> void* {return allocate(size);}
auto operator new(std::size_t size,std::align_val_t alignment) -> void* {return allocate(size,static_cast<std::size_t>(alignment));}
auto operator new[](std::size_t size,std::align_val_t alignment) -> void* {return allocate(size,static_cast<std::size_t>(alignment));}
auto operator delete(void* pointer) noexcept -> void {std::free(pointer);}
auto operator delete[](void* pointer) noexcept -> void {std::free(pointer);}
auto operator delete(void* pointer,std::size_t) noexcept -> void {std::free(pointer);}
auto operator delete[](void* pointer,std::size_t) noexcept -> void {std::free(pointer);}
auto operator delete(void* pointer,std::align_val_t) noexcept -> void {std::free(pointer);}
auto operator delete[](void* pointer,std::align_val_t) noexcept -> void {std::free(pointer);}
auto operator delete(void* pointer,std::size_t,std::align_val_t) noexcept -> void {std::free(pointer);}
auto operator delete[](void* pointer,std::size_t,std::align_val_t) noexcept -> void {std::free(pointer);}
auto require(bool condition,std::string_view message) -> void {if (!condition) throw std::runtime_error(std::string(message));}
auto view(std::string_view text) -> std::span<std::uint8_t const> {return {reinterpret_cast<std::uint8_t const*>(text.data()),text.size()};}
inline constexpr auto start=h::Clock::time_point{}+1s,limit=start+5s;
inline constexpr std::string_view response="HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\n\r\n";
inline constexpr std::string_view early_json=R"({"nodeKeyChallenge":"chalpub:0000000000000000000000000000000000000000000000000000000000000000","future":{"value":1}})";
auto initiation() -> std::array<std::uint8_t,h::initiation_bytes> {
    std::array<std::uint8_t,h::initiation_bytes> value{};for (unsigned i=0;i<value.size();++i) value[i]=static_cast<std::uint8_t>(i);
    value[2]=1;value[3]=0;value[4]=96;return value;
}
auto payload(std::size_t size) -> Bytes {Bytes bytes(size);for (std::size_t i=0;i<size;++i) bytes[i]=static_cast<std::uint8_t>(i*17+size);return bytes;}
auto framed(std::span<std::uint8_t const> body,bool early) -> Bytes {
    Bytes wire(early ? 9 : 4);
    if (early) {wire[0]=wire[1]=wire[2]=0xff;wire[3]='T';wire[4]='S';for (unsigned i=0;i<4;++i) wire[8-i]=static_cast<std::uint8_t>(body.size()>>(8*i));}
    else for (unsigned i=0;i<4;++i) wire[i]=static_cast<std::uint8_t>(body.size()>>(8*i));
    wire.insert(wire.end(),body.begin(),body.end());return wire;
}
auto requests() -> void {
    auto initial=initiation();std::array<std::uint8_t,1024> buffer{};buffer.fill(0xa5);
    auto wire=h::encode_upgrade_request(buffer,"control.example:443",initial);require(bool(wire),"POST encoder");
    auto text=std::string_view(reinterpret_cast<char const*>(buffer.data()),*wire);
    require(text.starts_with("POST /ts2021 HTTP/1.1\r\nHost: control.example:443\r\n") && text.ends_with("\r\nContent-Length: 0\r\n\r\n") &&
        text.contains("Upgrade: tailscale-control-protocol\r\nX-Tailscale-Handshake: ") && text.find("\r\n\r\n")==text.size()-4,"init sent outside single header");
    std::array<std::uint8_t,1024> output{};output.fill(0xa5);
    require(!h::encode_upgrade_request(std::span(output).first(*wire-1),"control.example:443",initial) && std::ranges::all_of(output,[](auto x){return x==0xa5;}),"capacity wrote request");
    for (std::string_view authority:{"","a\r\nHost: evil","a b","http://example.com","a@b","a#b","a?b","a\\b"})
        require(!h::encode_upgrade_request(output,authority,initial),"unsafe authority accepted");
    require(!h::encode_upgrade_request(output,std::string(513,'a'),initial),"authority size");
    auto bad=initial;bad[2]=2;require(!h::encode_upgrade_request(output,"example.com",bad),"non-initiation frame encoded");
    std::ranges::copy(initial,output.begin());auto previous=output;
    require(!h::encode_upgrade_request(output,"example.com",std::span<std::uint8_t const,h::initiation_bytes>(output.data(),h::initiation_bytes)) && output==previous,"init overlap");
    output.fill('a');previous=output;
    require(!h::encode_upgrade_request(output,{reinterpret_cast<char const*>(output.data()),17},initial) && output==previous,"authority overlap");
}
auto responses() -> void {
    for (auto text:{response,"HTTP/1.1 101\r\nConnection: keep-alive, UpGrAdE\r\nUpgrade: tailscale-control-protocol\r\nContent-Length: 0\r\nFuture: x\r\n\r\n"sv}) {
        Bytes combined(view(text).begin(),view(text).end());combined.insert(combined.end(),{2,0,48,1,2,3,4,5,6,7});
        for (std::size_t chunk:{1,2,3,7,1024}) {
            h::UpgradeResponseDecoder decoder(start,limit);std::size_t used=0;bool ready=false;
            while (!ready) {
                auto result=decoder.feed(std::span(combined).subspan(used,std::min(chunk,combined.size()-used)),start+1ms);
                require(!result.error,"valid upgrade response");used+=result.consumed;ready=result.ready;
            }
            require(used==text.size() && combined[used]==2 && decoder.feed(std::span(combined).subspan(used),start+2ms).consumed==0 && bool(decoder.eof()),"Noise pre-read consumed/lost");
        }
    }
    for (auto text:{"HTTP/1.1 200 OK\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\n\r\n",
        "HTTP/1.0 101\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\n\r\n",
        "HTTP/1.1 101x\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\n\r\n",
        "HTTP/1.1 101\r\nUpgrade: tailscale-control-protocol\r\n\r\n",
        "HTTP/1.1 101\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        "HTTP/1.1 101\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\nUpgrade: tailscale-control-protocol\r\n\r\n",
        "HTTP/1.1 101\r\nConnection: upgrade\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\n\r\n",
        "HTTP/1.1 101\r\nConnection: upgrade, close\r\nUpgrade: tailscale-control-protocol\r\n\r\n",
        "HTTP/1.1 101\r\nConnection: upgrade,\r\nUpgrade: tailscale-control-protocol\r\n\r\n",
        "HTTP/1.1 101\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\nContent-Length: 1\r\n\r\n",
        "HTTP/1.1 101\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 101\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\nTransfer-Encoding: chunked\r\n\r\n",
        "HTTP/1.1 101\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\nExpect: 100-continue\r\n\r\n",
        "HTTP/1.1 101\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\nFuture: x\r\n folded\r\n\r\n"}) {
        h::UpgradeResponseDecoder decoder(start,limit);auto result=decoder.feed(view(text),start);
        require(result.error && !result.ready && decoder.feed(view(response),start).error,"invalid upgrade accepted/recovered");
    }
    for (std::size_t size=0;size<response.size();++size) {
        h::UpgradeResponseDecoder decoder(start,limit);auto result=decoder.feed(view(response).first(size),start);
        require(!result.ready && !result.error && !decoder.eof() && decoder.feed(view(response),start).error==h::Error::closed,"truncated upgrade EOF");
    }
    auto check_bound=[](std::string const& text) {h::UpgradeResponseDecoder decoder(start,limit);require(bool(decoder.feed(view(text),start).error),"HTTP header bound");};
    check_bound(std::string(16384,'a'));
    auto fields=std::string(response.substr(0,response.size()-2));for (unsigned i=0;i<100;++i) fields+="X: a\r\n";fields+="\r\n";check_bound(fields);
    auto line=std::string(response.substr(0,response.size()-2))+"X: "+std::string(8192,'a')+"\r\n\r\n";check_bound(line);
    h::UpgradeResponseDecoder late(start,limit);require(!late.feed(view(response).first(7),start+1s).error && late.feed(view(response).subspan(7),limit).error==h::Error::timeout,"upgrade budget reset");
    h::UpgradeResponseDecoder rollback(start,limit);require(!rollback.feed({},start+1s).error && rollback.feed(view(response),start).error==h::Error::timeout,"upgrade clock rollback");
}
auto prefaces() -> void {
    std::array<std::uint8_t,9> h2{0,0,0,4,0,0,0,0,0};Bytes bytes(h2.begin(),h2.end());bytes.insert(bytes.end(),{1,2,3});
    std::array<std::uint8_t,256> storage{};storage.fill(0xa5);
    h::EarlyPrefaceDecoder plain(storage,start,limit);auto fed=plain.feed(bytes,start);
    require(fed.ready && fed.consumed==9 && !fed.error && plain.kind()==h::PrefaceKind::http2 && std::ranges::equal(plain.prefix(),h2) &&
        !plain.payload() && std::ranges::all_of(storage,[](auto x){return x==0xa5;}),"nonmagic 9-byte H2 prefix");
    auto wire=framed(view(early_json),true);wire.insert(wire.end(),h2.begin(),h2.end());
    for (std::size_t chunk:{1,2,3,9,17,1024}) {
        h::EarlyPrefaceDecoder decoder(storage,start,limit);std::size_t used=0;
        for (;;) {auto step=decoder.feed(std::span(wire).subspan(used,std::min(chunk,wire.size()-used)),start);require(!step.error,"early decode");used+=step.consumed;if (step.ready) break;}
        require(used==9+early_json.size() && decoder.payload() && std::ranges::equal(*decoder.payload(),view(early_json)) && decoder.prefix().empty() &&
            decoder.feed(std::span(wire).subspan(used),start).consumed==0 && bool(decoder.eof()),"early payload/H2 handoff");
    }
    for (std::size_t size=0;size<9+early_json.size();++size) {
        h::EarlyPrefaceDecoder decoder(storage,start,limit);require(!decoder.feed(std::span(wire).first(size),start).error && !decoder.eof(),"truncated early EOF");
    }
    auto empty=framed({},true);h::EarlyPrefaceDecoder empty_decoder({},start,limit);
    require(empty_decoder.feed(empty,start).ready && empty_decoder.payload() && empty_decoder.payload()->empty(),"zero early framing must reach typed JSON validator");
    Bytes full(h::max_early_payload,0x61),scratch(full.size());auto maximum=framed(full,true);
    h::EarlyPrefaceDecoder max(scratch,start,limit);require(max.feed(maximum,start).ready && max.payload()->size()==full.size(),"early max boundary");
    maximum[8]=1;h::EarlyPrefaceDecoder huge(scratch,start,limit);require(huge.feed(maximum,start).error==h::Error::size,"early maximum+1/wire cap");
    h::EarlyPrefaceDecoder small{std::span(storage).first(1),start,limit};require(small.feed(wire,start).error==h::Error::capacity,"early caller cap");
    h::EarlyPrefaceDecoder overlap(storage,start,limit);auto before=storage;require(overlap.feed(std::span(storage).first(17),start).error==h::Error::overlap && storage==before,"early overlap writes");
    h::EarlyPrefaceDecoder late(storage,start,limit);require(!late.feed(std::span(wire).first(5),start+1s).error && late.feed(std::span(wire).subspan(5),limit).error==h::Error::timeout,"early original deadline");
}
auto maps() -> void {
    auto body=payload(17),wire=framed(body,false);Bytes joined=wire;joined.insert(joined.end(),wire.begin(),wire.end());std::array<std::uint8_t,64> storage{};
    for (std::size_t chunk:{1,2,3,4,7,64}) {
        h::MapFrameDecoder decoder(storage);std::size_t used=0;
        for (;;) {auto step=decoder.feed(std::span(joined).subspan(used,std::min(chunk,joined.size()-used)));require(!step.error,"map decode");used+=step.consumed;if (step.ready) break;}
        require(used==wire.size() && decoder.payload() && std::ranges::equal(*decoder.payload(),body) && decoder.feed(std::span(joined).subspan(used)).consumed==0,"map overconsume/view");
        require(bool(decoder.consume()),"map consume");auto second=decoder.feed(std::span(joined).subspan(used));
        require(second.ready && second.consumed==wire.size() && bool(decoder.consume()) && bool(decoder.eof()) && decoder.feed(wire).error==h::Error::closed,"map coalesced/EOF");
    }
    for (std::size_t size=1;size<wire.size();++size) {h::MapFrameDecoder decoder(storage);require(!decoder.feed(std::span(wire).first(size)).error && !decoder.eof(),"truncated map EOF");}
    for (auto header:{std::array<std::uint8_t,4>{0,0,0,0},std::array<std::uint8_t,4>{1,0,64,0},std::array<std::uint8_t,4>{0xff,0xff,0xff,0xff}}) {
        h::MapFrameDecoder decoder(storage);require(decoder.feed(header).error==h::Error::size && decoder.feed(wire).error,"map zero/oversize accepted/recovered");
    }
    h::MapFrameDecoder small{std::span(storage).first(16)};storage.fill(0xa5);auto before=storage;
    require(small.feed(wire).error==h::Error::capacity && storage==before,"map cap writes");
    h::MapFrameDecoder overlap(storage);require(overlap.feed(std::span(storage).first(17)).error==h::Error::overlap && storage==before,"map overlap writes");
    Bytes full(h::max_map_frame,0x61),scratch(full.size());auto maximum=framed(full,false);h::MapFrameDecoder max(scratch);
    require(max.feed(maximum).ready && max.payload()->size()==full.size() && bool(max.consume()) && bool(max.eof()),"map exact maximum");
}
auto zero_allocations() -> void {
    auto initial=initiation();std::array<std::uint8_t,1024> request{};std::array<std::uint8_t,256> early{},map{};
    auto ewire=framed(view(early_json),true),mwire=framed(view(early_json),false);auto before=allocations.load();
    for (unsigned i=0;i<100;++i) {
        require(bool(h::encode_upgrade_request(request,"control.example",initial)),"measured request");
        h::UpgradeResponseDecoder response_decoder(start,limit);require(response_decoder.feed(view(response),start).ready,"measured response");
        h::EarlyPrefaceDecoder early_decoder(early,start,limit);require(early_decoder.feed(ewire,start).ready,"measured early");
        h::MapFrameDecoder map_decoder(map);require(map_decoder.feed(mwire).ready && bool(map_decoder.consume()) && bool(map_decoder.eof()),"measured map");
    }
    require(allocations.load()==before,"codec C++ allocation");
}
auto hex(std::span<std::uint8_t const> bytes) -> std::string {std::string result;for (auto byte:bytes) {result+="0123456789abcdef"[byte>>4];result+="0123456789abcdef"[byte&15];}return result;}
auto vectors() -> void {
    auto initial=initiation();std::array<std::uint8_t,1024> output{};
    for (std::string_view authority:{"control.example","control.example:8443","[::1]:8080"}) {
        auto n=h::encode_upgrade_request(output,authority,initial);require(bool(n),"vector request");std::println("request-{}={}",authority,hex(std::span(output).first(*n)));
    }
    auto early=framed(view(early_json),true);std::println("early-wire={}",hex(early));
    std::array<std::uint8_t,256> storage{};h::EarlyPrefaceDecoder decoder(storage,start,limit);require(decoder.feed(early,start).ready,"vector early");
    std::println("early-payload={}",hex(*decoder.payload()));
    std::array<std::uint8_t,9> h2{0,0,0,4,0,0,0,0,0};h::EarlyPrefaceDecoder plain(storage,start,limit);require(plain.feed(h2,start).ready,"vector h2");
    std::println("h2-prefix={}",hex(plain.prefix()));
    for (std::size_t size:{1,17,256}) {auto body=payload(size),wire=framed(body,false);std::println("map-{}={}",size,hex(wire));}
}
auto main(int argc,char** argv) -> int {
    try {
        if (argc==2 && std::string_view(argv[1])=="--vectors") {vectors();return 0;}
        requests();responses();prefaces();maps();zero_allocations();
        std::println("TS2021 POST/header-only initiation, bounded 101/early/Map handoff, deadlines, zero/truncation/overlap and zero C++ allocation passed");
        std::println("sizeof(UpgradeResponseDecoder)={} EarlyPrefaceDecoder={} MapFrameDecoder={}",sizeof(h::UpgradeResponseDecoder),sizeof(h::EarlyPrefaceDecoder),sizeof(h::MapFrameDecoder));
    } catch (std::exception const& error) {std::cerr<<error.what()<<'\n';return 1;}
}
