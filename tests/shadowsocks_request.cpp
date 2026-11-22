import std;
import shadowsocks.request;
import shadowsocks.frame;
import shadowsocks.replay;
namespace s=shadowsocks;
auto hex(std::string_view text) -> std::vector<std::uint8_t> {
    auto digit=[](char c) { return c<='9' ? c-'0' : c-'a'+10; };
    std::vector<std::uint8_t> result;
    for (std::size_t i=0;i<text.size();i+=2) result.push_back(static_cast<std::uint8_t>(digit(text[i])*16+digit(text[i+1])));
    return result;
}
int main() {
    auto now=std::chrono::steady_clock::time_point{};
    std::array<std::uint8_t,7> address{1,127,0,0,1,0x1f,0x90};
    std::array<std::uint8_t,2> padding{0xaa,0xbb}; std::array<std::uint8_t,3> payload{1,2,3};
    for (std::size_t size:{16u,32u}) {
        std::array<std::uint8_t,32> psk{},salt{};
        for (std::size_t i=0;i<size;++i) { psk[i]=i; salt[i]=i+size; }
        auto key=std::span{psk}.first(size); auto salt_view=std::span{salt}.first(size);
        auto encoded=s::encode_request(key,salt_view,42,address,padding,payload);
        auto vector=hex(size==16 ? "101112131415161718191a1b1c1d1e1ff62b42ac3938191bfa7a7d5051bfe38efb15191f6e90aedb1f787be3ea6945a057d11955a0519e2020cf61dca1a4fc6fc0ab4aae891e789599" : "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3faa4efbd219eb5c8426827418aee69ddf92fe885903d02802187f7eeb72d0ac0ff402cca12fa3e65c28401af77fcfaf74a9f96890d5a58db459");
        if (!encoded || encoded->wire!=vector) return 1;
        {
            constexpr unsigned workers=16;
            s::ReplayTable shared(2); std::latch gate(workers); std::atomic<unsigned> accepted=0,rejected=0;
            std::vector<std::jthread> threads;
            for (unsigned i=0;i<workers;++i) threads.emplace_back([&] {
                gate.arrive_and_wait(); auto result=s::decode_request_prefix(key,vector,42,now,shared);
                if (result) ++accepted; else if (result.error()==s::RequestError::replay) ++rejected;
            });
            threads.clear();
            if (accepted!=1 || rejected!=workers-1 || shared.size()!=1) return 11;
        }
        {
            constexpr unsigned workers=32;
            auto wall=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
            std::vector<std::vector<std::uint8_t>> wires;
            for (unsigned i=0;i<workers;++i) {
                auto unique=salt; unique[0]=static_cast<std::uint8_t>(i);
                auto request=s::encode_request(key,std::span{unique}.first(size),wall,address,padding,payload);
                if (!request) return 12;
                wires.push_back(std::move(request->wire));
            }
            s::ReplayTable shared(workers); std::latch gate(workers); std::atomic<unsigned> accepted=0;
            std::vector<std::jthread> threads;
            for (unsigned i=0;i<workers;++i) threads.emplace_back([&,i] {
                gate.arrive_and_wait();
                if (s::decode_request_prefix_current(key,wires[i],shared)) ++accepted;
            });
            threads.clear();
            if (accepted!=workers || shared.size()!=workers) return 13;
            if (s::decode_request_prefix_current(key,wires[0],shared).error()!=s::RequestError::replay) return 14;
            auto stale=s::encode_request(key,salt_view,wall-31,address,padding,payload);
            if (!stale || s::decode_request_prefix_current(key,stale->wire,shared).error()!=s::RequestError::invalid_header) return 15;
        }
        s::ReplayTable replay(2); auto damaged=vector; damaged[size]^=1;
        if (s::decode_request_prefix(key,damaged,42,now,replay).error()!=s::RequestError::authentication || replay.size()!=0) return 2;
        if (s::decode_request_prefix(key,vector,73,now,replay).error()!=s::RequestError::invalid_header || replay.size()!=0) return 3;
        if (s::decode_request_prefix(key,std::span{vector}.first(size+26),42,now,replay).error()!=s::RequestError::short_read || replay.size()!=0) return 4;
        auto prefix=s::decode_request_prefix(key,vector,42,now,replay);
        if (!prefix || prefix->consumed!=size+27 || prefix->header_length!=14 || replay.size()!=1) return 5;
        if (s::decode_request_prefix(key,vector,42,now,replay).error()!=s::RequestError::replay) return 6;
        if (s::decode_request_prefix(key,vector,42,now+std::chrono::seconds(62),replay).error()!=s::RequestError::clock || replay.size()!=1) return 10;
        auto header=s::decode_request_header(std::move(*prefix),std::span{vector}.subspan(size+27));
        if (!header || !std::ranges::equal(header->salt,salt_view) || !std::ranges::equal(header->header.address,address) || !std::ranges::equal(header->header.payload,payload)) return 7;
        s::FrameEncoder writer(std::move(encoded->cipher)); s::FrameDecoder reader(std::move(header->cipher));
        auto following=writer.encode(payload); if (!following) return 8;
        auto next=reader.feed(*following); if (!next || !next->payload || !std::ranges::equal(*next->payload,payload) || !reader.finish()) return 8;
        s::ReplayTable other(1); auto prefix2=s::decode_request_prefix(key,vector,42,now,other);
        damaged=vector; damaged.back()^=1;
        if (s::decode_request_header(std::move(*prefix2),std::span{damaged}.subspan(size+27)).error()!=s::RequestError::authentication || other.size()!=1) return 9;
    }
    std::cout << "Shadowsocks 2022 request vectors passed\n";
}
