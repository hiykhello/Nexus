import std;
import grpc.message;
namespace g=grpc;
auto main() -> int {
    for (auto size:{0u,1u,127u,128u,16384u,1048576u}) {
        std::vector<std::uint8_t> data(size,173);
        auto encoded=g::encode_message(data); if (!encoded) return 1;
        auto input=*encoded; input.insert(input.end(),encoded->begin(),encoded->end());
        for (auto chunk:{1u,3u,7u,4096u,1048592u}) {
            g::MessageDecoder decoder;
            std::size_t consumed=0;
            while (consumed<encoded->size()) {
                auto fed=decoder.feed(std::span(input).subspan(consumed,std::min(std::size_t{chunk},input.size()-consumed)));
                if (!fed.consumed || (fed.status!=g::MessageStatus::incomplete && fed.status!=g::MessageStatus::accepted)) return 2;
                consumed+=fed.consumed;
            }
            auto decoded=decoder.data();
            if (consumed!=encoded->size() || !decoded || !std::ranges::equal(*decoded,data) ||
                decoder.wire_size()!=encoded->size() || decoder.feed(input).consumed || decoder.at_boundary()) return 3;
            if (!decoder.consume() || !decoder.at_boundary() || decoder.feed(*encoded).status!=g::MessageStatus::accepted) return 4;
            decoder.close(); if (decoder.data() || decoder.consume() || decoder.feed(input).status!=g::MessageStatus::closed) return 5;
        }
    }
    auto abc=*g::encode_message(std::array<std::uint8_t,3>{'a','b','c'});
    if (abc!=std::vector<std::uint8_t>{0,0,0,0,5,10,3,'a','b','c'} ||
        *g::encode_message({})!=std::vector<std::uint8_t>{0,0,0,0,0}) return 6;
    std::vector<std::vector<std::uint8_t>> valid{{}, {10,0}, {10,1,'a',10,1,'b'},
        {16,129,1,10,1,'a'}, {17,0,0,0,0,0,0,0,0,10,1,'a'}, {18,2,3,4,10,1,'a'}, {21,0,0,0,0,10,1,'a'},
        {19,24,1,20,10,1,'a'}};
    for (auto const& message:valid) {
        auto hunk=g::parse_hunk(message);
        if (hunk.status!=g::MessageStatus::accepted || (!message.empty() && message!=std::vector<std::uint8_t>{10,0} && hunk.data.empty())) return 7;
    }
    auto last=g::parse_hunk(valid[2]);
    if (!std::ranges::equal(last.data,std::array<std::uint8_t,1>{'b'})) return 8;
    for (auto message:std::vector<std::vector<std::uint8_t>>{{0}, {8,1}, {10,3,'a'}, {10,128}, {128}, {16,128}, {17,0},
        {18,3,0}, {19,28}, {20}, {22}, {10,255,255,255,255,255,255,255,255,255,2}})
        if (g::parse_hunk(message).status==g::MessageStatus::accepted) return 9;
    for (auto byte:{1u,2u,255u}) {
        auto wire=abc; wire[0]=static_cast<std::uint8_t>(byte); g::MessageDecoder decoder;
        auto fed=decoder.feed(wire);
        if (fed.consumed!=5 || fed.status!=(byte==1 ? g::MessageStatus::compressed : g::MessageStatus::malformed) || decoder.data()) return 10;
    }
    g::MessageDecoder wire_limited(4),data_limited(16,2);
    if (wire_limited.feed(abc).status!=g::MessageStatus::too_large || data_limited.feed(abc).status!=g::MessageStatus::too_large) return 11;
    for (std::size_t split=0;split<abc.size();++split) {
        g::MessageDecoder decoder;
        if (decoder.feed(std::span(abc).first(split)).status!=g::MessageStatus::incomplete ||
            decoder.finish()!=(split ? g::MessageStatus::truncated : g::MessageStatus::accepted)) return 12;
    }
    std::vector<std::uint8_t> overflow(10,255); overflow.back()=2;
    if (g::read_varint(overflow).status!=g::MessageStatus::malformed) return 13;
    if (g::encode_message(std::vector<std::uint8_t>(g::max_hunk_bytes+1))) return 14;
    std::vector<std::uint8_t> lite{0,0,0,0,2,10,0}; g::MessageDecoder empty;
    auto accepted=empty.feed(lite); auto data=empty.data();
    if (accepted.status!=g::MessageStatus::accepted || !data || !data->empty() || !empty.consume() || !empty.at_boundary()) return 15;
    std::println("gRPC length/compression and protobuf Hunk vectors, empty messages, arbitrary fragments, retained boundaries and limits passed");
}
