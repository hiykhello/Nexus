import std;
import quic.varint;
namespace q=quic;
auto main() -> int {
    std::vector<std::pair<std::vector<std::uint8_t>,std::uint64_t>> vectors{
        {{0x25},37},{{0x7b,0xbd},15293},{{0x9d,0x7f,0x3e,0x7d},494878333},
        {{0xc2,0x19,0x7c,0x5e,0xff,0x14,0xe8,0x8c},151288809941952652},
        {{0x40,0x25},37},{{0x80,0,0,0x25},37},{{0xc0,0,0,0,0,0,0,0x25},37}
    };
    for (auto const& [bytes,value]:vectors) {
        auto parsed=q::read_varint(bytes);
        if (parsed.status!=q::VarintStatus::accepted || parsed.consumed!=bytes.size() || parsed.value!=value) return 1;
        auto wire=bytes; wire.insert(wire.end(),bytes.begin(),bytes.end());
        for (std::size_t split=0;split<=bytes.size();++split) {
            q::VarintDecoder decoder;
            auto first=decoder.feed(std::span(wire).first(split)),second=decoder.feed(std::span(wire).subspan(split));
            if ((split<bytes.size() && first.status!=q::VarintStatus::incomplete) || second.status!=q::VarintStatus::accepted ||
                first.consumed+second.consumed!=bytes.size() || second.value!=value || decoder.feed(wire).consumed) return 2;
            decoder.reset();
            for (std::size_t i=0;i<bytes.size();++i) {
                auto part=decoder.feed(std::span(wire).subspan(i,1));
                if (part.consumed!=1 || part.status!=(i+1==bytes.size() ? q::VarintStatus::accepted : q::VarintStatus::incomplete)) return 3;
            }
            decoder.close(); if (decoder.feed(wire).status!=q::VarintStatus::closed) return 4;
        }
        for (std::size_t size=0;size<bytes.size();++size)
            if (q::read_varint(std::span(bytes).first(size)).status!=q::VarintStatus::incomplete) return 5;
    }
    for (auto value:std::array<std::uint64_t,13>{0,1,63,64,16383,16384,1073741823,1073741824,q::max_varint,37,15293,494878333,151288809941952652}) {
        for (auto width:{1u,2u,4u,8u}) {
            std::array<std::uint8_t,8> encoded; encoded.fill(0xa5);
            auto before=encoded;
            auto size=q::write_varint(encoded,value,width);
            if (width<q::varint_size(value)) { if (size || encoded!=before) return 6; continue; }
            if (!size || *size!=width) return 7;
            auto parsed=q::read_varint(encoded);
            if (parsed.value!=value || parsed.consumed!=width) return 8;
        }
        std::vector<std::uint8_t> output;
        if (!q::append_varint(output,value) || output.size()!=q::varint_size(value) || q::read_varint(output).value!=value) return 9;
        if (q::write_varint(std::span<std::uint8_t>{},value)) return 10;
    }
    std::array<std::uint8_t,8> unchanged{}; auto before=unchanged;
    if (q::write_varint(unchanged,q::max_varint+1) || q::write_varint(unchanged,0,3) || unchanged!=before) return 11;
    std::println("QUIC RFC9000 varint vectors, legal wider widths, retained boundaries and arbitrary fragments passed");
}

