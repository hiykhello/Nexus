import std;
import anytls;
import anytls.padding;

auto main() -> int {
    using namespace anytls;
    auto scheme=PaddingScheme::parse(default_padding_scheme);
    if (!scheme || scheme->raw()!=default_padding_scheme || scheme->stop()!=8 || scheme->steps(0).size()!=1 ||
        scheme->steps(2).size()!=9 || !scheme->steps(2)[1].check || !scheme->steps(8).empty()) return 1;
    if (sample_padding(scheme->steps(0)[0],0)!=30 || sample_padding({true},123)) return 2;
    for (auto random:{0u,1u,195u,196u,299u,300u,1000u,0xffffffffu}) {
        auto size=sample_padding({false,100,400},random);
        if ((random<196)!=!size || (size && (*size<100 || *size>=400))) return 3;
    }
    auto reverse=PaddingScheme::parse("stop=2\r\n1=200-100,c\r\n");
    if (!reverse || reverse->steps(1).size()!=2 || reverse->steps(1)[0].min!=100 || reverse->steps(1)[0].max!=200) return 4;
    auto stopped=PaddingScheme::parse("stop=0\n0=30-30\n1=100-200");
    if (!stopped || stopped->steps(0).size()!=1 || !stopped->steps(1).empty()) return 4;
    for (auto text:{"", "1=1-2", "stop=-1", "stop=1\nstop=2", "stop=1\n1=2-3\n1=3-4", "stop=1\n01=2-3",
                    "stop=1\n1=0-1", "stop=1\n1=1-1048577", "stop=1\n0=65535-65536", "stop=1\n1=1-2,", "stop=1\n1=bad", "stop=1\n1=1--2"})
        if (PaddingScheme::parse(text)) return 5;
    std::array<std::uint8_t,4> payload{0,1,2,255};
    auto input=*encode_frame(Command::push,1,payload);
    for (auto size:{11u,12u,18u,19u,30u,65535u,1048576u}) {
        auto padded=pad_packet(input,size);
        if (!padded || padded->size()>size || !std::ranges::equal(std::span(*padded).first(input.size()),input)) return 6;
        FrameDecoder decoder;
        std::size_t offset=0;
        while (offset<padded->size()) {
            auto fed=decoder.feed(std::span(*padded).subspan(offset)); offset+=fed.consumed;
            auto frame=decoder.frame();
            if (fed.status!=Status::accepted || !frame || (offset>input.size() &&
                (frame->header.command!=Command::waste || frame->header.stream || std::ranges::any_of(frame->payload,[](auto value) { return value!=0; })))) return 7;
            if (!decoder.consume()) return 8;
        }
        if (!decoder.at_boundary()) return 9;
    }
    for (auto size:{0u,1u,9u,65535u,65536u,1048576u}) {
        auto padded=pad_packet({},size);
        if (!padded || padded->size()!=size+((size+65534)/65535)*header_size) return 10;
        FrameDecoder decoder;
        std::size_t offset=0;
        while (offset<padded->size()) {
            auto fed=decoder.feed(std::span(*padded).subspan(offset)); offset+=fed.consumed;
            auto frame=decoder.frame();
            if (!frame || frame->header.command!=Command::waste || frame->header.stream || !decoder.consume()) return 11;
        }
    }
    if (pad_packet({},1048577) || pad_packet(input,10)) return 12;
    std::println("AnyTLS bounded padding scheme, unbiased sample rejection and exact waste framing passed");
}
