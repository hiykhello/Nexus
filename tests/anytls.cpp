import std;
import anytls;

auto main() -> int {
    using namespace anytls;
    Key key;
    std::iota(key.begin(),key.end(),0);
    for (auto padding:{0u,30u,65535u}) {
        auto request=encode_authentication(key,padding);
        if (!request || request->size()!=34+padding || (*request)[32]!=(padding>>8) || (*request)[33]!=(padding&255)) return 1;
        auto input=*request; input.push_back(123);
        for (auto split:{std::size_t{0},std::size_t{1},std::size_t{31},std::size_t{32},std::size_t{33},request->size()}) {
            AuthenticationDecoder decoder;
            auto first=decoder.feed(std::span(input).first(split));
            auto second=decoder.feed(std::span(input).subspan(split));
            auto decoded_key=decoder.key();
            if ((split<request->size() && first.status!=Status::incomplete) || second.status!=Status::accepted ||
                first.consumed+second.consumed!=request->size() || !decoded_key || !std::ranges::equal(*decoded_key,key)) return 2;
            if (decoder.feed(input).consumed) return 3;
        }
        AuthenticationDecoder bytewise;
        for (std::size_t index=0;index<request->size();++index) {
            auto fed=bytewise.feed(std::span(*request).subspan(index,1));
            if (fed.consumed!=1 || fed.status!=(index+1==request->size() ? Status::accepted : Status::incomplete)) return 4;
        }
    }
    if (encode_authentication(std::span(key).first(31),0) || encode_authentication(key,65536)) return 5;
    AuthenticationDecoder limited(29);
    auto auth=*encode_authentication(key,30);
    auto denied=limited.feed(auth);
    if (denied.status!=Status::too_large || denied.consumed!=34 || limited.key()) return 6;
    for (auto command:{Command::waste,Command::syn,Command::push,Command::fin,Command::settings,Command::alert,
                       Command::padding,Command::syn_ack,Command::heart_request,Command::heart_response,
                       Command::server_settings,static_cast<Command>(255)}) {
        for (auto size:{0u,1u,4096u,65535u}) {
            std::vector<std::uint8_t> payload(size,173);
            auto wire=*encode_frame(command,0x01020304,payload);
            auto pair=wire; pair.insert(pair.end(),wire.begin(),wire.end());
            for (auto chunk:{1u,3u,4095u,65542u}) {
                FrameDecoder decoder;
                std::size_t consumed=0;
                while (consumed<wire.size()) {
                    auto fed=decoder.feed(std::span(pair).subspan(consumed,std::min(std::size_t{chunk},pair.size()-consumed)));
                    consumed+=fed.consumed;
                    if (!fed.consumed || (fed.status!=Status::incomplete && fed.status!=Status::accepted)) return 7;
                }
                auto frame=decoder.frame();
                if (consumed!=wire.size() || !frame || frame->header.command!=command || frame->header.stream!=0x01020304 ||
                    frame->header.length!=payload.size() || !std::ranges::equal(frame->payload,payload) ||
                    decoder.feed(pair).consumed || decoder.at_boundary()) return 8;
                if (!decoder.consume() || !decoder.at_boundary() || decoder.feed(wire).status!=Status::accepted) return 9;
                decoder.close();
                if (decoder.frame() || decoder.feed(wire).status!=Status::closed || decoder.consume()) return 10;
            }
        }
    }
    std::array<std::uint8_t,4> data{0,1,2,255};
    auto frame=*encode_frame(Command::push,0x01020304,data);
    if (frame!=std::vector<std::uint8_t>{2,1,2,3,4,0,4,0,1,2,255}) return 11;
    FrameDecoder small(3);
    if (small.feed(frame).status!=Status::too_large || small.frame() || small.at_boundary() || small.feed(frame).consumed) return 12;
    std::vector<std::uint8_t> oversized(65536);
    if (encode_frame(Command::push,1,oversized)) return 13;
    std::println("AnyTLS authentication/frame vectors, arbitrary fragments, retained boundaries and resource limits passed");
}
