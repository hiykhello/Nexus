import std;
import shadowsocks.key;
import shadowsocks.chunk;
import shadowsocks.frame;
namespace s=shadowsocks;
auto hex(std::string_view text) -> std::vector<std::uint8_t> {
    auto digit=[](char c) { return c<='9' ? c-'0' : c-'a'+10; };
    std::vector<std::uint8_t> result;
    for (std::size_t i=0;i<text.size();i+=2) result.push_back(static_cast<std::uint8_t>(digit(text[i])*16+digit(text[i+1])));
    return result;
}
int main() {
    for (std::size_t size:{16u,32u}) {
        std::array<std::uint8_t,32> key{},salt{};
        for (std::size_t i=0;i<size;++i) { key[i]=i; salt[i]=i+size; }
        auto cipher=[&](bool encrypt) { auto k=s::SessionKey::derive(std::span{key}.first(size),std::span{salt}.first(size)); return s::ChunkCipher::create(std::move(*k),encrypt); };
        s::FrameEncoder enc(std::move(*cipher(true))); s::FrameDecoder dec(std::move(*cipher(false)));
        auto hello=hex("68656c6c6f"); auto wire=enc.encode(hello);
        auto expected=hex(size==16 ? "f62e761028fc894b9a77d2429b71671734278af00529ce082186ceba562e6176880532a1e7c15b" : "aa4bc52bd8bc8e4a2dab8bcb473e39f7e0b98268bcc061321794861798930279e6ff7d94135c5b");
        if (!wire || *wire!=expected) return 1;
        for (std::size_t i=0;i<wire->size();++i) {
            auto step=dec.feed(std::span{*wire}.subspan(i,1));
            if (!step || step->consumed!=1 || (i+1<wire->size() && step->payload) ||
                (i+1==wire->size() && (!step->payload || *step->payload!=hello))) return 2;
        }
        std::vector<std::uint8_t> large(65535,0x42);
        auto empty=enc.encode({}), big=enc.encode(large); if (!empty || !big) return 3;
        auto joined=*empty; joined.insert(joined.end(),big->begin(),big->end());
        auto first=dec.feed(joined);
        if (!first || !first->payload || !first->payload->empty() || first->consumed!=empty->size()) return 4;
        auto second=dec.feed(std::span{joined}.subspan(first->consumed));
        if (!second || !second->payload || *second->payload!=large || second->consumed!=big->size() || !dec.finish()) return 5;
        if (dec.feed({}).error()!=s::FrameError::closed) return 6;
        for (std::size_t cut=1;cut<wire->size();++cut) {
            s::FrameDecoder partial(std::move(*cipher(false)));
            if (!partial.feed(std::span{*wire}.first(cut)) || partial.finish().error()!=s::FrameError::truncated) return 7;
        }
        for (std::size_t index:{0u,18u}) {
            auto bad=*wire; bad[index]^=1; s::FrameDecoder broken(std::move(*cipher(false)));
            if (broken.feed(bad).error()!=s::FrameError::authentication || broken.feed({}).error()!=s::FrameError::closed) return 8;
        }
        large.push_back(1); if (enc.encode(large).error()!=s::FrameError::invalid_length || enc.encode({}).error()!=s::FrameError::closed) return 9;
    }
    std::cout << "Shadowsocks 2022 data frames passed\n";
}
