import std;
import nexus.shadowsocks.key;
import nexus.shadowsocks.chunk;
namespace s=nexus::shadowsocks;
auto hex(std::string_view text) -> std::vector<std::uint8_t> {
    auto digit=[](char c) { return c<='9' ? c-'0' : c-'a'+10; };
    std::vector<std::uint8_t> result;
    for (std::size_t i=0;i<text.size();i+=2) result.push_back(static_cast<std::uint8_t>(digit(text[i])*16+digit(text[i+1])));
    return result;
}
int main() {
    for (std::size_t size:{16u,32u}) {
        std::array<std::uint8_t,32> key{},salt{};
        for (std::size_t i=0;i<size;++i) { key[i]=static_cast<std::uint8_t>(i); salt[i]=static_cast<std::uint8_t>(i+size); }
        auto make=[&](bool enc) { return s::ChunkCipher::create(*s::SessionKey::derive(std::span{key}.first(size),std::span{salt}.first(size)),enc); };
        auto enc=make(true),dec=make(false);
        auto length=hex("0005"),hello=hex("68656c6c6f");
        auto c1=enc->process(length),c2=enc->process(hello);
        if (!c1 || !c2 || *c1!=hex(size==16 ? "f62e761028fc894b9a77d2429b7167173427" : "aa4bc52bd8bc8e4a2dab8bcb473e39f7e0b9") ||
            *c2!=hex(size==16 ? "8af00529ce082186ceba562e6176880532a1e7c15b" : "8268bcc061321794861798930279e6ff7d94135c5b")) return 1;
        if (dec->process(*c1)!=length || dec->process(*c2)!=hello) return 2;
        auto broken=make(false); (*c1)[0]^=1;
        if (broken->process(*c1).error()!=s::ChunkError::authentication_failed || broken->process(*c1).error()!=s::ChunkError::closed) return 3;
        auto large=make(true); std::vector<std::uint8_t> bytes(65535,0x42);
        auto encrypted=large->process(bytes); auto large_dec=make(false);
        if (!encrypted || large_dec->process(*encrypted)!=bytes) return 4;
        bytes.push_back(0); if (large->process(bytes).error()!=s::ChunkError::invalid_length || large->process({}).error()!=s::ChunkError::closed) return 5;
        auto moved=std::move(*enc); if (enc->process({}).error()!=s::ChunkError::closed || !moved.process({})) return 6;
    }
    std::cout << "Shadowsocks 2022 AEAD chunk vectors passed\n";
}
