import std;
import shadowsocks.response;
import shadowsocks.frame;
import shadowsocks.key;
import shadowsocks.chunk;
import shadowsocks.header;
namespace s=shadowsocks;
auto hex(std::string_view text) -> std::vector<std::uint8_t> {
    auto digit=[](char c) { return c<='9' ? c-'0' : c-'a'+10; };
    std::vector<std::uint8_t> result;
    for (std::size_t i=0;i<text.size();i+=2) result.push_back(static_cast<std::uint8_t>(digit(text[i])*16+digit(text[i+1])));
    return result;
}
int main() {
    std::array<std::uint8_t,3> payload{1,2,3};
    for (std::size_t size:{16u,32u}) {
        std::array<std::uint8_t,32> key{},salt{},request{};
        for (std::size_t i=0;i<size;++i) { key[i]=i; request[i]=i+size; salt[i]=i+2*size; }
        auto k=std::span{key}.first(size); auto r=std::span{request}.first(size); auto s=std::span{salt}.first(size);
        auto encoded=s::encode_response(k,s,r,42,payload);
        auto vector=hex(size==16 ? "202122232425262728292a2b2c2d2e2fcfd439ccd5ae0bf118874d1521cc11d623310888444d4ba6dd1ab8510d804230fbc66b6e181eecc277da4f1fdf91cfb5bad2b83f5e5d619f652490cf99e9" : "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f6874e6d351a6d63ef4e5455e54edf8f6c233ea6c714db7b18bc0a4e65b4840528dd5be3b89a9e7f3a8a03547bc41a7954a4ff3d69c6209f17d800def3dffdad31c02d7aa67841d8ca0d6f239f170");
        if (!encoded || encoded->wire!=vector) return 1;
        if (s::decode_response_prefix(k,r,std::span{vector}.first(2*size+26),42).error()!=s::ResponseError::short_read) return 2;
        if (s::decode_response_prefix(k,r,vector,73).error()!=s::ResponseError::invalid_header) return 3;
        request[0]^=1; if (s::decode_response_prefix(k,r,vector,42).error()!=s::ResponseError::invalid_header) return 4; request[0]^=1;
        auto bad=vector; bad[size]^=1; if (s::decode_response_prefix(k,r,bad,42).error()!=s::ResponseError::authentication) return 5;
        auto prefix=s::decode_response_prefix(k,r,vector,42);
        if (!prefix || prefix->consumed!=2*size+27 || prefix->payload_length!=3) return 6;
        auto decoded=s::decode_response_payload(std::move(*prefix),std::span{vector}.subspan(2*size+27));
        if (!decoded || !std::ranges::equal(decoded->payload,payload)) return 7;
        s::FrameEncoder writer(std::move(encoded->cipher)); s::FrameDecoder reader(std::move(decoded->cipher));
        auto next=writer.encode(payload); if (!next) return 8;
        auto step=reader.feed(*next); if (!step || !step->payload || !std::ranges::equal(*step->payload,payload) || !reader.finish()) return 8;
        prefix=s::decode_response_prefix(k,r,vector,42); bad=vector; bad.back()^=1;
        if (s::decode_response_payload(std::move(*prefix),std::span{bad}.subspan(2*size+27)).error()!=s::ResponseError::authentication) return 9;
        if (s::encode_response(k,s,r,42,{}).error()!=s::ResponseError::invalid_payload) return 10;
        std::vector<std::uint8_t> large(65535,0x42); auto max=s::encode_response(k,s,r,42,large);
        if (!max) return 11; auto p=s::decode_response_prefix(k,r,max->wire,42);
        if (!p || s::decode_response_payload(std::move(*p),std::span{max->wire}.subspan(2*size+27))->payload!=large) return 12;
        large.push_back(0); if (s::encode_response(k,s,r,42,large).error()!=s::ResponseError::invalid_payload) return 13;
        auto zkey=s::SessionKey::derive(k,s); auto zhdr=s::make_fixed_header(true,42,0,r); auto zcipher=s::ChunkCipher::create(std::move(*zkey),true);
        auto zf=zcipher->process(*zhdr); auto zs=zcipher->process(std::span<std::uint8_t const>{});
        std::vector<std::uint8_t> zwire(s.begin(),s.end()); zwire.insert(zwire.end(),zf->begin(),zf->end()); zwire.insert(zwire.end(),zs->begin(),zs->end());
        auto zp=s::decode_response_prefix(k,r,zwire,42); if (!zp || zp->consumed!=2*size+27 || zp->payload_length!=0) return 14;
        auto zd=s::decode_response_payload(std::move(*zp),std::span{zwire}.subspan(2*size+27));
        if (!zd || !zd->payload.empty()) return 15;
        s::FrameEncoder zw(std::move(*zcipher)); s::FrameDecoder zr(std::move(zd->cipher));
        auto znext=zw.encode(payload); if (!znext) return 16;
        auto zstep=zr.feed(*znext);
        if (!zstep || !zstep->payload || !std::ranges::equal(*zstep->payload,payload)) return 17;
    }
    std::cout << "Shadowsocks 2022 response vectors passed\n";
}
