import std;
import wireguard.blake2s;

namespace {
    auto hex(std::span<std::uint8_t const> bytes) -> std::string {
        constexpr std::string_view alphabet="0123456789abcdef";
        std::string result; result.reserve(bytes.size()*2);
        for (auto byte:bytes) { result.push_back(alphabet[byte>>4]); result.push_back(alphabet[byte&15]); }
        return result;
    }
    template<std::size_t N>
    auto check(std::span<std::uint8_t const> input,std::span<std::uint8_t const> key,std::string_view expected) -> bool {
        using namespace wireguard::blake2s;
        auto result=digest<N>(input,key);
        if (!result || hex(*result)!=expected) return false;
        std::array<std::uint8_t,N> direct{};
        if (!digest_to(std::span(direct),input,key) || direct!=*result ||
            !digest_parts_to(std::span(direct),{input.first(input.size()/2),input.subspan(input.size()/2)},key) || direct!=*result) return false;
        for (auto chunk:{1u,2u,31u,63u,64u,65u,127u}) {
            auto state=State<N>::keyed(key); if (!state) return false;
            for (std::size_t offset=0;offset<input.size();) {
                auto count=std::min(std::size_t{chunk},input.size()-offset);
                if (!state->update(input.subspan(offset,count)) || !state->update({})) return false;
                offset+=count;
            }
            auto moved=std::move(*state);
            if (state->update({}) || state->finish()) return false;
            auto incremental=moved.finish();
            if (!incremental || *incremental!=*result || moved.update({}) || moved.finish()) return false;
            auto output=State<N>::keyed(key);
            if (!output || !output->update(input) || !output->finish_to(direct) || direct!=*result || output->finish_to(direct)) return false;
        }
        return true;
    }
}

auto main() -> int {
    using namespace wireguard::blake2s;
    struct Vector { std::size_t size,length; bool keyed; std::string_view expected; };
    // hashlib.blake2s reference values, including keyed empty and final blocks.
    constexpr std::array vectors{
        Vector{16,0,false,"64550d6ffe2c0a01a14aba1eade0200c"},
        Vector{16,0,true,"9536f9b267655743dee97b8a670f9f53"},
        Vector{16,1,false,"9f31f3ec588c6064a8e1f9051aeab90a"},
        Vector{16,1,true,"13bacfb85b48a1223c595f8c1e7e82cb"},
        Vector{16,63,false,"4006430a2d313751a9ece24fccb52de5"},
        Vector{16,63,true,"ece382a8bd5018f1de5da44b72cea75b"},
        Vector{16,64,false,"dc66ca8f03865801b0ffe06ed8a1a90e"},
        Vector{16,64,true,"f1efa90d2547036841ecd3627fafbc36"},
        Vector{16,65,false,"399d3e92ccfcedcdde9bf4c2be14cf8c"},
        Vector{16,65,true,"811ff8686d23a435ecbd0bdafcd27b1b"},
        Vector{16,255,false,"b504e782a6ba7a75eca305c265cf3633"},
        Vector{16,255,true,"cd075928ab7e6883e697fe7fd3ac43ee"},
        Vector{16,1024,false,"50dd8cb7e196b8030f7aaba8f6107aba"},
        Vector{16,1024,true,"df2d406b98b634d8f6e143858658aee7"},
        Vector{32,0,false,"69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"},
        Vector{32,0,true,"48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49"},
        Vector{32,1,false,"e34d74dbaf4ff4c6abd871cc220451d2ea2648846c7757fbaac82fe51ad64bea"},
        Vector{32,1,true,"40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1"},
        Vector{32,63,false,"e57cb79487dd57902432b250733813bd96a84efce59f650fac26e6696aefafc3"},
        Vector{32,63,true,"c65382513f07460da39833cb666c5ed82e61b9e998f4b0c4287cee56c3cc9bcd"},
        Vector{32,64,false,"56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e"},
        Vector{32,64,true,"8975b0577fd35566d750b362b0897a26c399136df07bababbde6203ff2954ed4"},
        Vector{32,65,false,"1b53ee94aaf34e4b159d48de352c7f0661d0a40edff95a0b1639b4090e974472"},
        Vector{32,65,true,"21fe0ceb0052be7fb0f004187cacd7de67fa6eb0938d927677f2398c132317a8"},
        Vector{32,255,false,"f03f5789d3336b80d002d59fdf918bdb775b00956ed5528e86aa994acb38fe2d"},
        Vector{32,255,true,"3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd"},
        Vector{32,1024,false,"a049455add68f38d48845e25a52ba3100c4d0899178c202aec07364fecacf650"},
        Vector{32,1024,true,"9ad228e0f38ae8e2f5ab6b1c668d6cd863e3e27244e6d52d4f14e3038aecf426"},
    };
    std::array<std::uint8_t,32> key; std::iota(key.begin(),key.end(),0);
    for (auto const& vector:vectors) {
        std::vector<std::uint8_t> input(vector.length);
        for (std::size_t i=0;i<input.size();++i) input[i]=static_cast<std::uint8_t>(i);
        auto selected=vector.keyed ? std::span<std::uint8_t const>(key) : std::span<std::uint8_t const>{};
        if (!(vector.size==16 ? check<16>(input,selected,vector.expected) : check<32>(input,selected,vector.expected))) return 1;
    }
    constexpr std::string_view text="abc";
    auto abc=digest(std::span(reinterpret_cast<std::uint8_t const*>(text.data()),text.size()));
    if (!abc || hex(*abc)!="508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982") return 2;
    auto one=digest<1>({});
    if (!one || (*one)[0]!=0xa1 || digest({},std::vector<std::uint8_t>(33)) || State<16>::keyed(std::vector<std::uint8_t>(33))) return 3;
    std::array<std::uint8_t,128> long_key; std::iota(long_key.begin(),long_key.end(),0);
    std::array<std::uint8_t,255> message; std::iota(message.begin(),message.end(),0);
    auto mac=hmac(long_key,{std::span(message).first(63),std::span(message).subspan(63)});
    if (!mac || hex(*mac)!="6c26f4d084cd946e34d8cf8e30d1ba522577f16440319e81e5c635932f266cbc") return 4;
    std::array<std::uint8_t,32> direct;
    if (!hmac_to(direct,long_key,{message}) || direct!=*mac) return 5;
    auto alias=key;
    auto expected=digest(message,key);
    if (!expected || !digest_to(std::span(alias),message,alias) || alias!=*expected) return 6;
    auto long_alias=long_key;
    if (!hmac_to(std::span(long_alias).first<32>(),long_alias,{message}) || !std::ranges::equal(std::span(long_alias).first<32>(),*mac)) return 7;
    std::ranges::fill(direct,173);
    if (digest_to(std::span(direct),{},std::vector<std::uint8_t>(33)) || std::ranges::any_of(direct,[](auto byte) { return byte!=173; })) return 8;
    std::println("BLAKE2s RFC/hashlib keyed/unkeyed vectors, incremental blocks, moved/closed states and HMAC passed");
}
