import std;
import crypto;

namespace c = ::crypto;
template<std::size_t Size>
auto hex(std::string_view input) -> std::array<std::uint8_t,Size> {
    if (input.size()!=Size*2) throw std::invalid_argument("hex length");
    auto digit=[](char value) -> unsigned { return value<='9' ? value-'0' : value-'a'+10; };
    std::array<std::uint8_t,Size> output;
    for (std::size_t i=0;i<Size;++i) output[i]=static_cast<std::uint8_t>((digit(input[2*i])<<4)|digit(input[2*i+1]));
    return output;
}
auto reference(std::span<std::uint8_t const> message,std::span<std::uint8_t const,32> key) -> std::array<std::uint8_t,16> {
    // Independent bitwise modular arithmetic in base 2^8, separate from the
    // selected backend's optimized polynomial multiplication.
    using Number=std::array<std::uint8_t,17>;
    Number r{},h{};
    std::copy_n(key.begin(),16,r.begin());
    for (auto i:{3,7,11,15}) r[i]&=15;
    for (auto i:{4,8,12}) r[i]&=252;
    auto add=[](Number const& left,Number const& right) -> Number {
        std::array<unsigned,17> sum{};
        unsigned carry=0;
        for (unsigned i=0;i<17;++i) { carry+=left[i]+right[i]; sum[i]=carry&255; carry>>=8; }
        // Both inputs are below p, so their sum is below 2^131. Fold the
        // bits at 2^130 using 2^130=5, retaining the final canonical range.
        while (sum[16]>=4) {
            auto high=sum[16]>>2; sum[16]&=3; sum[0]+=5*high;
            for (unsigned i=0;i<16;++i) { sum[i+1]+=sum[i]>>8; sum[i]&=255; }
        }
        bool subtract=sum[16]==3 && sum[0]>=251;
        for (unsigned i=1;i<16;++i) subtract&=sum[i]==255;
        if (subtract) { sum[0]-=251; for (unsigned i=1;i<16;++i) sum[i]-=255; sum[16]-=3; }
        Number result{};
        for (unsigned i=0;i<17;++i) result[i]=static_cast<std::uint8_t>(sum[i]);
        return result;
    };
    while (!message.empty()) {
        auto size=std::min<std::size_t>(message.size(),16);
        Number block{}; std::copy_n(message.begin(),size,block.begin()); block[size]=1;
        auto factor=add(h,block); Number product{};
        for (unsigned bit=0;bit<128;++bit) {
            if (r[bit/8]&(1u<<(bit%8))) product=add(product,factor);
            factor=add(factor,factor);
        }
        h=product; message=message.subspan(size);
    }
    std::array<std::uint8_t,16> tag{};
    unsigned carry=0;
    for (unsigned i=0;i<16;++i) { carry+=h[i]+key[i+16]; tag[i]=static_cast<std::uint8_t>(carry); carry>>=8; }
    return tag;
}
auto main() -> int {
    // RFC 8439 section 2.5.2 and empty-message s-only behavior.
    auto key=hex<32>("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    constexpr std::string_view input="Cryptographic Forum Research Group";
    auto message=std::span(reinterpret_cast<std::uint8_t const*>(input.data()),input.size());
    std::array<std::uint8_t,16> tag{};
    c::poly1305_to(tag,key,message);
    if (tag!=hex<16>("a8061dc1305136c6c22b8baf0c0127a9") || tag!=reference(message,key)) return 1;
    c::poly1305_to(tag,key,{});
    if (!std::ranges::equal(tag,std::span(key).subspan(16))) return 2;
    for (std::size_t size:{0,1,15,16,17,31,32,33,63,64,65,255,256,1024,4096}) {
        std::vector<std::uint8_t> bytes(size);
        for (std::size_t i=0;i<size;++i) bytes[i]=static_cast<std::uint8_t>(i*73+size);
        for (unsigned variant=0;variant<8;++variant) {
            for (unsigned i=0;i<32;++i) key[i]=static_cast<std::uint8_t>(i*17+variant*41);
            c::poly1305_to(tag,key,bytes);
            if (tag!=reference(bytes,key)) { std::cerr<<"Poly1305 size="<<size<<" variant="<<variant<<'\n'; return 3; }
        }
    }
    // Direct output may alias the consumed input or one-time key.
    auto expected=reference(message,key);
    c::poly1305_to(std::span(key).first<16>(),key,message);
    if (!std::ranges::equal(std::span(key).first<16>(),expected)) return 4;
    std::vector<std::uint8_t> alias(message.begin(),message.end());
    expected=reference(alias,key);
    c::poly1305_to(std::span(alias).first<16>(),key,alias);
    if (!std::ranges::equal(std::span(alias).first<16>(),expected)) return 5;
    std::println("Poly1305 RFC vector, independent arithmetic, block boundaries and direct-output aliases passed");
}
