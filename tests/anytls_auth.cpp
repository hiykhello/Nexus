import std;
import anytls;
import anytls.auth;
import anytls.padding;

auto main() -> int {
    using namespace anytls;
    constexpr std::string_view password="password",expected="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
    auto secret=PasswordKey::from_password({reinterpret_cast<std::uint8_t const*>(password.data()),password.size()});
    if (!secret) return 1;
    constexpr std::string_view hex="0123456789abcdef";
    std::string encoded;
    for (auto byte:secret->view()) { encoded.push_back(hex[byte>>4]); encoded.push_back(hex[byte&15]); }
    if (encoded!=expected) return 2;
    auto other=PasswordKey::from_password(std::array<std::uint8_t,1>{'x'});
    if (!other) return 3;
    std::vector<PasswordKey> keys;
    keys.push_back(std::move(*secret)); keys.push_back(std::move(*other));
    if (authenticate(keys,keys[0].view())!=0 || authenticate(keys,keys[1].view())!=1 ||
        std::ranges::any_of(secret->view(),[](auto byte) { return byte!=0; })) return 4;
    Key invalid{};
    if (authenticate(keys,invalid) || authenticate(keys,std::span(invalid).first(31)) ||
        PasswordKey::from_password({}) || PasswordKey::from_password(std::vector<std::uint8_t>(4097,'a'))) return 5;
    auto scheme=PaddingScheme::parse(default_padding_scheme);
    if (!scheme) return 6;
    auto fingerprint=padding_fingerprint(*scheme);
    if (!fingerprint || *fingerprint!="75cff2ad89aadf5e257059ee571ebe11") return 7;
    if (random_padding({false,30,30})!=30 || random_padding({true}) || random_padding({false,0,10})) return 8;
    for (int i=0;i<64;++i) {
        auto length=random_padding({false,100,400});
        if (!length || *length<100 || *length>=400) return 9;
    }
    std::println("AnyTLS SHA-256 authentication, move erasure, MD5 compatibility fingerprint and system entropy padding passed");
}
