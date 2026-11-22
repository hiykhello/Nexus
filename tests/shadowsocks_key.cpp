import std;
import shadowsocks.key;
namespace s=shadowsocks;
int main() {
    constexpr std::array<std::uint8_t,16> expected16{0xbc,0x32,0xfb,0x8d,0x52,0x05,0xf7,0xb8,0x4f,0x96,0x91,0xdf,0xb9,0xf0,0x4f,0xf3};
    constexpr std::array<std::uint8_t,32> expected32{0x37,0x4f,0xca,0x03,0xe4,0xda,0xe7,0xf9,0x98,0xfd,0x7e,0x59,0xc1,0xed,0xfc,0xc8,0xe3,0x19,0x7f,0x4d,0xb1,0xc1,0x9c,0xa1,0x67,0x1b,0xe3,0xb6,0x6a,0x92,0xdd,0xda};
    constexpr std::array<std::uint8_t,16> udp16{0xbb,0x10,0xb7,0x65,0x26,0x9a,0x37,0xfd,0x03,0xbb,0x0f,0x41,0x7b,0xf9,0x8e,0x9d};
    constexpr std::array<std::uint8_t,32> udp32{0x96,0x39,0x7d,0x42,0x24,0xf3,0xab,0x46,0xbe,0x00,0x31,0xb7,0xd8,0x20,0xb3,0xc0,0x59,0x5c,0xc5,0xbb,0xca,0x63,0xe4,0x1e,0x1f,0xa1,0x32,0x61,0xde,0xc8,0x88,0x23};
    constexpr std::array<std::uint8_t,8> session{0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7};
    for (std::size_t size:{16u,32u}) {
        std::array<std::uint8_t,32> key{},salt{};
        for (std::size_t i=0;i<size;++i) { key[i]=static_cast<std::uint8_t>(i); salt[i]=static_cast<std::uint8_t>(i+size); }
        auto derived=s::SessionKey::derive(std::span{key}.first(size),std::span{salt}.first(size));
        auto expected=size==16 ? std::span<std::uint8_t const>{expected16} : std::span<std::uint8_t const>{expected32};
        if (!derived || !std::ranges::equal(derived->view(),expected)) return 1;
        auto udp=s::SessionKey::derive_udp(std::span{key}.first(size),session);
        auto udp_expected=size==16 ? std::span<std::uint8_t const>{udp16} : std::span<std::uint8_t const>{udp32};
        if (!udp || !std::ranges::equal(udp->view(),udp_expected)) return 5;
        auto moved=std::move(*derived); if (!derived->view().empty() || !std::ranges::equal(moved.view(),expected)) return 2;
        if (s::SessionKey::derive(std::span{key}.first(size),std::span{salt}.first(size-1))) return 3;
    }
    std::array<std::uint8_t,15> invalid{};
    if (s::SessionKey::derive(invalid,invalid) || s::SessionKey::derive_udp(invalid,session)) return 4;
    std::cout << "Shadowsocks 2022 session key vectors passed\n";
}
