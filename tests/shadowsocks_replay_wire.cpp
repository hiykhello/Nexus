import std;
import shadowsocks.request;
auto main(int argc,char** argv) -> int {
    if (argc!=3 && argc!=4) return 1;
    auto size=std::stoul(argv[1]),port=std::stoul(argv[2]); if ((size!=16 && size!=32) || !port || port>65535) return 2;
    auto offset=argc==4 ? std::stoul(argv[3]) : 40;
    if (offset>223) return 2;
    std::array<std::uint8_t,32> key{},salt{};
    for (std::size_t i=0;i<size;++i) { key[i]=static_cast<std::uint8_t>(i); salt[i]=static_cast<std::uint8_t>(i+offset); }
    std::array<std::uint8_t,7> address{1,127,0,0,1,static_cast<std::uint8_t>(port>>8),static_cast<std::uint8_t>(port)};
    std::array<std::uint8_t,1> padding{0};
    auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto result=shadowsocks::encode_request(std::span{key}.first(size),std::span{salt}.first(size),now,address,padding,{});
    if (!result) return 3;
    std::cout.write(reinterpret_cast<char const*>(result->wire.data()),result->wire.size());
}
