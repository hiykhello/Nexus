import std;
import nexus.thirdparty.blake3;

int main() {
    constexpr std::string_view context="BLAKE3 2019-12-27 16:29:52 test vectors context";
    constexpr std::array vectors{
        std::pair<std::size_t,std::string_view>{0,"2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"},
        std::pair<std::size_t,std::string_view>{1,"b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c"},
        std::pair<std::size_t,std::string_view>{64,"a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e"},
        std::pair<std::size_t,std::string_view>{1023,"74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea5"},
        std::pair<std::size_t,std::string_view>{1024,"7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706"},
        std::pair<std::size_t,std::string_view>{1025,"effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb"},
        std::pair<std::size_t,std::string_view>{2048,"7b2945cb4fef70885cc5d78a87bf6f6207dd901ff239201351ffac04e1088a23"},
        std::pair<std::size_t,std::string_view>{2049,"2ea477c5515cc3dd606512ee72bb3e0e758cfae7232826f35fb98ca1bcbdf273"},
        std::pair<std::size_t,std::string_view>{8192,"ad01d7ae4ad059b0d33baa3c01319dcf8088094d0359e5fd45d6aeaa8b2d0c3d"},
    };
    constexpr char hex[]="0123456789abcdef";
    if (std::string_view(nex::blake3::blake3_version())!="1.8.4") return 1;
    for (auto [size,expected] : vectors) {
        std::vector<std::uint8_t> input(size);
        for (std::size_t i=0;i<size;++i) input[i]=static_cast<std::uint8_t>(i%251);
        nex::blake3::blake3_hasher hasher{};
        nex::blake3::blake3_hasher_init_derive_key_raw(&hasher,context.data(),context.size());
        for (std::size_t offset=0;offset<input.size();) {
            auto count=std::min(std::size_t{37},input.size()-offset);
            nex::blake3::blake3_hasher_update(&hasher,input.data()+offset,count); offset+=count;
        }
        std::array<unsigned char,32> output{};
        nex::blake3::blake3_hasher_finalize(&hasher,output.data(),output.size());
        std::string actual;
        for (auto byte:output) { actual+=hex[byte>>4]; actual+=hex[byte&15]; }
        if (actual!=expected) return 2;
    }
    std::cout << "BLAKE3 derive-key official vectors passed\n";
}
