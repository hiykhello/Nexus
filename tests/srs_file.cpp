#include <zlib.h>
import std;
import rules;
import rules.srs_file;

namespace {
    auto check(bool ok,std::string_view message) -> void {if(!ok){std::cerr<<message<<'\n';std::exit(1);}}
    auto read(char const* path) -> std::vector<std::uint8_t> {
        std::ifstream file(path,std::ios::binary);
        check(bool(file),"fixture unavailable");
        return {std::istreambuf_iterator<char>(file),{}};
    }
}
auto main(int argc,char** argv) -> int {
    using namespace ::rules;
    check(argc==4,"expected v1, v2 and unsupported v3 SRS fixtures");
    for(int i=1;i<3;++i) {
        auto bytes=read(argv[i]);auto rules=decode_srs_file(bytes);
        check(bool(rules),"SRS file rejected");auto matcher=Matcher::compile(*rules);check(bool(matcher),"matcher rejected");
        for(auto [name,expected]:std::array<std::pair<std::string_view,bool>,5>{{
            {"exact.test",true},{"root.test",true},{"x.root.test",true},{"only.test",false},{"x.only.test",true}}}) {
            auto result=matcher->match({.domain=name});check(result && bool(*result)==expected,"SRS domain mismatch");
        }
        auto truncated=bytes;truncated.pop_back();check(!decode_srs_file(truncated),"truncated stream accepted");
        auto trailing=bytes;trailing.push_back(0);check(!decode_srs_file(trailing),"trailing stream bytes accepted");
        auto invalid=bytes;invalid[3]=6;check(!decode_srs_file(invalid),"unsupported version accepted");
        invalid=bytes;invalid.back()^=1;check(!decode_srs_file(invalid),"invalid checksum accepted");
    }
    auto unsupported=decode_srs_file(read(argv[3]));
    check(!unsupported && unsupported.error().message.find("unsupported SRS condition")!=std::string::npos,
          "unsupported v3 condition was not rejected");
    std::vector<std::uint8_t> huge(max_input_bytes+1,0);
    uLongf compressed_size=compressBound(huge.size());std::vector<std::uint8_t> compressed(compressed_size+4);
    compressed[0]='S';compressed[1]='R';compressed[2]='S';compressed[3]=2;
    check(compress2(compressed.data()+4,&compressed_size,huge.data(),huge.size(),Z_BEST_COMPRESSION)==Z_OK,"fixture compression failed");
    compressed.resize(compressed_size+4);auto large=decode_srs_file(compressed);
    check(!large && large.error().code==ErrorCode::limit,"decompressed limit not enforced");
    std::cout<<"SRS v1/v2 files, truncation, checksum, trailing data and decompression limit passed\n";
}
