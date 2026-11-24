export module test.hy2_production_resource_link;
import std;
import hysteria2.credential;
import tls.server_credential;
import corosio;
export namespace test::hy2_production_resource {
struct Heap {
    static inline std::size_t at=0,calls=0,blocks=0;static inline bool denied=false;
    static auto arm(std::size_t point)noexcept->void{at=point;calls=0;denied=false;}
    static auto allocate(std::size_t bytes)noexcept->void*{++calls;if(at && calls==at){denied=true;at=0;return nullptr;}auto* p=std::malloc(bytes);if(p)++blocks;return p;}
    static auto release(void* p)noexcept->void{--blocks;std::free(p);}
};
inline bool cpp_denied=false;
auto phase(corosio::io_context&,tls::ServerCredential const&,std::span<std::uint8_t const>,hysteria2::Password const&,bool* clean=nullptr)->bool;
}
