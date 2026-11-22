import std;
import tailscale.control_early;
import tailscale.control_http;
std::size_t ordinary=0,aligned=0;
auto operator new(std::size_t size) -> void* {++ordinary;if (auto p=std::malloc(size ? size : 1)) return p;throw std::bad_alloc();}
auto operator new[](std::size_t size) -> void* {return ::operator new(size);}
auto operator delete(void* p) noexcept -> void {std::free(p);}
auto operator delete[](void* p) noexcept -> void {std::free(p);}
auto operator delete(void* p,std::size_t) noexcept -> void {std::free(p);}
auto operator delete[](void* p,std::size_t) noexcept -> void {std::free(p);}
auto operator new(std::size_t size,std::align_val_t alignment) -> void* {++aligned;auto align=static_cast<std::size_t>(alignment);auto n=std::max(size,std::size_t{1});n=(n+align-1)/align*align;if (auto p=std::aligned_alloc(align,n)) return p;throw std::bad_alloc();}
auto operator new[](std::size_t size,std::align_val_t alignment) -> void* {return ::operator new(size,alignment);}
auto operator delete(void* p,std::align_val_t) noexcept -> void {std::free(p);}
auto operator delete[](void* p,std::align_val_t) noexcept -> void {std::free(p);}
auto operator delete(void* p,std::size_t,std::align_val_t) noexcept -> void {std::free(p);}
auto operator delete[](void* p,std::size_t,std::align_val_t) noexcept -> void {std::free(p);}
namespace early=tailscale::control_early;
auto parse(std::string_view text) {return early::parse({reinterpret_cast<std::uint8_t const*>(text.data()),text.size()});}
auto main(int argc,char** argv) -> int {
    if (argc==2 && std::string_view(argv[1])=="--check") {
        std::string line;unsigned count=0;while (std::getline(std::cin,line)) {auto value=parse(line);if (!value || !value->present) return 20;++count;}
        if (count!=2) return 21;std::println("official EarlyNoise differential passed: {} vectors",count);return 0;
    }
    std::string zero="{\"nodeKeyChallenge\":\"chalpub:"+std::string(64,'0')+"\"}";
    auto value=parse(zero);if (!value || !value->present || std::ranges::any_of(value->challenge.view(),[](auto b) {return b!=0;})) return 1;
    auto nonzero=zero;auto position=nonzero.find("chalpub:")+std::string_view("chalpub:").size();nonzero[position]='f';value=parse(nonzero);if (!value || value->challenge.view()[0]!=0xf0) return 2;
    value=parse("{}  ");if (!value || value->present) return 3;
    for (std::string_view text:{"", "null", "[]", "{\"nodeKeyChallenge\":null}", "{\"nodeKeyChallenge\":2}", "{\"nodeKeyChallenge\":true}",
        "{\"nodeKeyChallenge\":{}}", "{\"future\":\"value\"}","{\"nodeKeyChallenge\":\"nodekey:00\"}","{}x", "{\"nodeKeyChallenge\":\"chalpub:\\u0030\"}"}) if (parse(text)) return 4;
    auto duplicate=zero;duplicate.pop_back();duplicate+=","+zero.substr(1);if (parse(duplicate)) return 5;
    auto escaped=zero;escaped.replace(escaped.find("nodeKeyChallenge"),1,"\\u006e");if (parse(escaped)) return 6;
    auto wrong=zero;wrong[position]='g';if (parse(wrong)) return 7;
    auto exact=zero;exact.append(tailscale::control_http::max_early_payload-exact.size(),' ');if (!parse(exact)) return 8;exact+=' ';if (parse(exact)) return 9;
    auto old_ordinary=ordinary,old_aligned=aligned;
    for (unsigned i=0;i<100;++i) {if (!parse(zero) || !parse("{}")) return 10;}
    auto used_ordinary=ordinary-old_ordinary,used_aligned=aligned-old_aligned;if (used_ordinary || used_aligned) return 11;
    std::println("typed early100 ordinary={} aligned={}",used_ordinary,used_aligned);
    std::println("typed early schema/key roles/zero/missing/unknown/duplicate/escaped/type/64KiB boundaries passed");
    std::println("sizeof typed-early={}",sizeof(early::Info));
}
