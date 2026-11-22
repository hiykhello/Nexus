import std;
import crypto;
import crypto.aead_context;
namespace c = ::crypto;
namespace {
    std::atomic<std::size_t> allocations{0};
    auto allocate(std::size_t size,std::size_t alignment=0) -> void* {
        ++allocations;
        size=std::max<std::size_t>(size,1);
        auto* result=alignment ? std::aligned_alloc(alignment,((size+alignment-1)/alignment)*alignment) : std::malloc(size);
        if (!result) throw std::bad_alloc(); return result;
    }
}
auto operator new(std::size_t size) -> void* { return allocate(size); }
auto operator new[](std::size_t size) -> void* { return allocate(size); }
auto operator new(std::size_t size,std::align_val_t alignment) -> void* { return allocate(size,static_cast<std::size_t>(alignment)); }
auto operator new[](std::size_t size,std::align_val_t alignment) -> void* { return allocate(size,static_cast<std::size_t>(alignment)); }
auto operator delete(void* pointer) noexcept -> void { std::free(pointer); }
auto operator delete[](void* pointer) noexcept -> void { std::free(pointer); }
auto operator delete(void* pointer,std::size_t) noexcept -> void { std::free(pointer); }
auto operator delete[](void* pointer,std::size_t) noexcept -> void { std::free(pointer); }
auto operator delete(void* pointer,std::align_val_t) noexcept -> void { std::free(pointer); }
auto operator delete[](void* pointer,std::align_val_t) noexcept -> void { std::free(pointer); }
auto operator delete(void* pointer,std::size_t,std::align_val_t) noexcept -> void { std::free(pointer); }
auto operator delete[](void* pointer,std::size_t,std::align_val_t) noexcept -> void { std::free(pointer); }
auto main() -> int {
    static_assert(!std::is_copy_constructible_v<c::AeadContext> && !std::is_move_constructible_v<c::AeadContext>);
    c::AeadContext context;
    std::array<std::uint8_t,32> key{};
    std::array<std::uint8_t,24> nonce{};
    std::array<std::uint8_t,17> aad{};
    std::array<std::uint8_t,4096> plaintext{};
    std::array<std::uint8_t,4112> encrypted{},opened{},inplace{};
    if (context.valid() || context.seal_to(encrypted,nonce,{}).error()!=c::Error::invalid_state) return 1;
    for (auto algorithm:{c::Aead::aes_128_gcm,c::Aead::aes_256_gcm,c::Aead::chacha20_poly1305,c::Aead::xchacha20_poly1305}) {
        auto k=std::span(key).first(algorithm==c::Aead::aes_128_gcm ? 16 : 32);
        auto n=std::span(nonce).first(algorithm==c::Aead::xchacha20_poly1305 ? 24 : 12);
        for (std::size_t i=0;i<key.size();++i) key[i]=static_cast<std::uint8_t>(i*13+3);
        for (std::size_t i=0;i<plaintext.size();++i) plaintext[i]=static_cast<std::uint8_t>(i*71);
        auto before=allocations.load();
        if (!context.reset(algorithm,k) || !context.valid() || allocations!=before) return 2;
        for (std::size_t size:{0,1,15,16,17,63,64,65,4096}) {
            auto input=std::span(plaintext).first(size);
            auto reference=c::seal(algorithm,k,n,input,aad);
            if (!reference) return 3;
            before=allocations.load();
            auto sealed=context.seal_to(encrypted,n,input,aad);
            if (!sealed || *sealed!=size+16 || !std::ranges::equal(std::span(encrypted).first(*sealed),*reference)) return 4;
            opened.fill(0xa5);
            auto output=context.open_to(std::span(opened).first(size),n,std::span(encrypted).first(*sealed),aad);
            if (!output || *output!=size || !std::ranges::equal(std::span(opened).first(size),input) || opened[size]!=0xa5) return 5;
            std::copy_n(input.begin(),size,inplace.begin());
            auto aliased=context.seal_to(std::span(inplace).first(size+16),n,std::span(inplace).first(size),aad);
            if (!aliased || !std::ranges::equal(std::span(inplace).first(*aliased),*reference)) return 6;
            auto recovered=context.open_to(std::span(inplace).first(size),n,std::span(inplace).first(*aliased),aad);
            if (!recovered || *recovered!=size || !std::ranges::equal(std::span(inplace).first(size),input)) return 7;
            encrypted[*sealed-1]^=1; opened.fill(0xa5);
            auto rejected=context.open_to(std::span(opened).first(size),n,std::span(encrypted).first(*sealed),aad);
            if (rejected || rejected.error()!=c::Error::authentication_failed || opened[size]!=0xa5 ||
                !std::ranges::all_of(std::span(opened).first(size),[](auto value) { return value==0; })) return 8;
            encrypted[*sealed-1]^=1;
            if (!context.open_to(opened,n,std::span(encrypted).first(*sealed),aad) || allocations!=before) return 9;
        }
        encrypted.fill(0xa5);
        if (context.seal_to(encrypted,n.first(n.size()-1),{}).error()!=c::Error::invalid_nonce ||
            context.seal_to(std::span(encrypted).first(15),n,{}).error()!=c::Error::invalid_length ||
            context.seal_to(std::span(encrypted).subspan(1),n,std::span(encrypted).first(32)).error()!=c::Error::invalid_length ||
            context.seal_to(encrypted,n,{},std::span(encrypted).first(1)).error()!=c::Error::invalid_length ||
            !std::ranges::all_of(encrypted,[](auto value) { return value==0xa5; })) return 10;
        if (context.reset(algorithm,{}).error()!=c::Error::invalid_key || !context.valid() ||
            context.reset(static_cast<c::Aead>(255),k).error()!=c::Error::unsupported_algorithm || !context.valid()) return 11;
        before=allocations.load();
        for (unsigned i=0;i<1000;++i) {
            n.back()=static_cast<std::uint8_t>(i);
            auto sealed=context.seal_to(encrypted,n,plaintext,aad);
            if (!sealed || !context.open_to(opened,n,std::span(encrypted).first(*sealed),aad)) return 12;
        }
        if (allocations!=before) return 13;
        context.clear();
        if (context.valid() || context.open_to(opened,n,encrypted).error()!=c::Error::invalid_state) return 14;
        context.clear();
    }
    std::cout<<"AEAD direct state/caller buffers, same-start aliases, failure cleanup and zero C++ allocations passed; sizeof="<<sizeof(context)<<'\n';
}
