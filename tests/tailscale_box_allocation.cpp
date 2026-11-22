import std;
import tailscale.box;
namespace b=tailscale::box;
namespace {
    std::atomic<std::size_t> allocations=0;
    auto allocate(std::size_t size,std::size_t alignment=0) -> void* {
        ++allocations;
        size=std::max(std::size_t{1},size);
        if (alignment && size>std::numeric_limits<std::size_t>::max()-(alignment-1)) throw std::bad_alloc();
        auto result=alignment ? std::aligned_alloc(alignment,((size+alignment-1)/alignment)*alignment) : std::malloc(size);
        if (!result) throw std::bad_alloc();
        return result;
    }
}
auto operator new(std::size_t size) -> void* {return allocate(size);}
auto operator new[](std::size_t size) -> void* {return allocate(size);}
auto operator new(std::size_t size,std::align_val_t alignment) -> void* {return allocate(size,static_cast<std::size_t>(alignment));}
auto operator new[](std::size_t size,std::align_val_t alignment) -> void* {return allocate(size,static_cast<std::size_t>(alignment));}
auto operator delete(void* pointer) noexcept -> void {std::free(pointer);}
auto operator delete[](void* pointer) noexcept -> void {std::free(pointer);}
auto operator delete(void* pointer,std::size_t) noexcept -> void {std::free(pointer);}
auto operator delete[](void* pointer,std::size_t) noexcept -> void {std::free(pointer);}
auto operator delete(void* pointer,std::align_val_t) noexcept -> void {std::free(pointer);}
auto operator delete[](void* pointer,std::align_val_t) noexcept -> void {std::free(pointer);}
auto operator delete(void* pointer,std::size_t,std::align_val_t) noexcept -> void {std::free(pointer);}
auto operator delete[](void* pointer,std::size_t,std::align_val_t) noexcept -> void {std::free(pointer);}
auto main() -> int {
    std::vector<std::uint8_t> plain(b::max_message_size),sealed(plain.size()+16),opened(plain.size());
    for (std::size_t i=0;i<plain.size();++i) plain[i]=static_cast<std::uint8_t>(i);
    std::array<std::uint8_t,32> raw{};std::array<std::uint8_t,24> nonce{};
    for (unsigned i=0;i<raw.size();++i) raw[i]=static_cast<std::uint8_t>(i);
    auto before=allocations.load();
    {
        auto created=b::SharedKey::from_secretbox_key(raw);if (!created) return 1;
        auto key=std::move(*created);if (created->valid() || !key.valid()) return 2;
        for (std::size_t size:{0u,1u,31u,32u,33u,63u,64u,65u,1024u,1048576u}) {
            nonce[0]=static_cast<std::uint8_t>(size);nonce[1]=static_cast<std::uint8_t>(size>>8);nonce[2]=static_cast<std::uint8_t>(size>>16);
            auto input=std::span(plain).first(size),output=std::span(sealed).first(size+16),clear=std::span(opened).first(size);
            auto encrypted=key.seal_to(output,nonce,input);
            if (!encrypted || *encrypted!=size+16) return 3;
            auto decrypted=key.open_to(clear,nonce,output);
            if (!decrypted || *decrypted!=size || !std::ranges::equal(clear,input)) return 4;
            auto previous=clear.empty() ? 0 : clear[0];output[0]^=1;
            if (key.open_to(clear,nonce,output).error()!=b::Error::authentication || (!clear.empty() && clear[0]!=previous)) return 5;
        }
        key.clear();if (key.valid()) return 6;
    }
    if (allocations.load()!=before) return 7;
    std::println("NaCl caller-span secretbox construct/move/clear, seal/open and bad-tag paths use zero ordinary/aligned C++ allocations");
    std::cout<<"sizeof(SharedKey)="<<sizeof(b::SharedKey)<<'\n';
}

