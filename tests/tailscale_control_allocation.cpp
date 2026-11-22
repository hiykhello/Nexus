import std;
import tailscale.control;
import crypto;
namespace t=tailscale::control;
using namespace std::chrono_literals;
namespace {
    std::atomic<std::size_t> allocations=0;
    auto allocate(std::size_t size,std::size_t alignment=0) -> void* {
        ++allocations;size=std::max(std::size_t{1},size);
        if (alignment && size>std::numeric_limits<std::size_t>::max()-(alignment-1)) throw std::bad_alloc();
        auto result=alignment ? std::aligned_alloc(alignment,((size+alignment-1)/alignment)*alignment) : std::malloc(size);
        if (!result) throw std::bad_alloc();return result;
    }
    template<class Key> auto key(unsigned seed) -> std::expected<Key,::crypto::Error> {
        t::KeyBytes bytes{};for (unsigned i=0;i<32;++i) bytes[i]=static_cast<std::uint8_t>(i+seed);
        auto result=Key::from_bytes(bytes);::crypto::cleanse(bytes);return result;
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
    auto machine=key<t::MachinePrivate>(3);auto control=key<t::ControlPrivate>(71);
    if (!machine || !control) return 1;auto pin=control->public_key();if (!pin) return 2;
    std::array<std::uint8_t,t::max_record_plaintext> plain{},opened{};
    std::array<std::uint8_t,t::max_record_wire> wire{};
    for (std::size_t i=0;i<plain.size();++i) plain[i]=static_cast<std::uint8_t>(i*17);
    auto before=allocations.load();
    for (std::uint16_t version:{1,148,65535}) {
        auto start=t::Clock::time_point{}+1s,deadline=start+5s;
        auto ce=key<t::EphemeralPrivate>(141);auto se=key<t::EphemeralPrivate>(211);if (!ce || !se) return 3;
        t::ClientHandshake client(*machine,*pin,version,start,deadline);t::ServerHandshake server(*control,start,deadline);
        auto initial=client.start(std::move(*ce),start);if (!initial) return 4;
        auto response=server.respond(*initial,std::move(*se),start);if (!response || !client.finish(*response,start)) return 5;
        auto ck=client.take_transport();auto sk=server.take_transport();if (!ck || !sk) return 6;
        t::TransportKeys moved(std::move(*ck));t::Records c,s;
        if (!c.install(std::move(moved)) || !s.install(std::move(*sk))) return 7;
        for (std::size_t size:{0,1,17,33,4077}) {
            auto input=std::span(plain).first(size);auto clear=std::span(opened).first(size);
            auto encrypted=c.seal_to(wire,input);if (!encrypted) return 8;
            t::RecordDecoder decoder;auto fed=decoder.feed(std::span(wire).first(*encrypted));
            if (!fed || *fed!=*encrypted || !decoder.ready()) return 9;
            auto decrypted=s.open_to(clear,decoder.wire());
            if (!decrypted || *decrypted!=size || !std::ranges::equal(clear,input) || !c.sent() || !decoder.consume()) return 10;
        }
        auto encrypted=c.seal_to(wire,std::span(plain).first(17));if (!encrypted) return 11;wire[*encrypted-1]^=1;
        auto rejected=s.open_to(std::span(opened).first(17),std::span(wire).first(*encrypted));
        if (rejected || rejected.error()!=t::Error::authentication) return 12;
        c.fail_send();client.cancel();server.cancel();
    }
    if (allocations.load()!=before) return 13;
    std::println("Control typed key/Noise construction, one-shot install, record/decoder and failure paths use zero ordinary/aligned C++ allocations");
    std::println("sizeof(ClientHandshake)={} ServerHandshake={} Records={} RecordDecoder={} TransportKeys={}",sizeof(t::ClientHandshake),sizeof(t::ServerHandshake),sizeof(t::Records),sizeof(t::RecordDecoder),sizeof(t::TransportKeys));
}
