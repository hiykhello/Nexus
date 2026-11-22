import std;
import quic.varint;
import quic.transport_parameters;

namespace q=quic;
namespace {
    bool measure=false,deny=false;
    std::size_t calls=0,requested=0,live=0;
    auto allocate(std::size_t size) -> void* {
        if (measure) { ++calls; requested+=size; if (deny) throw std::bad_alloc(); }
        auto* pointer=std::malloc(std::max<std::size_t>(size,1)); if (!pointer) throw std::bad_alloc();
        ++live; return pointer;
    }
    auto release(void* pointer) noexcept -> void { if (pointer) { --live; std::free(pointer); } }
}
auto operator new(std::size_t size) -> void* { return allocate(size); }
auto operator new[](std::size_t size) -> void* { return allocate(size); }
auto operator delete(void* pointer) noexcept -> void { release(pointer); }
auto operator delete[](void* pointer) noexcept -> void { release(pointer); }
auto operator delete(void* pointer,std::size_t) noexcept -> void { release(pointer); }
auto operator delete[](void* pointer,std::size_t) noexcept -> void { release(pointer); }
namespace {
    auto parameter(std::vector<std::uint8_t>& bytes,std::uint64_t id,std::span<std::uint8_t const> value={},std::size_t id_width=0,std::size_t length_width=0) -> void {
        std::array<std::uint8_t,8> encoded{};
        auto width=q::write_varint(encoded,id,id_width); if (!width) throw std::runtime_error("parameter ID");
        bytes.insert(bytes.end(),encoded.begin(),encoded.begin()+*width);
        width=q::write_varint(encoded,value.size(),length_width); if (!width) throw std::runtime_error("parameter length");
        bytes.insert(bytes.end(),encoded.begin(),encoded.begin()+*width); bytes.insert(bytes.end(),value.begin(),value.end());
    }
    auto verify(std::span<std::uint8_t const> bytes,std::optional<q::ParameterBlockError> expected,std::size_t allocations,std::size_t allocation_bytes,bool fail=false) -> bool {
        auto before=live; calls=requested=0; deny=fail; measure=true;
        auto result=q::validate_parameter_block(bytes);
        measure=deny=false;
        return result.has_value()==!expected.has_value() && (!expected || result.error()==*expected) && calls==allocations && requested==allocation_bytes && live==before;
    }
}
auto main() -> int {
    using E=q::ParameterBlockError;
    if (!verify({},std::nullopt,0,0)) return 1;
    std::vector<std::uint8_t> bytes;
    for (auto width:{1u,2u,4u,8u}) {
        bytes.clear(); parameter(bytes,27,std::array<std::uint8_t,3>{0,255,1},width,width);
        if (!verify(bytes,std::nullopt,0,0)) return 2;
    }
    bytes.clear();
    for (auto id:{std::uint64_t{0},std::uint64_t{63},std::uint64_t{64},std::uint64_t{16383},std::uint64_t{16384},q::max_varint}) parameter(bytes,id);
    if (!verify(bytes,std::nullopt,0,0)) return 3;
    parameter(bytes,27,{},8,8); parameter(bytes,27,{},1,1);
    if (!verify(bytes,E::duplicate,0,0)) return 4;
    bytes.clear(); parameter(bytes,q::max_varint,std::array<std::uint8_t,16>{},8,8);
    for (std::size_t size=1;size<bytes.size();++size) if (!verify(std::span(bytes).first(size),E::malformed,0,0)) return 5;
    if (!verify(bytes,std::nullopt,0,0)) return 6;
    bytes.assign(65536,0); if (!verify(bytes,E::malformed,0,0)) return 7;
    bytes.clear(); bytes.reserve(65535);
    for (unsigned id=0;id<64;++id) parameter(bytes,id);
    if (!verify(bytes,std::nullopt,0,0)) return 8;
    parameter(bytes,64);
    if (!verify(bytes,std::nullopt,1,65*8) || !verify(bytes,E::allocation_failed,1,65*8,true)) return 9;
    bytes.clear();
    // Unknown 4-byte IDs fill the entire legal 65535-byte extension, with
    // empty values. No parameter semantics or known-ID allowlist is imposed.
    for (unsigned id=1000000;bytes.size()+5<=65535;++id) parameter(bytes,id);
    if (bytes.size()!=65535 || !verify(bytes,std::nullopt,1,13107*8)) return 10;
    // The largest possible ID count uses two-byte empty tuples. Duplicates
    // are rejected even at this boundary; there is one exact-sized spill.
    bytes.assign(65534,0);
    if (!verify(bytes,E::duplicate,1,32767*8) || !verify(bytes,E::allocation_failed,1,32767*8,true)) return 11;
    bytes.push_back(0);
    if (!verify(bytes,E::malformed,0,0)) return 12;
    std::println("QUIC TP tuple framing, full-ID duplicates, legal wide varints, unknown IDs, all truncations, 64-ID stack and 65535B boundaries passed; maximum spill=262136 bytes in one allocation, local ID array=512 bytes; bad_alloc returns allocation_failed with zero live growth");
}
