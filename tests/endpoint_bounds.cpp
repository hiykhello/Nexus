import std;
import platform.netlink_abi;
import platform.netlink_codec;
namespace a = ::platform::netlink_abi;
namespace n = ::platform::netlink;
auto main() -> int {
    std::array<std::uint8_t,1005> storage{};
    for (auto size:{std::size_t{1005},std::size_t{1020},std::numeric_limits<std::size_t>::max()-3,std::numeric_limits<std::size_t>::max()}) {
        n::Request request(a::RTM_NEWLINK,a::NLM_F_REQUEST);
        auto before=request.bytes(); std::array<std::uint8_t,16> original{};
        std::ranges::copy(before,original.begin());
        // These oversized spans are never dereferenced: size is rejected before
        // addition, alignment or any payload memory access.
        auto payload=std::span<std::uint8_t const>(storage.data(),size);
        if (request.append(1,payload) || request.valid() || request.bytes().size()!=original.size() || !std::ranges::equal(request.bytes(),original)) return 1;
    }
    n::Request exact(a::RTM_NEWLINK,a::NLM_F_REQUEST);
    if (!exact.append(1,std::span(storage).first(1004)) || exact.bytes().size()!=1024 || !exact.valid()) return 2;
    if (exact.append(1,{}) || exact.valid() || exact.bytes().size()!=1024) return 3;
    std::println("netlink Request append exact capacity, padding boundary and huge sizes reject before arithmetic/memory access; existing bytes preserved");
}
