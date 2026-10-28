module nexus.dns.fakeip_request;
import std;
import nexus.dns.fakeip_registry;
import nexus.dns.fakeip_target;
import nexus.dns.fakeip_shared;
import nexus.socks5;
namespace nexus::dns {
    namespace {
    template<class Registry>
    auto validate(Registry const& registry,std::span<std::uint8_t const> address)
        -> std::expected<void,FakeIpRegistryError> {
        if (address.size()==16) {
            if (!std::ranges::all_of(address.first(10),[](auto b){return b==0;}) ||
                address[10]!=0xff || address[11]!=0xff) return {};
            address=address.subspan(12);
        } else if (address.size()!=4) return std::unexpected(FakeIpRegistryError::invalid);
        std::uint32_t value=0;
        for (auto byte:address) value=(value<<8)|byte;
        auto inside=registry.contains(value);
        if constexpr (!std::same_as<decltype(inside),bool>) {
            if (!inside) return std::unexpected(inside.error());
            if (*inside) return std::unexpected(FakeIpRegistryError::unknown);
        } else if (inside) return std::unexpected(FakeIpRegistryError::unknown);
        return {};
    }
    template<class Result,class Acquire>
    auto translate(socks5::Request const& request,Acquire acquire)
        -> std::expected<Result,FakeIpRegistryError> {
        if (request.status!=socks5::Status::accepted || request.port==0)
            return std::unexpected(FakeIpRegistryError::invalid);
        std::size_t offset=0;
        if (request.address_type==1 && request.address_length==4) {
            offset=0;
        } else if (request.address_type==4 && request.address_length==16) {
            if (!std::ranges::all_of(std::span(request.address).first(10),[](auto b){return b==0;}) ||
                request.address[10]!=0xff || request.address[11]!=0xff)
                return Result{request,{}};
            offset=12;
        } else if (request.address_type==3 && request.address_length>0) {
            return Result{request,{}};
        } else return std::unexpected(FakeIpRegistryError::invalid);
        std::uint32_t address=0;
        for (std::size_t i=0;i<4;++i) address=(address<<8)|request.address[offset+i];
        auto target=acquire(address);
        if (!target) return std::unexpected(target.error());
        if (!*target) return Result{request,{}};
        auto const& domain=(*target)->mapping().domain;
        auto converted=request;
        converted.address_type=3;
        converted.address_length=static_cast<std::uint8_t>(domain.size());
        converted.address.fill(0);
        std::ranges::copy(domain,converted.address.begin());
        return Result{converted,std::move(*target)};
    }
    }
    auto validate_fakeip_resolution(FakeIpRegistry const& registry,std::span<std::uint8_t const> address)
        -> std::expected<void,FakeIpRegistryError> { return validate(registry,address); }
    auto validate_fakeip_resolution(FakeIpShared const& registry,std::span<std::uint8_t const> address)
        -> std::expected<void,FakeIpRegistryError> {
        if (!registry.sealed()) return std::unexpected(FakeIpRegistryError::unsealed);
        return validate(registry,address);
    }
    auto translate_fakeip_request(FakeIpRegistry& registry,socks5::Request const& request,
        std::uint64_t view,std::chrono::steady_clock::time_point now)
        -> std::expected<FakeIpRequest,FakeIpRegistryError> {
        return translate<FakeIpRequest>(request,[&](auto address){return registry.acquire(address,view,now);});
    }
    auto translate_fakeip_request(FakeIpShared& registry,socks5::Request const& request,std::uint64_t view)
        -> std::expected<SharedFakeIpRequest,FakeIpRegistryError> {
        if (!registry.sealed()) return std::unexpected(FakeIpRegistryError::unsealed);
        return translate<SharedFakeIpRequest>(request,[&](auto address){return registry.acquire(address,view);});
    }
}
