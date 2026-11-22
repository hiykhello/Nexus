module dns.fakeip_request;
import std;
import dns.fakeip;
import dns.fakeip_registry;
import dns.fakeip_target;
import dns.fakeip_shared;
import socks5;
namespace dns {
    namespace {
        template<class Result,class Acquire>
        auto translate(socks5::Request const& request,Acquire acquire)
            -> std::expected<Result,FakeIpRegistryError> {
            if (request.status!=socks5::Status::accepted || request.port==0)
                return std::unexpected(FakeIpRegistryError::invalid);
            if (request.address_type==3 && request.address_length>0)
                return Result{request,{}};
            if ((request.address_type!=1 || request.address_length!=4) &&
                (request.address_type!=4 || request.address_length!=16))
                return std::unexpected(FakeIpRegistryError::invalid);
            auto target=acquire(std::span(request.address).first(request.address_length));
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
        -> std::expected<void,FakeIpRegistryError> {
        if (address.size()!=4 && address.size()!=16) return std::unexpected(FakeIpRegistryError::invalid);
        auto key=fakeip_ipv4_key(address);
        if (key && registry.contains(*key)) return std::unexpected(FakeIpRegistryError::unknown);
        return {};
    }
    auto validate_fakeip_resolution(FakeIpShared const& registry,std::span<std::uint8_t const> address)
        -> std::expected<void,FakeIpRegistryError> {
        auto inside=registry.contains(address);
        if (!inside) return std::unexpected(inside.error());
        if (*inside) return std::unexpected(FakeIpRegistryError::unknown);
        return {};
    }
    auto translate_fakeip_request(FakeIpRegistry& registry,socks5::Request const& request,
        std::uint64_t view,std::chrono::steady_clock::time_point now)
        -> std::expected<FakeIpRequest,FakeIpRegistryError> {
        return translate<FakeIpRequest>(request,[&](std::span<std::uint8_t const> address)
            -> std::expected<std::unique_ptr<FakeIpTarget>,FakeIpRegistryError> {
            auto key=fakeip_ipv4_key(address);
            if (!key) return std::unique_ptr<FakeIpTarget>{};
            return registry.acquire(*key,view,now);
        });
    }
    auto translate_fakeip_request(FakeIpShared& registry,socks5::Request const& request,std::uint64_t view)
        -> std::expected<SharedFakeIpRequest,FakeIpRegistryError> {
        if (!registry.sealed()) return std::unexpected(FakeIpRegistryError::unsealed);
        return translate<SharedFakeIpRequest>(request,[&](auto address){return registry.acquire(address,view);});
    }
}
