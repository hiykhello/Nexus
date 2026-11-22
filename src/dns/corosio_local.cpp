module dns.corosio_local;
import std;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace dns::detail {
    auto LocalDefaultLookup::resolve(dns_io::endpoint endpoint,bool tcp,AddressStrategy strategy,std::string const& name,
        std::chrono::steady_clock::time_point deadline)
        -> dns_capy::task<std::expected<std::vector<Address>,ResolveError>> {
        active_=std::make_unique<DualAddressResolver>(context_,unused_cache_,tcp,strategy,true,false,nullptr,nullptr,std::nullopt,subnet_);
        return active_->resolve(endpoint,0,name,deadline);
    }
    auto LocalDefaultLookup::resolve_answer(dns_io::endpoint endpoint,bool tcp,AddressStrategy strategy,std::string const& name,
        std::chrono::steady_clock::time_point deadline)
        -> dns_capy::task<std::expected<AddressAnswer,ResolveError>> {
        active_=std::make_unique<DualAddressResolver>(context_,unused_cache_,tcp,strategy,true,false,nullptr,nullptr,std::nullopt,subnet_);
        return active_->resolve_answer(endpoint,0,name,deadline);
    }
    auto LocalAddressResolver::resolve(std::string input,std::chrono::steady_clock::time_point deadline)
        -> dns_capy::task<std::expected<std::vector<Address>,ResolveError>> {
        return resolver_.resolve(std::move(input),deadline);
    }
    auto LocalAddressResolver::resolve_answer(std::string input,std::chrono::steady_clock::time_point deadline)
        -> dns_capy::task<std::expected<AddressAnswer,ResolveError>> {
        return resolver_.resolve_answer(std::move(input),deadline);
    }
}
