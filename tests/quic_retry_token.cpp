import std;
import crypto;
import quic.retry_token;
import corosio;
namespace q=quic;namespace io = ::corosio;
using Clock=std::chrono::steady_clock;using namespace std::chrono_literals;
namespace entropy {
    bool fail=false,allocation_failure=false;unsigned calls=0;std::uint8_t next=0;
    auto fill(std::span<std::uint8_t> bytes) -> std::expected<void,::crypto::Error> {
        ++calls;if(allocation_failure)throw std::bad_alloc();if(fail)return std::unexpected(::crypto::Error::backend_failure);
        for(auto& byte:bytes)byte=next++;return {};
    }
}
namespace allocation {bool observe=false;unsigned calls=0;}
auto operator new(std::size_t size) -> void* {if(allocation::observe)++allocation::calls;if(auto* p=std::malloc(size?size:1))return p;throw std::bad_alloc();}
auto operator new[](std::size_t size) -> void* {return ::operator new(size);}
auto operator new(std::size_t size,std::align_val_t alignment) -> void* {if(allocation::observe)++allocation::calls;auto a=static_cast<std::size_t>(alignment);size=std::max<std::size_t>(size,1);if(size>std::numeric_limits<std::size_t>::max()-a)throw std::bad_alloc();if(auto* p=std::aligned_alloc(a,((size+a-1)/a)*a))return p;throw std::bad_alloc();}
auto operator new[](std::size_t size,std::align_val_t alignment) -> void* {return ::operator new(size,alignment);}
auto operator delete(void* p) noexcept -> void {std::free(p);}
auto operator delete[](void* p) noexcept -> void {std::free(p);}
auto operator delete(void* p,std::size_t) noexcept -> void {std::free(p);}
auto operator delete[](void* p,std::size_t) noexcept -> void {std::free(p);}
auto operator delete(void* p,std::align_val_t) noexcept -> void {std::free(p);}
auto operator delete[](void* p,std::align_val_t) noexcept -> void {std::free(p);}
auto operator delete(void* p,std::size_t,std::align_val_t) noexcept -> void {std::free(p);}
auto operator delete[](void* p,std::size_t,std::align_val_t) noexcept -> void {std::free(p);}
auto require(bool condition,char const* label) -> void {if(!condition){std::println("retry token check failed: {}",label);std::exit(1);}}
template<class Result>auto error(Result const& result,q::RetryTokenError expected) -> bool {return !result && result.error()==expected;}
auto main() -> int {
    using Authority=q::RetryTokenAuthority<entropy::fill>;Authority owner;
    constexpr auto token_size=Authority::token_bytes;
    std::array<std::uint8_t,20> original{},source{};
    for(unsigned i=0;i<20;++i){original[i]=static_cast<std::uint8_t>(i+17);source[i]=static_cast<std::uint8_t>(i+71);}
    std::array<std::uint8_t,token_size> token{},second{},saved{};
    io::endpoint peer(io::ipv4_address::loopback(),12345),other_port(io::ipv4_address::loopback(),12346);
    auto now=Clock::time_point(123456s);
    require(error(owner.issue(token,original,source,peer,now),q::RetryTokenError::state),"uninitialized");
    require(bool(owner.initialize()),"fresh initialized");
    require(bool(owner.issue(token,original,source,peer,now)),"issue20byteCIDs");
    saved=token;auto claims=owner.verify(token,source,peer,now);
    require(claims && std::ranges::equal(claims->original.bytes(),original) && std::ranges::equal(claims->retry.bytes(),source) && claims->version==1 && claims->issued_ms==123456000,"claims roundtrip");
    require(bool(owner.verify(token,source,peer,now+10s)),"exact deadline accepted");
    require(error(owner.verify(token,source,peer,now+10001ms),q::RetryTokenError::expired),"past deadline rejected");
    require(error(owner.verify(token,source,peer,now-1ms),q::RetryTokenError::expired),"future claim rejected");
    require(error(owner.verify(token,source,other_port,now),q::RetryTokenError::invalid),"port bound");
    std::array<std::uint8_t,4> address{127,0,0,2};io::endpoint other_address(io::ipv4_address(address),12345);
    require(error(owner.verify(token,source,other_address,now),q::RetryTokenError::invalid),"address bound");
    io::endpoint v6(io::ipv6_address::loopback(),12345);
    require(error(owner.verify(token,source,v6,now),q::RetryTokenError::invalid),"family bound");
    auto changed=source;changed[0]^=1;require(error(owner.verify(token,changed,peer,now),q::RetryTokenError::invalid),"retry source CID bound");
    require(error(owner.verify(token,source,peer,now,2),q::RetryTokenError::invalid),"version bound");
    unsigned tampered=0;
    for(std::size_t i=0;i<token.size();++i){auto invalid=token;invalid[i]^=1;require(error(owner.verify(invalid,source,peer,now),q::RetryTokenError::invalid),"every ciphertext/nonce/tag byte authenticated");++tampered;}
    for(std::size_t size=0;size<token.size();++size)require(error(owner.verify(std::span(token).first(size),source,peer,now),q::RetryTokenError::invalid),"truncated token");
    std::array<std::uint8_t,token_size+1> oversized{};require(error(owner.verify(oversized,source,peer,now),q::RetryTokenError::invalid),"oversize token");
    require(error(owner.issue(std::span(second).first(token_size-1),original,source,peer,now),q::RetryTokenError::argument),"short output");
    for(std::size_t size=0;size<=20;++size){
        auto result=owner.issue(second,std::span(original).first(size),source,peer,now);
        require(size>=8 ? bool(result) : error(result,q::RetryTokenError::argument),"original CID bounds");
        auto retry=owner.issue(second,original,std::span(source).first(size),peer,now);
        require(size>=8 ? bool(retry) : error(retry,q::RetryTokenError::argument),"retry CID bounds");
    }
    require(error(owner.issue(second,original,source,peer,Clock::time_point(-1ms)),q::RetryTokenError::argument),"negative clock");
    entropy::fail=true;require(error(owner.initialize(),q::RetryTokenError::entropy),"entropy failure reported");entropy::fail=false;
    require(bool(owner.verify(saved,source,peer,now)),"failed rotation preserves previous valid key");
    entropy::allocation_failure=true;require(error(owner.initialize(),q::RetryTokenError::allocation),"local C++ allocation failure stays distinct from entropy failure");entropy::allocation_failure=false;
    require(bool(owner.verify(saved,source,peer,now)),"allocation-failed rotation preserves valid key");
    require(bool(owner.initialize()),"successful rotation");require(error(owner.verify(saved,source,peer,now),q::RetryTokenError::invalid),"successful rotation invalidates old token");
    std::array<std::uint8_t,16> linklocal{0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    io::endpoint scoped(io::ipv6_address(linklocal,3),12345),different_scope(io::ipv6_address(linklocal,4),12345);
    require(bool(owner.issue(token,original,source,scoped,now)) && bool(owner.verify(token,source,scoped,now)),"IPv6 scope roundtrip");
    require(error(owner.verify(token,source,different_scope,now),q::RetryTokenError::invalid),"IPv6 scope bound");
    q::RetryTokenAuthority<entropy::fill,3> bounded;require(bool(bounded.initialize()),"bounded key initialized");
    for(unsigned i=0;i<3;++i)require(bool(bounded.issue(token,original,source,peer,now)),"three unique nonces");
    require(error(bounded.issue(token,original,source,peer,now),q::RetryTokenError::exhausted),"counter never wraps");
    require(bool(bounded.initialize()) && bool(bounded.issue(token,original,source,peer,now)),"fresh key recovers exhausted counter");
    allocation::observe=true;
    for(unsigned i=0;i<100000;++i){
        require(bool(owner.issue(token,original,source,peer,now)),"steady token issued");
        require(!std::ranges::equal(std::span(token).subspan(1,12),std::span(second).subspan(1,12)),"monotonic nonce distinct");
        second=token;if(i%1000==0)require(bool(owner.verify(token,source,peer,now)),"steady verified");
    }
    allocation::observe=false;require(allocation::calls==0,"steady C++ ordinary/array/aligned allocations0");
    q::RetryTokenAuthority<> real;require(bool(real.initialize()) && bool(real.issue(token,original,source,peer,now)) && bool(real.verify(token,source,peer,now)),"real CSPRNG positive");
    owner.clear();require(!owner.valid() && error(owner.verify(token,source,peer,now),q::RetryTokenError::state),"clear invalidates key");
    Authority bad_lifetime(0ms);require(error(bad_lifetime.initialize(),q::RetryTokenError::argument),"zero lifetime rejected");
    std::println("QUIC Retry token owner={} token={} tampered={} nonce_uniqueness=100000 IPv4/IPv6/scope/CID/time/rotation/entropy/exhaustion=true steady_Cppnew={}",sizeof(Authority),token_size,tampered,allocation::calls);
}
