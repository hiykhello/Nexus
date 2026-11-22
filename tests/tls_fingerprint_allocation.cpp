import std;
import tls.fingerprint;
import tls.client_hello_exchange;
import tls.server_keys;

namespace allocation {
    struct Header { void* base; };
    bool enabled=false,denied=false;
    std::ptrdiff_t allowance=-1;
    std::size_t live=0,calls=0;
    auto get(std::size_t size,std::size_t alignment=alignof(std::max_align_t)) -> void* {
        if (enabled) {
            ++calls;
            if (!allowance) {denied=true;throw std::bad_alloc();}
            if (allowance>0) --allowance;
        }
        alignment=std::max(alignment,alignof(Header));size=std::max<std::size_t>(size,1);
        if (size>std::numeric_limits<std::size_t>::max()-2*alignment) throw std::bad_alloc();
        auto* base=static_cast<std::byte*>(std::aligned_alloc(alignment,(size+2*alignment-1)/alignment*alignment));
        if (!base) throw std::bad_alloc();
        auto* pointer=base+alignment;
        std::construct_at(reinterpret_cast<Header*>(pointer)-1,Header{base});
        ++live;return pointer;
    }
    auto release(void* pointer) noexcept -> void {
        if (!pointer) return;
        auto* header=static_cast<Header*>(pointer)-1;auto* base=header->base;
        --live;std::free(base);
    }
}
auto operator new(std::size_t n) -> void* {return allocation::get(n);}
auto operator new[](std::size_t n) -> void* {return allocation::get(n);}
auto operator new(std::size_t n,std::align_val_t a) -> void* {return allocation::get(n,static_cast<std::size_t>(a));}
auto operator new[](std::size_t n,std::align_val_t a) -> void* {return allocation::get(n,static_cast<std::size_t>(a));}
auto operator delete(void* p) noexcept -> void {allocation::release(p);}
auto operator delete[](void* p) noexcept -> void {allocation::release(p);}
auto operator delete(void* p,std::size_t) noexcept -> void {allocation::release(p);}
auto operator delete[](void* p,std::size_t) noexcept -> void {allocation::release(p);}
auto operator delete(void* p,std::align_val_t) noexcept -> void {allocation::release(p);}
auto operator delete[](void* p,std::align_val_t) noexcept -> void {allocation::release(p);}
auto operator delete(void* p,std::size_t,std::align_val_t) noexcept -> void {allocation::release(p);}
auto operator delete[](void* p,std::size_t,std::align_val_t) noexcept -> void {allocation::release(p);}

namespace t=tls;
using Bytes=std::vector<std::uint8_t>;
auto attempt(t::Fingerprint profile,t::FingerprintShares shares,t::HandshakeTransport transport) -> bool {
    t::FingerprintConfig config{profile,shares,1600};
    if (transport==t::HandshakeTransport::quic) config.cipher_count=2;
    std::array<std::string_view,1> alpn{"h3"};std::array<std::uint8_t,2> parameters{15,0};
    auto draft=t::make_fingerprint_hello("localhost",alpn,config,transport,transport==t::HandshakeTransport::quic ? std::optional<std::span<std::uint8_t const>>(parameters) : std::nullopt);
    if (!draft) return false;
    auto exchange=t::ClientHelloExchange::create(std::move(draft->hello),draft->initial_groups(),transport);if (!exchange) return false;
    Bytes first(exchange->initial().begin(),exchange->initial().end());if(!exchange->initial_sent())return false;
    std::array<std::uint16_t,1> schemes{0x0807},ciphers{0x1302};
    auto server=t::server_handshake_secrets(first,schemes,t::PeerSignaturePolicy::require_offered,ciphers,transport);
    if (shares==t::FingerprintShares::retry) {
        auto retry=t::server_retry_hello(first,schemes,ciphers,transport);if(!retry)return false;
        auto received=exchange->receive(*retry);if(!received||received->outbound.empty())return false;
        Bytes second(received->outbound.begin(),received->outbound.end());if(!exchange->retry_sent())return false;
        server=t::server_handshake_secrets_retry(first,*retry,second,schemes,ciphers,transport);
    }
    if(!server||!exchange->receive(server->server_hello))return false;
    auto flight=exchange->take_flight();if(!flight)return false;
    auto keys=flight->handshake_secrets();
    return keys&&std::ranges::equal(keys->client,server->secrets.client_traffic.view())&&std::ranges::equal(keys->server,server->secrets.server_traffic.view());
}
int main() {
    std::size_t failures=0;
    for(auto transport:{t::HandshakeTransport::tcp,t::HandshakeTransport::quic})
      for(auto profile:{t::Fingerprint::tls13_grease,t::Fingerprint::tls13_randomized})
       for(auto shares:{t::FingerprintShares::x25519,t::FingerprintShares::hybrid,t::FingerprintShares::dual,t::FingerprintShares::retry}) {
        if(!attempt(profile,shares,transport))return 1;
        auto before=allocation::live;
        allocation::allowance=-1;allocation::calls=0;allocation::enabled=true;
        if(!attempt(profile,shares,transport))return 2;
        allocation::enabled=false;auto count=allocation::calls;
        if(allocation::live!=before)return 3;
        for(std::size_t fail=0;fail<=count;++fail) {
            bool complete=false,threw=false;allocation::allowance=static_cast<std::ptrdiff_t>(fail);
            allocation::calls=0;allocation::denied=false;allocation::enabled=true;
            try {complete=attempt(profile,shares,transport);}catch(std::bad_alloc const&){threw=true;}
            allocation::enabled=false;
            if(allocation::live!=before || (fail<count&&(!allocation::denied||complete)) || (fail==count&&(!complete||threw||allocation::denied)))return 4;
            if(fail<count)++failures;
            if(!attempt(profile,shares,transport)||allocation::live!=before)return 5;
        }
        std::println("transport={} profile={} shares={} C++failures={} fresh-owner recovery and live balance passed",static_cast<int>(transport),static_cast<int>(profile),static_cast<int>(shares),count);
       }
    std::println("fingerprint allocation failure points={} passed",failures);
}
