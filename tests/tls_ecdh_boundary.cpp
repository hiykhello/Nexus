import std;
import tls.fingerprint;
import tls.client_hello_exchange;
import tls.server_keys;
import tls.handshake;
namespace native {
    struct alignas(std::max_align_t) Header { std::size_t size; };
    bool enabled=false,denied=false;
    std::ptrdiff_t allowance=-1;
    std::size_t calls=0,live=0,bytes=0;
}
// Fixed BoringSSL mem.cc's native allocator hook, not a C++ allocation shim.
extern "C" auto OPENSSL_memory_alloc(std::size_t size) noexcept -> void* {
    if (native::enabled) { ++native::calls; if (!native::allowance) {native::denied=true;return nullptr;} if(native::allowance>0)--native::allowance; }
    if(size>std::numeric_limits<std::size_t>::max()-sizeof(native::Header))return nullptr;
    auto* block=static_cast<native::Header*>(std::malloc(sizeof(native::Header)+size));if(!block)return nullptr;
    block->size=size;++native::live;native::bytes+=size;return block+1;
}
extern "C" auto OPENSSL_memory_free(void* pointer) noexcept -> void {
    if(!pointer)return;
    auto* block=static_cast<native::Header*>(pointer)-1;auto size=block->size;
    native::bytes-=size;--native::live;
    auto* byte=reinterpret_cast<volatile unsigned char*>(block);
    for(std::size_t i=0;i<sizeof(native::Header)+size;++i)byte[i]=0;
    std::free(block);
}
extern "C" auto OPENSSL_memory_get_size(void* pointer) noexcept -> std::size_t {
    return (static_cast<native::Header*>(pointer)-1)->size;
}

namespace t=tls;namespace c = ::crypto;
auto frame(t::ServerHello const& hello) -> c::Bytes {
    auto body=hello.encode();if(!body)throw std::runtime_error("encode server");auto wire=t::HandshakeDecoder::encode(2,*body,65535);if(!wire)throw std::runtime_error("frame server");return std::move(*wire);
}
int main() {
    constexpr std::array<std::uint16_t,5> groups{29,0x11ec,23,24,25};
    std::array<std::uint16_t,1> schemes{0x0807};unsigned pairs=0;
    for(std::size_t first=0;first<groups.size();++first)for(std::size_t second=first+1;second<groups.size();++second) {
        t::FingerprintConfig config;config.profile=t::Fingerprint::tls13_randomized;config.group_count=5;config.key_share_count=2;
        config.key_share_groups={groups[first],groups[second]};
        auto shape=t::make_fingerprint_hello("localhost",{},config);if(!shape)return 1;
        auto exchange=t::ClientHelloExchange::create(std::move(shape->hello),shape->initial_groups());if(!exchange)return 2;
        auto server=t::server_handshake_secrets(exchange->initial(),schemes);if(!server||!exchange->initial_sent()||!exchange->receive(server->server_hello))return 3;
        auto flight=exchange->take_flight();if(!flight)return 4;auto keys=flight->handshake_secrets();
        if(!keys||!std::ranges::equal(keys->client,server->secrets.client_traffic.view())||!std::ranges::equal(keys->server,server->secrets.server_traffic.view()))return 5;
        std::swap(config.key_share_groups[0],config.key_share_groups[1]);
        if(t::make_fingerprint_hello("localhost",{},config))return 6;
        ++pairs;
    }
    t::FingerprintConfig invalid;invalid.group_count=2;invalid.group_order={23,24,0,0,0};invalid.key_share_count=2;invalid.key_share_groups={23,23};
    if(t::make_fingerprint_hello("localhost",{},invalid))return 7;
    invalid.key_share_groups={23,25};if(t::make_fingerprint_hello("localhost",{},invalid))return 8;
    invalid.group_count=6;if(t::make_fingerprint_hello("localhost",{},invalid))return 9;
    invalid.group_count=1;invalid.group_order[0]=26;if(t::make_fingerprint_hello("localhost",{},invalid))return 10;
    for(auto group:{23,24,25})for(unsigned fault:{0u,1u,2u,3u}) {
        t::FingerprintConfig config;config.group_count=1;config.group_order[0]=group;config.key_share_groups[0]=group;
        auto shape=t::make_fingerprint_hello("localhost",{},config);if(!shape)return 11;
        auto before=native::live;
        auto exchange=t::ClientHelloExchange::create(std::move(shape->hello),shape->initial_groups());if(!exchange)return 12;
        auto native_key_count=native::live-before;
        c::Bytes response;
        std::optional<t::ServerHandshakeSecrets> server;
        if(fault==3) {
            auto result=t::server_handshake_secrets(exchange->initial(),schemes);if(!result)return 13;
            server.emplace(std::move(*result));response=server->server_hello;
        } else {
            t::ServerHello bad;bad.random.fill(7);bad.extensions={{43,{3,4}}};
            if(fault==1)bad.extensions.push_back({51,{0}});
            if(fault==2) {auto count=c::nist_curve(group)->public_size();c::Bytes value{static_cast<std::uint8_t>(group>>8),static_cast<std::uint8_t>(group),0,static_cast<std::uint8_t>(count)};value.resize(count+4);value[4]=4;bad.extensions.push_back({51,std::move(value)});}
            response=frame(bad);
        }
        auto before_failure=native::live;
        if(!exchange->initial_sent()||!exchange->receive(response))return 14;
        if(fault==3) {native::allowance=0;native::calls=0;native::denied=false;native::enabled=true;}
        auto failed=exchange->take_flight();native::enabled=false;boringssl::ERR_clear_error();
        if(failed || failed.error()!=(fault==3 ? t::ClientHelloDriverError::crypto_error : t::ClientHelloDriverError::invalid_hello) || native::live!=before_failure-native_key_count || (fault==3 && !native::denied))return 15;
        if(exchange->ready()||exchange->can_receive()||exchange->initial_key())return 16;
    }
    std::println("{} mixed X/hybrid/NIST dual-share schedules, ordered subset rejection, 12 failed-flight immediate native key cleanups and crypto-error retention passed",pairs);
}
