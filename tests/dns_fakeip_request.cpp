import std;
import nexus.dns.fakeip;
import nexus.dns.fakeip_response;
import nexus.dns.fakeip_target;
import nexus.dns.fakeip_registry;
import nexus.dns.fakeip_request;
import nexus.dns.fakeip_shared;
import nexus.dns.message;
import nexus.socks5;
namespace d=nexus::dns;
namespace s=nexus::socks5;
using namespace std::chrono_literals;
auto request(std::initializer_list<std::uint8_t> address,std::uint8_t type) -> s::Request {
    s::Request r; r.status=s::Status::accepted; r.address_type=type;
    r.address_length=static_cast<std::uint8_t>(address.size()); r.port=443;
    std::ranges::copy(address,r.address.begin()); return r;
}
auto main() -> int {
    constexpr std::uint32_t base=0xc6120000;
    auto t=std::chrono::steady_clock::time_point{};
    d::FakeIpRegistry registry(1);
    auto pool=d::FakeIpPool::create(base+1,base+1,10s,2s);
    if (!pool || !registry.add(base,base+3,std::move(*pool))) return 1;
    auto ip=request({198,18,0,1},1);
    auto unknown=d::translate_fakeip_request(registry,ip,7,t);
    if (unknown || unknown.error()!=d::FakeIpRegistryError::unknown) return 2;
    auto query=d::make_query(1,{"example.com",1});
    if (!query) return 3;
    auto response=registry.respond(base,*query,7,t);
    if (!response || !(*response)->finish(true,t)) return 4;
    auto wrong=d::translate_fakeip_request(registry,ip,8,t);
    if (wrong || wrong.error()!=d::FakeIpRegistryError::wrong_view) return 5;
    auto translated=d::translate_fakeip_request(registry,ip,7,t);
    auto mapped=request({0,0,0,0,0,0,0,0,0,0,255,255,198,18,0,1},4);
    auto second=d::translate_fakeip_request(registry,mapped,7,t);
    if (!translated || !second || !translated->target || !second->target ||
        translated->request.address_type!=3 || translated->request.port!=443 ||
        std::string_view(reinterpret_cast<char const*>(translated->request.address.data()),translated->request.address_length)!="example.com" ||
        second->request.address_type!=3) return 6;
    auto other=request({127,0,0,1},1);
    auto ordinary=d::translate_fakeip_request(registry,other,7,t);
    auto ipv6=request({0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1},4);
    auto ordinary6=d::translate_fakeip_request(registry,ipv6,7,t);
    auto domain=request({'e','x','a','m','p','l','e'},3);
    auto ordinary_domain=d::translate_fakeip_request(registry,domain,7,t);
    if (!ordinary || ordinary->target || ordinary->request.address!=other.address ||
        !ordinary6 || ordinary6->target || ordinary6->request.address!=ipv6.address ||
        !ordinary_domain || ordinary_domain->target || ordinary_domain->request.address!=domain.address) return 7;
    auto reserved=request({198,18,0,0},1);
    auto rejected=d::translate_fakeip_request(registry,reserved,7,t);
    if (rejected || rejected.error()!=d::FakeIpRegistryError::unknown) return 8;
    auto invalid=ip; invalid.address_length=3;
    if (d::translate_fakeip_request(registry,invalid,7,t).error()!=d::FakeIpRegistryError::invalid) return 9;
    auto new_query=d::make_query(2,{"other.example",1});
    if (!new_query || !translated->target->release(t+12s)) return 10;
    auto blocked=registry.respond(base,*new_query,7,t+12s);
    if (blocked || blocked.error()!=std::variant<d::FakeIpRegistryError,d::FakeIpDnsError>{d::FakeIpDnsError::full}) return 11;
    if (!second->target->release(t+12s)) return 12;
    auto reused=registry.respond(base,*new_query,7,t+12s);
    if (!reused || !(*reused)->finish(false,t+12s)) return 13;
    auto address=std::span(ip.address).first(4);
    auto mapped_address=std::span(mapped.address).first(16);
    if (d::validate_fakeip_resolution(registry,address).error()!=d::FakeIpRegistryError::unknown ||
        d::validate_fakeip_resolution(registry,mapped_address).error()!=d::FakeIpRegistryError::unknown ||
        d::validate_fakeip_resolution(registry,std::span(reserved.address).first(4)).error()!=d::FakeIpRegistryError::unknown ||
        !d::validate_fakeip_resolution(registry,std::span(other.address).first(4)) ||
        !d::validate_fakeip_resolution(registry,std::span(ipv6.address).first(16)) ||
        d::validate_fakeip_resolution(registry,std::span(ip.address).first(3)).error()!=d::FakeIpRegistryError::invalid) return 14;
    if (!registry.retire(base) ||
        d::validate_fakeip_resolution(registry,address).error()!=d::FakeIpRegistryError::unknown ||
        d::validate_fakeip_resolution(registry,mapped_address).error()!=d::FakeIpRegistryError::unknown) return 15;
    auto shared=std::make_unique<d::FakeIpShared>(1);
    if (!shared->add(base,base+3,base+1,base+1,10s,2s)) return 16;
    auto not_ready=d::translate_fakeip_request(*shared,other,7);
    auto not_ready_resolution=d::validate_fakeip_resolution(*shared,std::span(other.address).first(4));
    if (not_ready || not_ready.error()!=d::FakeIpRegistryError::unsealed || not_ready_resolution ||
        not_ready_resolution.error()!=d::FakeIpRegistryError::unsealed || !shared->seal()) return 20;
    auto published=shared->respond(base,*query,7);
    if (!published || !(*published)->finish(true)) return 17;
    auto converted=d::translate_fakeip_request(*shared,mapped,7);
    auto denied=d::translate_fakeip_request(*shared,ip,8);
    auto loop=d::validate_fakeip_resolution(*shared,mapped_address);
    if (!converted || !converted->target || converted->request.address_type!=3 ||
        converted->target->mapping().domain!="example.com" || denied ||
        denied.error()!=d::FakeIpRegistryError::wrong_view || loop || loop.error()!=d::FakeIpRegistryError::unknown) return 18;
    shared.reset();
    std::atomic<bool> released=false;
    std::thread worker([target=std::move(converted->target),&released] { released=target->release().has_value(); });
    worker.join();
    if (!released) return 19;
    d::FakeIpShared historical(1);
    if (!historical.reserve(0x0a000000,0x0affffff) || !historical.seal()) return 21;
    auto old=request({10,2,3,4},1);
    auto old_target=d::translate_fakeip_request(historical,old,7);
    auto old_resolution=d::validate_fakeip_resolution(historical,std::span(old.address).first(4));
    if (old_target || old_target.error()!=d::FakeIpRegistryError::unknown ||
        old_resolution || old_resolution.error()!=d::FakeIpRegistryError::unknown) return 22;
    std::println("FakeIP request translation and connection pins passed");
}
