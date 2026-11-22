module;
#include <boost/capy/ex/run_async.hpp>
#include <unistd.h>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
module proxy;
import std;
import proxy.v4;
import uot;
import dns.local_config;
import proxy.dns_state;
namespace proxy {
    namespace {
        // The context may retain a suspended task until destruction, so it
        // must be destroyed before the DNS state borrowed by that task.
        struct FixtureState {
            LocalDnsState local_dns;
#ifdef NEXUS_DNS_SHARED
            SharedDnsGeneration generation{1,1};
            DnsState dns{DnsRouting{},generation.cache(),0,0};
#endif
            io::io_context context{io::epoll};
            FixtureState() {
#ifdef NEXUS_DNS_SHARED
                generation.seal();
                dns.local_views.emplace(generation.local_registry());
                dns.coordinator.emplace(context,dns.cache,generation.coordinator());
#endif
            }
            auto make_session() -> std::unique_ptr<Session> {
                auto session=std::make_unique<Session>(context);
                session->local_dns=&local_dns;
#ifdef NEXUS_DNS_SHARED
                session->dns=&dns;
#endif
                return session;
            }
        };
        auto invalid_probe(std::unique_ptr<Session> owned,io::io_context& context,unsigned server,unsigned port,unsigned mode,int& result) -> capy::task<> {
            auto& session=*owned;
            std::array<std::uint8_t,16> key{}; for (std::uint8_t i=0;i<key.size();++i) key[i]=i;
            auto factory=make_shadowsocks_factory("127.0.0.1",static_cast<std::uint16_t>(server),key,{},true,10000);
            if (!factory) { result=2; co_return; }
            session.tunnel=(*factory)(session,context);
            struct Reset { Session& session; ~Reset() { session.tunnel={}; } } reset{session};
            if (co_await session.tunnel->connect_uot()!=TunnelConnectResult::connected) { result=3; co_return; }
            uot::Address target{}; target.family=uot::Family::ipv4; target.length=4; target.bytes[0]=127; target.bytes[3]=1; target.port=static_cast<std::uint16_t>(port);
            auto request=uot::encode_request({false,target});
            std::array<std::uint8_t,1> payload{'x'};
            auto valid=uot::encode_packet(false,target,payload);
            if (!request || !valid) { result=4; co_return; }
            std::vector<std::uint8_t> wire;
            if (mode==0) { wire={0,99}; wire.insert(wire.end(),valid->begin(),valid->end()); }
            else if (mode==1) { wire=*request; wire.push_back(255); wire.insert(wire.end(),valid->begin(),valid->end()); }
            else if (mode==2) { wire=*request; wire.insert(wire.end(),valid->begin(),valid->end()-1); }
            else { result=4; co_return; }
            if (!co_await session.tunnel->send(wire)) { result=5; co_return; }
            if (mode==2 && !co_await session.tunnel->close_output()) { result=6; co_return; }
            std::array<std::uint8_t,128> buffer{};
            auto response=co_await session.tunnel->read(buffer);
            result=(!response || !*response) ? 0 : 7;
        }
        auto cross_probe(std::unique_ptr<Session> owned,io::io_context& context,unsigned server_port,unsigned target_port,bool reverse,unsigned count,int& result,bool gated=false,bool empty=false,bool empty_reply=false) -> capy::task<> {
            auto& session=*owned;
            std::array<std::uint8_t,16> key{}; for (std::uint8_t i=0;i<key.size();++i) key[i]=i;
            auto factory=make_shadowsocks_factory("127.0.0.1",static_cast<std::uint16_t>(server_port),key,{},true,10000);
            if (!factory) { result=2; co_return; }
            session.tunnel=(*factory)(session,context);
            struct Reset { Session& session; ~Reset() { session.tunnel={}; } } reset{session};
            if (co_await session.tunnel->connect_uot()!=TunnelConnectResult::connected) { result=3; co_return; }
            uot::Address target{}; target.family=uot::Family::ipv4; target.length=4; target.bytes[0]=127; target.bytes[3]=reverse ? 2 : 1; target.port=static_cast<std::uint16_t>(target_port);
            auto request=uot::encode_request({false,target});
            if (!request || !co_await session.tunnel->send(*request)) { result=4; co_return; }
            std::vector<std::uint8_t> payload; if (!empty) payload={'p','r','o','b','e'};
            std::vector<std::uint8_t> expected; if (!empty_reply) expected={'g','o','o','d'};
            uot::PacketDecoder decoder(false); std::array<std::uint8_t,256> buffer{};
            for (unsigned i=0;i<std::max(count,1u);++i) {
                auto frame=uot::encode_packet(false,target,payload);
                if (!frame || !co_await session.tunnel->send(*frame)) { result=5; co_return; }
                bool received=false;
                while (!received) {
                    auto n=co_await session.tunnel->read(buffer);
                    if (!n || !*n) { result=6; co_return; }
                    auto fed=decoder.feed(std::span(buffer).first(*n));
                    if (fed.status==uot::Status::incomplete && fed.consumed==*n) continue;
                    auto reply=decoder.packet();
                    if (fed.status!=uot::Status::accepted || fed.consumed!=*n || !reply || reply->destination!=target || !std::ranges::equal(reply->payload,expected) || !decoder.consume()) { result=7; co_return; }
                    received=true;
                }
                if (gated && i+1<count) {
                    std::println("ready"); std::fflush(stdout);
                    char release; if (::read(STDIN_FILENO,&release,1)!=1) { result=10; co_return; }
                }
                target.bytes[3]=reverse ? 1 : 2;
            }
            if (!count) {
                std::println("ready"); std::fflush(stdout);
                auto response=co_await session.tunnel->read(buffer);
                result=(!response || !*response) ? 0 : 8;
                co_return;
            }
            result=0;
        }
        auto probe(std::unique_ptr<Session> owned, io::io_context& context, unsigned server_port, unsigned target_port, bool connected, int policy, int& result) -> capy::task<> {
            auto& session=*owned;
            std::array<std::uint8_t,16> key{};
            for (std::uint8_t i=0;i<key.size();++i) key[i]=i;
            auto factory=make_shadowsocks_factory("127.0.0.1",static_cast<std::uint16_t>(server_port),key,{},true,10000);
            if (!factory) { result=2; co_return; }
            session.tunnel=(*factory)(session,context);
            struct Reset { Session& session; ~Reset() { session.tunnel = {}; } } reset{session};
            if (co_await session.tunnel->connect_uot()!=TunnelConnectResult::connected) { result=3; co_return; }
            uot::Address target{}; target.family=uot::Family::ipv4; target.length=4;
            target.bytes[0]=127; target.bytes[3]=1; target.port=static_cast<std::uint16_t>(target_port);
            auto request=uot::encode_request({connected,target});
            constexpr std::array<std::uint8_t,9> payload{'u','o','t','-','p','r','o','b','e'};
            auto packet=uot::encode_packet(connected,target,payload);
            if (!request || !packet) { result=4; co_return; }
            if (policy==4 || policy==5 || policy==6) {
                request=uot::encode_request({false,target});
                for (unsigned i=0;i<(policy==6 ? 1000u : 100u);++i) {
                    std::vector<std::uint8_t> large(policy==5 ? 60000 : policy==6 ? 8192 : 0,static_cast<std::uint8_t>(i));
                    auto frame=uot::encode_packet(false,target,policy==5 || policy==6 ? std::span<std::uint8_t const>(large) : std::span<std::uint8_t const>(payload));
                    if (!request || !frame) { result=4; co_return; }
                    request->insert(request->end(),frame->begin(),frame->end());
                }
            } else if (policy) {
                auto domain=[&](std::string_view name) {
                    uot::Address address{}; address.family=uot::Family::domain; address.length=static_cast<std::uint8_t>(name.size());
                    std::ranges::copy(name,address.bytes.begin()); address.port=target.port; return address;
                };
                request=uot::encode_request({false,domain("allowed.test")});
                if (policy==2 || policy==3) {
                    for (unsigned i=0;i<(policy==3 ? 20u : 100u);++i) {
                        std::vector<std::uint8_t> large(policy==3 ? 60000 : 0,static_cast<std::uint8_t>(i));
                        auto frame=uot::encode_packet(false,domain("blocked.test"),policy==3 ? std::span<std::uint8_t const>(large) : std::span<std::uint8_t const>(payload));
                        if (!request || !frame) { result=4; co_return; }
                        request->insert(request->end(),frame->begin(),frame->end());
                    }
                } else {
                    for (auto name:{"blocked.test","deny.test","allowed.test","later.test"}) {
                        auto frame=uot::encode_packet(false,domain(name),payload);
                        if (!request || !frame) { result=4; co_return; }
                        request->insert(request->end(),frame->begin(),frame->end());
                    }
                }
                target.bytes[3]=2;
            } else {
            request->insert(request->end(),packet->begin(),packet->end());
            }
            if (!co_await session.tunnel->send(*request)) { result=5; co_return; }
            if (policy==2 || policy==3 || policy==4) { std::println("sent"); std::fflush(stdout); }
            uot::PacketDecoder decoder(connected,target);
            std::array<std::uint8_t,16384> buffer{};
            unsigned replies=0;
            for (;;) {
                auto n=co_await session.tunnel->read(buffer);
                if (!n || !*n) { result=6; co_return; }
                std::size_t offset=0;
                while (offset<*n) {
                    auto step=decoder.feed(std::span(buffer).subspan(offset,*n-offset)); offset+=step.consumed;
                    if (step.status==uot::Status::incomplete) break;
                    if (step.status!=uot::Status::accepted) { result=8; co_return; }
                    auto reply=decoder.packet();
                    bool valid_payload=reply && (policy==3 || policy==5 || policy==6 ? reply->payload.size()==(policy==6 ? 8192u : 60000u) &&
                        std::ranges::all_of(reply->payload,[&](auto byte){return byte==static_cast<std::uint8_t>(replies);}) : std::ranges::equal(reply->payload,payload));
                    if (!reply || reply->destination!=target || !valid_payload) {
                        if (policy==3 && reply) std::println(stderr,"reply {} size {} first {}",replies,reply->payload.size(),reply->payload.empty() ? 256 : reply->payload.front());
                        result=7; co_return;
                    }
                    if (++replies==(policy==6 ? 1000u : policy==3 ? 20u : policy==2 || policy==4 || policy==5 ? 100u : policy ? 2u : 1u)) { result=0; co_return; }
                    if (!decoder.consume()) { result=8; co_return; }
                }
            }
        }
    }
}
extern "C" int nexus_test_proxy_uot(unsigned server, unsigned target, bool connected) {
    using namespace proxy;
    int result=9;
    FixtureState state;
    auto& context=state.context;
    auto session=state.make_session();
    capy::run_async(context.get_executor())(probe(std::move(session),context,server,target,connected,false,result));
    context.restart(); (void)context.run_for(std::chrono::seconds(15));
    return result;
}
extern "C" int nexus_test_proxy_uot_policy(unsigned server, unsigned target) {
    using namespace proxy;
    int result=9;
    FixtureState state;
    auto& context=state.context;
    auto session=state.make_session();
    capy::run_async(context.get_executor())(probe(std::move(session),context,server,target,false,true,result));
    context.restart(); (void)context.run_for(std::chrono::seconds(15));
    return result;
}
extern "C" int nexus_test_proxy_uot_flood(unsigned server, unsigned target) {
    using namespace proxy;
    int result=9;
    FixtureState state;
    auto& context=state.context;
    auto session=state.make_session();
    capy::run_async(context.get_executor())(probe(std::move(session),context,server,target,false,2,result));
    context.restart(); (void)context.run_for(std::chrono::seconds(15));
    return result;
}
extern "C" int nexus_test_proxy_uot_empty_echo(unsigned server, unsigned target) {
    using namespace proxy;
    int result=9; FixtureState state; auto& context=state.context; auto session=state.make_session();
    capy::run_async(context.get_executor())(cross_probe(std::move(session),context,server,target,false,1,result,false,true,true));
    context.restart(); (void)context.run_for(std::chrono::seconds(15)); return result;
}
extern "C" int nexus_test_proxy_uot_empty(unsigned server, unsigned target) {
    using namespace proxy;
    int result=9; FixtureState state; auto& context=state.context; auto session=state.make_session();
    capy::run_async(context.get_executor())(cross_probe(std::move(session),context,server,target,false,1,result,false,true));
    context.restart(); (void)context.run_for(std::chrono::seconds(15)); return result;
}
extern "C" int nexus_test_proxy_uot_rotate(unsigned server, unsigned target) {
    using namespace proxy;
    int result=9; FixtureState state; auto& context=state.context; auto session=state.make_session();
    capy::run_async(context.get_executor())(cross_probe(std::move(session),context,server,target,false,3,result,true));
    context.restart(); (void)context.run_for(std::chrono::seconds(20)); return result;
}
extern "C" int nexus_test_proxy_uot_end(unsigned server, unsigned target) {
    using namespace proxy;
    int result=9; FixtureState state; auto& context=state.context; auto session=state.make_session();
    capy::run_async(context.get_executor())(cross_probe(std::move(session),context,server,target,false,2,result,true));
    context.restart(); (void)context.run_for(std::chrono::seconds(20)); return result;
}
extern "C" int nexus_test_proxy_uot_cross(unsigned server, unsigned target, bool reverse) {
    using namespace proxy;
    int result=9; FixtureState state; auto& context=state.context; auto session=state.make_session();
    capy::run_async(context.get_executor())(cross_probe(std::move(session),context,server,target,reverse,2,result));
    context.restart(); (void)context.run_for(std::chrono::seconds(15)); return result;
}
extern "C" int nexus_test_proxy_uot_one(unsigned server, unsigned target) {
    using namespace proxy;
    int result=9; FixtureState state; auto& context=state.context; auto session=state.make_session();
    capy::run_async(context.get_executor())(cross_probe(std::move(session),context,server,target,false,1,result));
    context.restart(); (void)context.run_for(std::chrono::seconds(15)); return result;
}
extern "C" int nexus_test_proxy_uot_downstream_fault(unsigned server, unsigned target) {
    using namespace proxy;
    int result=9; FixtureState state; auto& context=state.context; auto session=state.make_session();
    capy::run_async(context.get_executor())(cross_probe(std::move(session),context,server,target,false,0,result));
    context.restart(); (void)context.run_for(std::chrono::seconds(15)); return result;
}
extern "C" int nexus_test_proxy_uot_large(unsigned server, unsigned target) {
    using namespace proxy;
    int result=9; FixtureState state; auto& context=state.context; auto session=state.make_session();
    capy::run_async(context.get_executor())(probe(std::move(session),context,server,target,false,3,result));
    context.restart(); (void)context.run_for(std::chrono::seconds(15)); return result;
}
extern "C" int nexus_test_proxy_uot_numeric_flood(unsigned server, unsigned target) {
    using namespace proxy;
    int result=9; FixtureState state; auto& context=state.context; auto session=state.make_session();
    capy::run_async(context.get_executor())(probe(std::move(session),context,server,target,false,4,result));
    context.restart(); (void)context.run_for(std::chrono::seconds(15)); return result;
}
extern "C" int nexus_test_proxy_uot_slow(unsigned server, unsigned target) {
    using namespace proxy;
    int result=9; FixtureState state; auto& context=state.context; auto session=state.make_session();
    capy::run_async(context.get_executor())(probe(std::move(session),context,server,target,false,5,result));
    context.restart(); (void)context.run_for(std::chrono::seconds(45)); return result;
}
extern "C" int nexus_test_proxy_uot_resume(unsigned server, unsigned target) {
    using namespace proxy;
    int result=9; FixtureState state; auto& context=state.context; auto session=state.make_session();
    capy::run_async(context.get_executor())(probe(std::move(session),context,server,target,false,6,result));
    context.restart(); (void)context.run_for(std::chrono::seconds(45)); return result;
}
extern "C" int nexus_test_proxy_uot_invalid(unsigned server, unsigned target, unsigned mode) {
    using namespace proxy;
    int result=9; FixtureState state; auto& context=state.context; auto session=state.make_session();
    capy::run_async(context.get_executor())(invalid_probe(std::move(session),context,server,target,mode,result));
    context.restart(); (void)context.run_for(std::chrono::seconds(15)); return result;
}
