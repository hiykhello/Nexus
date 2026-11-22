module;
#include <proxy/proxy_macros.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/task.hpp>
#include "../coro/quitter.hpp"
#include <boost/capy/when_all.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/endpoint.hpp>
#ifdef NEXUS_ENABLE_SOCKS_UDP
#include <boost/corosio/delay.hpp>
#endif
#ifdef NEXUS_TEST_UOT_WRITE_RACE
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#endif
#include "../shadowsocks/probe_close.hpp"
module proxy;
import std;
import proxy.v4;
import socks5;
import rules;
import http.connect;
import crypto;
import shadowsocks.replay;
import shadowsocks.identity;
import shadowsocks.key;
import shadowsocks.corosio_server;
import shadowsocks.corosio_inbound;
import shadowsocks.corosio_client;
import sniff.tcp;
import sniff.tcp_io;
import sniff.route_tcp;
import nexus.thirdparty.capy;
import proxy.stream_relay;
import uot;
import net.stream_datagrams;
import net.udp_route;
import net.udp_authorization;
import xudp;
import xudp.client_sessions;
import xudp.client_io;
#ifdef NEXUS_TEST_SS_ABANDON
extern "C" void nexus_test_ss_profile_created();
extern "C" void nexus_test_ss_profile_released();
extern "C" void nexus_test_ss_profile_frame_enter();
extern "C" void nexus_test_ss_profile_frame_exit();
#endif
namespace proxy {
    namespace {
        using Incoming=shadowsocks::detail::InboundStream<io::tcp_socket>;
        auto sniff_ss(void* context,sniff::TcpSniffer& sniffer,Clock::time_point deadline) -> capy::task<sniff::TcpReadResult> {
            auto& incoming=*static_cast<Incoming*>(context);std::array<std::uint8_t,4096> buffer{};
            for(;;) {
                auto state=sniffer.limit();
                if(state.status!=sniff::TcpStatus::need_more)co_return {sniff::TcpReadStop::classified,state,{}};
                if(Clock::now()>=deadline)co_return {sniff::TcpReadStop::deadline,state,{}};
                auto result=co_await incoming.read_sniff(std::span(buffer).first(std::min(buffer.size(),sniffer.remaining())),deadline);
                if(!result) {
                    if(result.error()==shadowsocks::detail::ReadError::timeout)co_return {sniff::TcpReadStop::deadline,sniffer.current(),{}};
                    co_return {sniff::TcpReadStop::io_error,sniffer.current(),std::make_error_code(std::errc::io_error)};
                }
                if(!*result)co_return {sniff::TcpReadStop::eof,sniffer.finish(),{}};
                auto fed=sniffer.feed(std::span(buffer).first(*result));
                if(fed.consumed!=*result)co_return {sniff::TcpReadStop::io_error,fed,std::make_error_code(std::errc::protocol_error)};
            }
        }
        struct Profile {
            std::vector<std::uint8_t> key;
            shadowsocks::ReplayTable replay{65536};
            explicit Profile(std::span<std::uint8_t const> value) : key(value.begin(),value.end()) {
#ifdef NEXUS_TEST_SS_ABANDON
                nexus_test_ss_profile_created();
#endif
            }
            ~Profile() { crypto::cleanse(key);
#ifdef NEXUS_TEST_SS_ABANDON
                nexus_test_ss_profile_released();
#endif
            }
        };
        struct IdentityProfile {
            std::vector<std::uint8_t> key;
            std::vector<shadowsocks::detail::TcpIdentityUser> users;
            std::vector<std::string> names;
            explicit IdentityProfile(std::span<std::uint8_t const> identity) : key(identity.begin(),identity.end()) {}
            ~IdentityProfile() {crypto::cleanse(key);}
        };
        // Retain profiles for the process lifetime so destroying and recreating
        // a listener cannot erase live replay records for a reused key.
        auto shared_profile(std::span<std::uint8_t const> key) -> std::expected<Profile*,std::string> {
            static std::mutex mutex;
            static std::vector<std::unique_ptr<Profile>> profiles;
            std::lock_guard lock(mutex);
            for (auto const& profile : profiles)
                if (crypto::constant_time_equal(profile->key,key)) return profile.get();
            if (profiles.size()>=64) return std::unexpected("Shadowsocks 2022 inbound key limit reached");
            auto profile=std::make_unique<Profile>(key);
            auto* result=profile.get();
            profiles.push_back(std::move(profile)); return result;
        }
        struct RelayInbound {
            Incoming& incoming;
            auto read(std::span<std::uint8_t> bytes) {
                return incoming.read(bytes,Clock::now()+std::chrono::seconds(300));
            }
            auto send(std::span<std::uint8_t const> bytes) {
                return incoming.send(bytes,Clock::now()+std::chrono::seconds(300));
            }
            auto close_output() { return incoming.close_output(); }
        };
#ifdef NEXUS_TEST_UOT_WRITE_RACE
        struct UotHooks {
            template<class State>
            static auto after_send(State& state,bool sent) -> nex::capy::task<bool> {
                if (auto gate=std::getenv("NEXUS_TEST_UOT_INBOUND_RACE")) {
                    auto fd=std::atoi(gate);
                    (void)::fcntl(fd,F_SETFL,::fcntl(fd,F_GETFL)|O_NONBLOCK);
                    char release;
                    while (!state.session.closed) {
                        auto n=::read(fd,&release,1);
                        if (n==1) { if (release=='f') sent=false; break; }
                        if (n==0 || (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)) { sent=false; break; }
                        auto [error]=co_await nex::corosio::delay(std::chrono::milliseconds(1));
                        if (error) { sent=false; break; }
                    }
                }
                co_return sent;
            }
            template<class State>
            static auto queue_full(State& state,std::size_t size) -> void {
                if (std::getenv("NEXUS_TEST_UOT_QUEUE_TRACE")) {
                    std::fprintf(stderr,"uot queue full %zu %zu %zu\n",state.pending.size(),state.pending_bytes,size); std::fflush(stderr);
                }
            }
            template<class State>
            static auto reply_pending(State&) -> void {
                if (std::getenv("NEXUS_TEST_UOT_INBOUND_RACE")) { std::fputs("uot inbound reply pending\n",stderr); std::fflush(stderr); }
            }
        };
#else
        using UotHooks=net::stream_datagrams::NoHooks;
#endif
        auto serve(Session& session,io::io_context& context,rules::RouteMatcher const& policy,
                   std::span<std::uint8_t const> key,shadowsocks::ReplayTable* replay,
                   shadowsocks::CipherMethod method,IdentityProfile const* identity=nullptr) -> capy::task<> {
#ifdef NEXUS_TEST_SS_ABANDON
            struct FrameProbe { ~FrameProbe() { nexus_test_ss_profile_frame_exit(); } } probe;
            nexus_test_ss_profile_frame_enter();
#endif
            auto fail=[&] { session.close(); session.done=true; };
            auto users=identity ? std::span<shadowsocks::detail::TcpIdentityUser const>(identity->users) :
                std::span<shadowsocks::detail::TcpIdentityUser const>{};
            auto request=co_await shadowsocks::detail::receive_request(session.client,key,replay,
                                                                        session.started+std::chrono::seconds(10),users,method);
            if (!request || session.closed) {
                if (!session.closed && !request && request.error()==shadowsocks::detail::ServerReadError::invalid_request)
                    (void)shadowsocks::detail::prepare_probe_reset(session.client.native_handle());
                fail(); co_return;
            }
            if (request->user) {
                key=users[*request->user].key;
                if (!session.admit_principal(identity->names[*request->user])) {fail(); co_return;}
            }
            Incoming incoming(session.client,key,std::move(*request));
#ifdef NEXUS_ENABLE_SOCKS_UDP
            auto address=incoming.address();
            if (address.size()==uot::v2_destination.size()+4 && address[0]==3 && address[1]==uot::v2_destination.size() &&
                std::ranges::equal(address.subspan(2,uot::v2_destination.size()),uot::v2_destination) &&
                address[address.size()-2]==0 && address.back()==0) {
                if(session.ordered_tcp && !session.ordered_tcp->udp){fail();co_return;}
                session.relaying=true; session.touched=Clock::now();
                uot::RequestDecoder request;
                std::array<std::uint8_t,260> bytes{};
                std::size_t begin=0,end=0;
                while (!session.closed && !request.request()) {
                    auto received=co_await incoming.read(bytes,Clock::now()+std::chrono::seconds(300));
                    if (!received || !*received || *received>bytes.size()) { fail(); co_return; }
                    auto fed=request.feed(std::span(bytes).first(*received));
                    if (fed.status!=uot::Status::incomplete && fed.status!=uot::Status::accepted) { fail(); co_return; }
                    if (request.request()) { begin=fed.consumed; end=*received; }
                }
                if (session.closed || !request.request()) { fail(); co_return; }
                auto config=*request.request();
                session.begin_traffic(TrafficProtocol::shadowsocks_uot,config.connected ? config.destination.port : 0);
                session.select_traffic_path(ConnectPath::datagrams);
                auto resolver=[&](std::string name,std::uint16_t port,Clock::time_point deadline) {
                    return resolve_udp_domain(session,context,std::move(name),port,deadline);
                };
                auto source=source_endpoint(session,session.ordered_tcp || policy.needs_source() || session.dns_requirements().source);
                auto router=session.ordered_tcp ? ordered_datagram_router(session,context,source) : net::stream_datagrams::OrderedRouter{};
                net::stream_datagrams::Server<Session,Incoming,decltype(resolver),UotHooks> state(session,context,incoming,policy,resolver,
                    {net::AddressWire::uot,config.connected,false},config.destination,source,std::move(router));
                try { (void)co_await capy::when_all(net::stream_datagrams::tasks(state,std::span(bytes).subspan(begin,end-begin))); }
                catch (...) { session.close(); state.cancel(); }
                fail(); co_return;
            }
#endif
            std::vector<std::uint8_t> bytes{5,1,0};
            bytes.insert(bytes.end(),incoming.address().begin(),incoming.address().end());
            auto target=socks5::parse_request(bytes);
            if (target.status!=socks5::Status::accepted) { fail(); co_return; }
            session.begin_traffic(TrafficProtocol::shadowsocks,target.port);
            if(session.ordered_tcp) {
                OrderedTcpRequest route;if(!route.prepare(session,target)){fail();co_return;}
                std::array<std::uint8_t,16384> wire{},scratch{};sniff::TcpSniffer sniffer(wire,scratch);rules::ProgramCursor cursor;
                auto const& ordered=*session.ordered_tcp;auto deadline=session.handshake_deadline;
                auto branch=[&]() -> capy::task<capy::results<OrderedTcpResult>> {
                    auto result=co_await execute_ordered_tcp(session,context,ordered.program,cursor,route.input,sniffer,route.candidates,
                        route.endpoints,ordered.fallback,std::min(deadline,Clock::now()+ordered.sniff_timeout),deadline,ordered.unknown_policy,&incoming,&sniff_ss);
                    co_return capy::results<OrderedTcpResult>{std::make_error_code(std::errc::operation_canceled),std::move(result)};
                };
                auto [signal,result,watch]=co_await capy::when_all(branch(),watch_client_error(session));(void)signal;(void)watch;
                if(session.closed || result.stop!=sniff::RouteTcpStop::terminal || result.code){fail();co_return;}
                sniff::TcpReplay replay(result.first_sent ? std::span<std::uint8_t const>{} : sniffer.wire());if(!co_await replay_ordered_tcp(session,replay,deadline)){fail();co_return;}
            } else {
                auto result=co_await dial(session,context,policy,target);
                if (result || session.closed) { fail(); co_return; }
            }
            session.relaying=true; session.touched=Clock::now();
            RelayInbound relay{incoming};
            try {
                auto first=stream_relay::direction(session,stream_relay::upload(session,relay));
                auto second=stream_relay::direction(session,stream_relay::download(session,relay));
                (void)co_await capy::when_all(std::move(first),std::move(second));
            } catch (...) {
                session.close();
            }
            fail();
        }
    }
    auto make_shadowsocks_inbound_factory(std::span<std::uint8_t const> key,std::span<ShadowsocksUserKey const> users,ShadowsocksCipher cipher)
        -> std::expected<InboundFactory,std::string> {
        if (key.size()!=16 && key.size()!=32) return std::unexpected("invalid Shadowsocks 2022 key length");
        if (cipher==ShadowsocksCipher::chacha20 && (key.size()!=32 || !users.empty()))
            return std::unexpected("ChaCha20 requires a 32-byte key and has no identity headers");
        auto method=cipher==ShadowsocksCipher::chacha20 ? shadowsocks::CipherMethod::chacha20 : shadowsocks::CipherMethod::aes;
        if (!users.empty()) {
            if (users.size()>32) return std::unexpected("too many Shadowsocks users");
            auto profile=std::make_unique<IdentityProfile>(key);
            for (auto const& user:users) {
                if (user.name.empty() || user.name.size()>255 || user.key.size()!=key.size() ||
                    std::ranges::find(profile->names,user.name)!=profile->names.end() ||
                    crypto::constant_time_equal(key,user.key)) return std::unexpected("invalid Shadowsocks user");
                auto hash=shadowsocks::identity_hash(user.key);
                if (std::ranges::find(profile->users,hash,&shadowsocks::detail::TcpIdentityUser::hash)!=profile->users.end())
                    return std::unexpected("duplicate Shadowsocks user key");
                auto owner=shared_profile(user.key);
                if (!owner) return std::unexpected(owner.error());
                profile->users.push_back({(*owner)->key,&(*owner)->replay,hash});
                profile->names.emplace_back(user.name);
            }
            return InboundFactory([profile=std::move(profile)](Session& session,io::io_context& context,rules::RouteMatcher const& policy) {
                return serve(session,context,policy,profile->key,nullptr,shadowsocks::CipherMethod::aes,profile.get());
            });
        }
        auto profile=shared_profile(key);
        if (!profile) return std::unexpected(profile.error());
        return InboundFactory([profile=*profile,method](Session& session,io::io_context& context,rules::RouteMatcher const& policy) {
            return serve(session,context,policy,profile->key,&profile->replay,method);
        });
    }
}
