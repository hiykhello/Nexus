module;
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/netfilter_ipv4.h>
#include <string.h>
#ifdef NEXUS_TEST_UOT_WRITE_RACE
#include <unistd.h>
#include <fcntl.h>
#endif
#include <proxy/proxy_macros.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/capy/task.hpp>
#include "../coro/quitter.hpp"
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#ifdef NEXUS_ENABLE_SOCKS_UDP
#include <boost/corosio/delay.hpp>
#endif

module proxy;
import proxy.v4;
import std;
import proxy.request_backend;
import socks5;
import socks5.udp_ingress;
import socks5.udp_tunnel_authorization;
import uot;
import xudp;
import xudp.client_sessions;
import xudp.client_io;
import rules;
import http.connect;
import http.header;
import sniff.tcp;
import sniff.route_tcp;
import net.stream_relay;
import proxy.stream_relay;
import net.lazy_readers;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import proxy.dns_state;
import dns.message;
import net.datagram_frame;
import sniff.udp_quic;

#include "session_traffic.hpp"


#ifdef NEXUS_TEST_SESSION_THROW
extern "C" void nexus_test_session_throw(std::uint8_t);
#endif
#ifdef NEXUS_TEST_FAKEIP
extern "C" void nexus_test_fakeip_session_release(bool);
#endif
#ifdef NEXUS_TEST_FAKEIP_ABANDON
extern "C" void nexus_test_fakeip_owner_check(bool);
#endif
#ifdef NEXUS_TEST_DNS_OWNER
extern "C" void nexus_test_handshake_borrowed_state(bool);
#endif

namespace proxy {
    auto relay_splice(Session&,bool,bool=false) -> capy::task<std::optional<bool>>;
    Session::Session(io::io_context& ctx) : client(ctx), target(ctx) {}
    Session::~Session() {
        end_traffic();
        if (registry) {
            auto* moved=registry->back();
            (*registry)[registry_index]=moved;
            moved->registry_index=registry_index;
            registry->pop_back(); registry=nullptr;
        }
#ifdef NEXUS_ENABLE_FAKEIP
        // Failure leaves the pool pin held, preventing unsafe reuse.
#ifdef NEXUS_TEST_FAKEIP_ABANDON
        nexus_test_fakeip_owner_check(fakeip && fakeip->sealed());
#endif
#ifdef NEXUS_TEST_FAKEIP
        nexus_test_fakeip_session_release(static_cast<bool>(fakeip_target));
#endif
        close();
        if (fakeip_target) try { (void)fakeip_target->release(); } catch (...) {}
#endif
    }
    auto Session::close() noexcept -> void {
        closed = true;
        stop.request_stop();
        if (cancel_dns) cancel_dns(dns_operation);
        if (tunnel) tunnel->cancel();
        client.close();
        target.close();
    }

    namespace {
        auto read_exact(io::tcp_socket& socket, std::span<std::uint8_t> buffer,
                        Session& session) -> capy::task<bool> {
            while (!buffer.empty()) {
                auto [error, n] = co_await socket.read_some(capy::mutable_buffer(buffer.data(), buffer.size()));
                if (error || n == 0) co_return false;
                session.touched = Clock::now();
                buffer = buffer.subspan(n);
            }
            co_return true;
        }

        auto write_all(io::tcp_socket& socket, std::span<std::uint8_t const> buffer,
                       Session& session,std::optional<bool> payload_direction={}) -> capy::task<bool> {
            while (!buffer.empty()) {
                auto [error, n] = co_await socket.write_some(capy::const_buffer(buffer.data(), buffer.size()));
                if (payload_direction && n) session.count_traffic(*payload_direction,n);
                if (error || n == 0) co_return false;
                session.touched = Clock::now();
                buffer = buffer.subspan(n);
            }
            co_return true;
        }

        auto reply(io::tcp_socket& client, std::uint8_t code, io::endpoint endpoint,
                   Session& session) -> capy::task<bool> {
            std::array<std::uint8_t, 22> bytes{5, code, 0};
            std::size_t size = 0;
            auto const address = endpoint.address();
            if (address.is_v4()) {
                bytes[3] = 1;
                auto raw = address.to_v4().to_bytes();
                std::copy(raw.begin(), raw.end(), bytes.begin() + 4);
                size = 10;
            } else {
                bytes[3] = 4;
                auto raw = address.to_v6().to_bytes();
                std::copy(raw.begin(), raw.end(), bytes.begin() + 4);
                size = 22;
            }
            bytes[size - 2] = static_cast<std::uint8_t>(endpoint.port() >> 8);
            bytes[size - 1] = static_cast<std::uint8_t>(endpoint.port());
            co_return co_await write_all(client, std::span(bytes).first(size), session);
        }

#include "session_direct_relay.hpp"

#include "session_principal_relay.hpp"

        auto relay_direction(Session& session, bool upstream) -> capy::task<capy::results<>> {
            try {
                if (session.principal) {
                    PrincipalClientStream client{session};
                    auto operation=upstream ? stream_relay::upload(session,client) : stream_relay::download(session,client);
                    co_return co_await stream_relay::direction(session,std::move(operation));
                }
                bool ok = false;
                if (session.tunnel) {
                    ok = upstream ? co_await session.tunnel->upload() : co_await session.tunnel->download();
                } else {
                    ok = co_await relay_direct(session, upstream);
                }
                if (ok) {
                    session.mark_half_closed();
                    co_return capy::results<>{};
                }
                session.close();
                co_return capy::results<>{std::make_error_code(std::errc::io_error)};
            } catch (...) {
                session.close();
                throw;
            }
        }

        auto relay_pair(Session& session) -> capy::task<> {
            try {
                (void)co_await capy::when_all(relay_direction(session,true),relay_direction(session,false));
            } catch (...) {
                session.close();
                session.done=true;
                throw;
            }
            session.close();
            session.done=true;
        }

        auto authenticate(Session& session, Credentials const& credentials) -> capy::task<bool> {
            std::array<std::uint8_t, 255> username{}, password{};
            std::array<std::uint8_t, 2> header{};
            if (!co_await read_exact(session.client, header, session)) co_return false;
            bool valid = header[0] == 1 && header[1] != 0;
            std::uint8_t user_size = header[1], password_size = 0;
            if (valid) {
                if (!co_await read_exact(session.client, std::span(username).first(user_size), session) ||
                    !co_await read_exact(session.client, std::span(&password_size, 1), session)) co_return false;
                valid = password_size != 0;
                if (valid && !co_await read_exact(session.client, std::span(password).first(password_size), session)) co_return false;
            }
            unsigned difference = (user_size ^ credentials.username_size) | (password_size ^ credentials.password_size);
            for (std::size_t i = 0; i < username.size(); ++i)
                difference |= (username[i] ^ credentials.username[i]) | (password[i] ^ credentials.password[i]);
            valid = valid && difference == 0;
            if (valid) valid=session.admit_principal(
                std::string_view(reinterpret_cast<char const*>(credentials.username.data()),credentials.username_size));
            std::array<std::uint8_t, 2> response{1, static_cast<std::uint8_t>(valid ? 0 : 1)};
            co_return (co_await write_all(session.client, response, session)) && valid;
        }

#ifdef NEXUS_ENABLE_SOCKS_UDP
        auto udp_control(Session& session,socks5::UdpIngress& ingress) -> capy::task<capy::results<>> {
            std::array<std::uint8_t,256> buffer{};
            try {
                while (!session.closed) {
                    auto [error,count]=co_await session.client.read_some(capy::mutable_buffer(buffer.data(),buffer.size()));
                    if (error || !count) break;
                }
                session.close();
                ingress.wake();
                co_return capy::results<>{};
            } catch (...) { session.close(); ingress.wake(); throw; }
        }
#include "session_udp_tunnel.hpp"
#include "session_udp_route.hpp"
        auto udp_associate(Session& session, io::io_context& context, rules::RouteMatcher const& policy, socks5::Request const& request) -> capy::task<> {
            auto remote=accepted_peer(session.client); auto local=session.client.local_endpoint();
            bool ipv6=remote.address().is_v6();
            if (!remote.port() || local.address().is_v6()!=ipv6 || (request.address_type!=1 && request.address_type!=4) ||
                (ipv6 && (remote.address().to_v6().scope_id() || local.address().to_v6().scope_id()))) {
                (void)co_await reply(session.client,8,{},session); session.close(); session.done=true; co_return;
            }
            socks5::UdpPeer tcp{ipv6 ? std::uint8_t{4} : std::uint8_t{1},{},remote.port()}, hint{request.address_type,{},request.port};
            socks5::UdpPeer bind{tcp.address_type,{},0};
            if (ipv6) {
                auto remote_bytes=remote.address().to_v6().to_bytes(); auto local_bytes=local.address().to_v6().to_bytes();
                std::ranges::copy(remote_bytes,tcp.address.begin()); std::ranges::copy(local_bytes,bind.address.begin());
            } else {
                auto remote_bytes=remote.address().to_v4().to_bytes(); auto local_bytes=local.address().to_v4().to_bytes();
                std::ranges::copy(remote_bytes,tcp.address.begin()); std::ranges::copy(local_bytes,bind.address.begin());
            }
            std::copy_n(request.address.begin(),request.address_length,hint.address.begin());
            auto association=socks5::UdpAssociation::create(tcp,hint);
            if (!association) { (void)co_await reply(session.client,2,{},session); session.close(); session.done=true; co_return; }
            session.begin_traffic(TrafficProtocol::socks_udp,0);
            session.select_traffic_path(ConnectPath::datagrams);
            socks5::UdpIngress ingress(*association,policy,true,true,session.auth_user,
                session.direct_tcp_options ? &session.direct_tcp_options->binding : nullptr,
                session.ordered_tcp && session.ordered_tcp->udp,session.traffic_delivery(),
                {&session,[](void* owner,bool ordered,socks5::UdpSelection const& route) noexcept {
                    static_cast<Session*>(owner)->record_datagram_route(ordered,
                        {socks5::udp_endpoint(route.target),route.outbound,route.rule,route.predicate});
                }});
            if (session.principal) ingress.set_byte_budget(session.principal->bytes());
#ifdef NEXUS_ENABLE_FAKEIP
            if (session.fakeip) {
                ingress.set_destination_filter(session.fakeip, [](void const* context, socks5::UdpPeer const& target) noexcept {
                    auto const& owner=*static_cast<dns::FakeIpShared const*>(context);
                    auto address=std::span(target.address).first(target.address_type==1 ? 4 : 16);
                    try { return bool(dns::validate_fakeip_resolution(owner,address)); }
                    catch (...) { return false; }
                });
            }
#endif
            UotState uot_state;
            UdpResolution resolution;
            auto endpoint=ingress.open(bind);
            if (!endpoint) { (void)co_await reply(session.client,1,{},session); session.close(); session.done=true; co_return; }
            io::endpoint bound;
            if (ipv6) bound={io::ipv6_address(endpoint->address),endpoint->port};
            else {
                io::ipv4_address::bytes_type bytes{}; std::copy_n(endpoint->address.begin(),4,bytes.begin());
                bound={io::ipv4_address(bytes),endpoint->port};
            }
            if (session.udp_advertise.port()) bound={session.udp_advertise.address(),endpoint->port};
            if (!co_await reply(session.client,0,bound,session)) {
                ingress.close(); session.close(); session.done=true; co_return;
            }
            session.relaying=true;
            try {
                std::vector<capy::task<capy::results<>>> tasks;
                tasks.push_back(udp_control(session,ingress));
                tasks.push_back(udp_drive(session,context,ingress,resolution,uot_state));
                tasks.push_back(session.ordered_tcp && session.ordered_tcp->udp ? udp_ordered(session,context,ingress,resolution) : udp_resolve(session,context,ingress,resolution,policy));
                tasks.push_back(uot_sender(session,context,ingress,uot_state));
                if(session.tunnel_factories && !session.tunnel_factories->empty())
                    tasks.push_back(uot_state.readers.run([&session,&ingress,&uot_state](std::size_t index) {
                        return uot_reader(session,ingress,uot_state,index);
                    }));
                (void)co_await capy::when_all(std::move(tasks));
            } catch (...) { uot_state.cancel(); ingress.close(); session.close(); session.done=true; throw; }
            ingress.close(); association->close(); session.close(); session.done=true;
        }
#endif
        enum class ConnectReply { none, socks5, socks4, http };
        auto reply_socks4(io::tcp_socket&, bool, io::endpoint, Session&) -> capy::task<bool>;
        auto ordered_connect(Session& session,io::io_context& context,socks5::Request const& request,
            std::span<std::uint8_t const> prefix,ConnectReply response,bool redirect_dns=false) -> capy::task<> {
            auto fail=[&] {session.close();session.done=true;};
            OrderedTcpRequest owner;
            if(!owner.prepare(session,request)) {fail();co_return;}
            owner.input.dns_hijack_tcp=redirect_dns;
            std::array<std::uint8_t,16384> wire{},scratch{};
            sniff::TcpSniffer sniffer(wire,scratch);
            sniff::TcpPrefetch prefetch;
            if(!prefetch.feed(sniffer,prefix)) {fail();co_return;}
            rules::ProgramCursor cursor;
            auto const& policy=*session.ordered_tcp;
            auto sniff_deadline=std::min(session.handshake_deadline,Clock::now()+policy.sniff_timeout);
            auto branch=[&]() -> capy::task<capy::results<OrderedTcpResult>> {
                auto result=co_await execute_ordered_tcp(session,context,policy.program,cursor,owner.input,sniffer,
                    owner.candidates,owner.endpoints,policy.fallback,sniff_deadline,session.handshake_deadline,policy.unknown_policy);
                co_return capy::results<OrderedTcpResult>{std::make_error_code(std::errc::operation_canceled),std::move(result)};
            };
            auto [signal,result,watch]=co_await capy::when_all(branch(),watch_client_error(session));
            (void)signal;(void)watch;
            if(session.closed){fail();co_return;}
            if (result.dns_hijacked) {
                co_await serve_redirect_dns(session,context,sniffer.wire(),result.deadline);
                fail();
                co_return;
            }
            auto code=result.stop==sniff::RouteTcpStop::terminal ? result.code : std::uint8_t{1};
            if(code) {
                if (!result.reject_drop) {
                    if (response==ConnectReply::http) {
                        auto text=code==2 ? "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n" :
                            "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                        auto bytes=std::span(reinterpret_cast<std::uint8_t const*>(text),std::strlen(text));
                        (void)co_await write_all(session.client,bytes,session);
                    } else if (response==ConnectReply::socks5) {
                        (void)co_await reply(session.client,code,{},session);
                    } else if (response==ConnectReply::socks4) {
                        (void)co_await reply_socks4(session.client,false,{},session);
                    } else if (code==2 && session.client.native_handle()>=0) {
                        ::linger rst{1,0};
                        (void)::setsockopt(session.client.native_handle(),SOL_SOCKET,SO_LINGER,&rst,sizeof(rst));
                    }
                }
                fail();co_return;
            }
            if (response==ConnectReply::http) {
                constexpr std::string_view text="HTTP/1.1 200 Connection Established\r\n\r\n";
                if(!co_await write_all(session.client,{reinterpret_cast<std::uint8_t const*>(text.data()),text.size()},session)){fail();co_return;}
            } else if (response==ConnectReply::socks5 &&
                !co_await reply(session.client,0,session.tunnel ? io::endpoint{} : session.target.local_endpoint(),session)) {
                fail();co_return;
            } else if (response==ConnectReply::socks4 &&
                !co_await reply_socks4(session.client,true,session.tunnel ? io::endpoint{} : session.target.local_endpoint(),session)) {
                fail();co_return;
            }
            auto replay_head=result.first_sent ? std::span<std::uint8_t const>{} : sniffer.wire();
            auto replay_tail=prefetch.tail();
            if (!session.tunnel && session.direct_shaping.pending() && (!replay_head.empty() || !replay_tail.empty())) {
                if(!co_await replay_shaped_direct(session,replay_head,replay_tail,session.handshake_deadline)){fail();co_return;}
            } else {
                sniff::TcpReplay replay(replay_head,replay_tail);
                if(!co_await replay_ordered_tcp(session,replay,session.handshake_deadline)){fail();co_return;}
            }
            session.relaying=true;
            co_await relay_pair(session);
        }

        auto socks_handshake(Session& session, io::io_context& context,
                       rules::RouteMatcher const& policy, std::optional<Credentials> const& credentials) -> capy::task<> {
            auto fail = [&] { session.close(); session.done = true; };
            std::array<std::uint8_t, 262> buffer{};
            buffer[0] = 5;
            if (!co_await read_exact(session.client, std::span(buffer).subspan(1, 1), session)) { fail(); co_return; }
            auto const methods = std::size_t{buffer[1]};
            if (!co_await read_exact(session.client, std::span(buffer).subspan(2, methods), session)) { fail(); co_return; }
            auto const method = credentials ? std::uint8_t{2} : std::uint8_t{0};
            auto const greeting = socks5::parse_greeting(std::span(buffer).first(2 + methods), method);
            if (greeting.status == socks5::Status::invalid_version) { fail(); co_return; }
            std::array<std::uint8_t, 2> selected{5, greeting.status == socks5::Status::accepted ? method : std::uint8_t{255}};
            if (!co_await write_all(session.client, selected, session) || selected[1] == 255) { fail(); co_return; }
            if (credentials && !co_await authenticate(session, *credentials)) { fail(); co_return; }
            if (!co_await read_exact(session.client, std::span(buffer).first(4), session)) { fail(); co_return; }
            auto head = socks5::parse_request(std::span(buffer).first(4)
#ifdef NEXUS_ENABLE_SOCKS_UDP
                                              ,true
#endif
            );
            if (head.status != socks5::Status::incomplete) {
                auto code = head.status == socks5::Status::unsupported_command ? 7 :
                            head.status == socks5::Status::unsupported_address ? 8 : 1;
                (void)co_await reply(session.client, static_cast<std::uint8_t>(code), {}, session);
                fail(); co_return;
            }
            std::size_t offset = 4;
            std::size_t length = buffer[3] == 1 ? 4 : buffer[3] == 4 ? 16 : 0;
            if (buffer[3] == 3) {
                if (!co_await read_exact(session.client, std::span(buffer).subspan(4, 1), session)) { fail(); co_return; }
                length = buffer[4];
                offset = 5;
            }
            if (!co_await read_exact(session.client, std::span(buffer).subspan(offset, length + 2), session)) { fail(); co_return; }
            auto request = socks5::parse_request(std::span(buffer).first(offset + length + 2)
#ifdef NEXUS_ENABLE_SOCKS_UDP
                                                 ,true
#endif
            );
            if (request.status != socks5::Status::accepted) {
                (void)co_await reply(session.client, 1, {}, session);
                fail(); co_return;
            }
#ifdef NEXUS_ENABLE_SOCKS_UDP
            if (request.command==3) {
                if(session.ordered_tcp && !session.ordered_tcp->udp) { (void)co_await reply(session.client,7,{},session);fail();co_return; }
                co_await udp_associate(session,context,policy,request); co_return;
            }
#endif
            session.begin_traffic(TrafficProtocol::socks5,request.port);
            if(session.ordered_tcp) {co_await ordered_connect(session,context,request,{},ConnectReply::socks5);co_return;}
            auto code = co_await dial(session, context, policy, request);
            if (code != 0) {
                (void)co_await reply(session.client, code, {}, session);
                fail(); co_return;
            }
            if (!co_await reply(session.client, 0, session.tunnel ? io::endpoint{} : session.target.local_endpoint(), session)) { fail(); co_return; }
            session.relaying = true;
            co_await relay_pair(session);
        }
#include "session_socks4.hpp"
#include "session_http.hpp"

    }

    #include "session_redirect.hpp"



    auto handshake(Session& session, io::io_context& context,
                       rules::RouteMatcher const& policy, ProxyHandshake mode, std::optional<Credentials> const& credentials) -> capy::task<> {
#ifdef NEXUS_TEST_DNS_OWNER
            struct BorrowProbe {
                rules::RouteMatcher const& policy;
                std::optional<Credentials> const& credentials;
                ~BorrowProbe() {
                    bool valid=false;
                    try {
                        auto result=policy.match({{},"127.0.0.1"});
                        valid=result && *result==1 && credentials && credentials->username_size==4 && credentials->username[0]=='u';
                    } catch (...) {}
                    nexus_test_handshake_borrowed_state(valid);
                }
            } probe{policy,credentials};
#endif
            std::array<std::uint8_t, 1> first{};
            if (!co_await read_exact(session.client, first, session)) {
                session.close(); session.done = true; co_return;
            }
#ifdef NEXUS_TEST_SESSION_THROW
            nexus_test_session_throw(first[0]);
#endif
            if (first[0]==5 && mode!=ProxyHandshake::http)
                co_await socks_handshake(session,context,policy,credentials);
            else if (first[0]==4 && mode!=ProxyHandshake::http)
                co_await socks4_handshake(session,context,policy,credentials);
            else if (first[0]!=5 && first[0]!=4 && mode!=ProxyHandshake::socks5)
                co_await http_handshake(session,context,policy,first[0],credentials);
            else { session.close(); session.done = true; }
        }
}
