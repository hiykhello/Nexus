module;
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cstring>

module relay;
import :session_internal;
import proxy.v4;
import std;
import rules;
import socks5;
import sniff.tcp;
import sniff.route_tcp;
import net.stream_relay;
import relay.stream_relay;
import capy;
import corosio;
import dns.message;
import relay.request_backend;


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

namespace relay {
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

    namespace session_detail {
        auto HandshakeReader::fill_some() -> capy::task<bool> {
            if (pos == end) {
                pos = 0;
                end = 0;
            } else if (end == buf.size()) {
                if (pos == 0) co_return false;
                auto const rem = end - pos;
                std::memmove(buf.data(), buf.data() + pos, rem);
                pos = 0;
                end = rem;
            }
            int const fd = session.client.native_handle();
            if (fd >= 0) {
                for (;;) {
                    ssize_t const r = ::recv(fd, buf.data() + end, buf.size() - end, MSG_DONTWAIT);
                    if (r > 0) {
                        end += static_cast<std::size_t>(r);
                        session.touched = Clock::now();
                        co_return true;
                    }
                    if (r == 0) co_return false;
                    if (errno == EINTR) continue;
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    co_return false;
                }
            }
            auto [error, n] = co_await session.client.read_some(
                capy::mutable_buffer(buf.data() + end, buf.size() - end));
            if (error || n == 0) co_return false;
            end += n;
            session.touched = Clock::now();
            co_return true;
        }

        auto HandshakeReader::ensure(std::size_t n) -> capy::task<bool> {
            while (avail() < n) {
                if (!co_await fill_some()) co_return false;
            }
            co_return true;
        }

        auto HandshakeReader::read_exact(std::span<std::uint8_t> dst) -> capy::task<bool> {
            while (!dst.empty()) {
                if (avail() == 0 && !co_await fill_some()) co_return false;
                auto const take = std::min(dst.size(), avail());
                std::memcpy(dst.data(), buf.data() + pos, take);
                pos += take;
                dst = dst.subspan(take);
            }
            co_return true;
        }

        auto HandshakeReader::read_byte(std::uint8_t& out) -> capy::task<bool> {
            if (avail() == 0 && !co_await fill_some()) co_return false;
            out = buf[pos++];
            co_return true;
        }

        auto read_exact(io::tcp_socket& socket, std::span<std::uint8_t> buffer,
                        Session& session) -> capy::task<bool> {
            while (!buffer.empty()) {
                if (session.closed) co_return false;
                int const fd = socket.native_handle();
                if (fd >= 0) {
                    ssize_t const r = ::recv(fd, buffer.data(), buffer.size(), MSG_DONTWAIT);
                    if (r > 0) {
                        session.touched = Clock::now();
                        buffer = buffer.subspan(static_cast<std::size_t>(r));
                        continue;
                    }
                    if (r == 0) co_return false;
                    if (errno == EINTR) continue;
                    if (errno != EAGAIN && errno != EWOULDBLOCK) co_return false;
                }
                auto [error, n] = co_await socket.read_some(capy::mutable_buffer(buffer.data(), buffer.size()));
                if (error || n == 0 || session.closed) co_return false;
                session.touched = Clock::now();
                buffer = buffer.subspan(n);
            }
            co_return true;
        }

        auto write_all(io::tcp_socket& socket, std::span<std::uint8_t const> buffer,
                       Session& session,std::optional<bool> payload_direction) -> capy::task<bool> {
#ifdef MSG_NOSIGNAL
            constexpr int kSendFlags = MSG_DONTWAIT | MSG_NOSIGNAL;
#else
            constexpr int kSendFlags = MSG_DONTWAIT;
#endif
            while (!buffer.empty()) {
                if (session.closed) co_return false;
                int const fd = socket.native_handle();
                if (fd >= 0) {
                    ssize_t const w = ::send(fd, buffer.data(), buffer.size(), kSendFlags);
                    if (w > 0) {
                        auto const n = static_cast<std::size_t>(w);
                        if (payload_direction) session.count_traffic(*payload_direction, n);
                        session.touched = Clock::now();
                        buffer = buffer.subspan(n);
                        continue;
                    }
                    if (w < 0 && errno == EINTR) continue;
                    if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) co_return false;
                }
                auto [error, n] = co_await socket.write_some(capy::const_buffer(buffer.data(), buffer.size()));
                if (payload_direction && n) session.count_traffic(*payload_direction,n);
                if (error || n == 0 || session.closed) co_return false;
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

        namespace {
            auto relay_direction(Session& session, bool upstream) -> capy::task<capy::results<>> {
            try {
                if (session.meters_principal_bytes()) {
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

        namespace {
        auto authenticate(Session& session, Credentials const& credentials, HandshakeReader& reader) -> capy::task<bool> {
            std::array<std::uint8_t, 255> username{}, password{};
            std::array<std::uint8_t, 2> header{};
            if (!co_await reader.read_exact(header)) co_return false;
            bool valid = header[0] == 1 && header[1] != 0;
            std::uint8_t user_size = header[1], password_size = 0;
            if (valid) {
                if (!co_await reader.read_exact(std::span(username).first(user_size)) ||
                    !co_await reader.read_byte(password_size)) co_return false;
                valid = password_size != 0;
                if (valid && !co_await reader.read_exact(std::span(password).first(password_size))) co_return false;
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
        }

        auto ordered_connect(Session& session,io::io_context& context,socks5::Request const& request,
            std::span<std::uint8_t const> prefix,ConnectReply response,bool redirect_dns,bool dns_hijack_only) -> capy::task<> {
            auto fail=[&] {session.close();session.done=true;};
            OrderedTcpRequest owner;
            if(!owner.prepare(session,request)) {fail();co_return;}
            if (dns_hijack_only) owner.input.reverse_domain.reset();
            owner.input.dns_hijack_tcp=redirect_dns;
            std::array<std::uint8_t,16384> wire{},scratch{};
            sniff::TcpSniffer sniffer(wire,scratch);
            sniff::TcpPrefetch prefetch;
            if(!prefetch.feed(sniffer,prefix)) {fail();co_return;}
            rules::ProgramCursor cursor;
            auto const& policy=*session.ordered_tcp;
            auto sniff_deadline=std::min(session.handshake_deadline,Clock::now()+policy.sniff_timeout);
            auto branch=[&]() -> capy::task<capy::results<OrderedTcpResult>> {
                OrderedTcpResult result;
                if (dns_hijack_only) {
                    owner.input.route_mode=session.active_route_mode();
                    auto deadline=session.handshake_deadline, sniff_limit=sniff_deadline;
                    for (;;) {
                        if (session.closed) { result={sniff::RouteTcpStop::canceled}; break; }
                        if (Clock::now()>=deadline) { result={sniff::RouteTcpStop::io_error,6}; break; }
                        auto step=co_await sniff::run_tcp_route(policy.program,cursor,owner.input,session.client,sniffer,
                            sniff_limit,true,policy.unknown_policy);
                        if (session.closed) { result={sniff::RouteTcpStop::canceled}; break; }
                        if (step.stop==sniff::RouteTcpStop::options) {
                            if (auto timeout=step.step->action.connect_timeout_ms) {
                                deadline=std::min(deadline,session.started+std::chrono::milliseconds(timeout));
                                sniff_limit=std::min(sniff_limit,deadline);
                            }
                            if (!cursor.complete(*step.step)) { result={sniff::RouteTcpStop::state_error}; break; }
                            continue;
                        }
                        if (step.stop==sniff::RouteTcpStop::terminal &&
                            step.step->action.kind==rules::ProgramActionKind::hijack_dns) {
                            if (auto timeout=step.step->action.connect_timeout_ms)
                                deadline=std::min(deadline,session.started+std::chrono::milliseconds(timeout));
                            result=Clock::now()>=deadline
                                ? OrderedTcpResult{sniff::RouteTcpStop::io_error,6}
                                : OrderedTcpResult{.stop=sniff::RouteTcpStop::terminal,.code=0,.deadline=deadline,.dns_hijacked=true};
                        } else {
                            result={sniff::RouteTcpStop::terminal,2};
                        }
                        break;
                    }
                } else {
                    result=co_await execute_ordered_tcp(session,context,policy.program,cursor,owner.input,sniffer,
                        owner.candidates,owner.endpoints,policy.fallback,sniff_deadline,session.handshake_deadline,policy.unknown_policy);
                }
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
            if (dns_hijack_only) { fail(); co_return; }
            auto code=result.stop==sniff::RouteTcpStop::terminal ? result.code : std::uint8_t{1};
            if(code) {
                if (!result.reject_drop) {
                    if (response==ConnectReply::http) {
                        auto text=code==2 ? "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 10\r\n\r\nForbidden\n" :
                            "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 12\r\n\r\nBad Gateway\n";
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
            if (!session.tunnel && session.direct_shaping_pending() && (!replay_head.empty() || !replay_tail.empty())) {
                if(!co_await replay_shaped_direct(session,replay_head,replay_tail,session.handshake_deadline)){fail();co_return;}
            } else {
                sniff::TcpReplay replay(replay_head,replay_tail);
                if(!co_await replay_ordered_tcp(session,replay,session.handshake_deadline)){fail();co_return;}
            }
            session.relaying=true;
            co_await relay_pair(session);
        }

            namespace {
            [[gnu::noinline]] auto socks_admit(Session& session, io::io_context& context,
                           rules::RouteMatcher const& policy, std::optional<Credentials> const& credentials,
                           HandshakeReader& reader) -> capy::task<bool> {
            auto fail = [&] { session.close(); session.done = true; };
            std::array<std::uint8_t, 262> buffer;
            buffer[0] = 5;
            if (!co_await reader.read_byte(buffer[1])) { fail(); co_return false; }
            auto const methods = std::size_t{buffer[1]};
            if (!co_await reader.read_exact(std::span(buffer).subspan(2, methods))) { fail(); co_return false; }
            auto const method = credentials ? std::uint8_t{2} : std::uint8_t{0};
            auto const greeting = socks5::parse_greeting(std::span(buffer).first(2 + methods), method);
            if (greeting.status == socks5::Status::invalid_version) { fail(); co_return false; }
            std::array<std::uint8_t, 2> selected{5, greeting.status == socks5::Status::accepted ? method : std::uint8_t{255}};
            if (!co_await write_all(session.client, selected, session) || selected[1] == 255) { fail(); co_return false; }
            if (credentials && !co_await authenticate(session, *credentials, reader)) { fail(); co_return false; }
            if (!co_await reader.read_exact(std::span(buffer).first(4))) { fail(); co_return false; }
            auto head = socks5::parse_request(std::span(buffer).first(4)
#ifdef NEXUS_ENABLE_SOCKS_UDP
                                              ,true
#endif
            );
            if (head.status != socks5::Status::incomplete) {
                auto code = head.status == socks5::Status::unsupported_command ? 7 :
                            head.status == socks5::Status::unsupported_address ? 8 : 1;
                (void)co_await reply(session.client, static_cast<std::uint8_t>(code), {}, session);
                fail(); co_return false;
            }
            std::size_t offset = 4;
            std::size_t length = buffer[3] == 1 ? 4 : buffer[3] == 4 ? 16 : 0;
            if (buffer[3] == 3) {
                if (!co_await reader.read_byte(buffer[4])) { fail(); co_return false; }
                length = buffer[4];
                offset = 5;
            }
            if (!co_await reader.read_exact(std::span(buffer).subspan(offset, length + 2))) { fail(); co_return false; }
            auto request = socks5::parse_request(std::span(buffer).first(offset + length + 2)
#ifdef NEXUS_ENABLE_SOCKS_UDP
                                                 ,true
#endif
            );
            if (request.status != socks5::Status::accepted) {
                (void)co_await reply(session.client, 1, {}, session);
                fail(); co_return false;
            }
#ifdef NEXUS_ENABLE_SOCKS_UDP
            if (request.command==3) {
                if(session.ordered_tcp && !session.ordered_tcp->udp) { (void)co_await reply(session.client,7,{},session);fail();co_return false; }
                co_await udp_associate(session,context,policy,request); co_return false;
            }
#endif
            session.begin_traffic(TrafficProtocol::socks5,request.port);
            auto tail = reader.tail();
            if(session.ordered_tcp) {co_await ordered_connect(session,context,request,tail,ConnectReply::socks5);co_return false;}
            bool first_sent = false;
            auto code = co_await dial(session, context, policy, request, Clock::time_point::max(), tail, &first_sent);
            if (code != 0) {
                (void)co_await reply(session.client, code, {}, session);
                fail(); co_return false;
            }
            if (!co_await reply(session.client, 0, session.tunnel ? io::endpoint{} : session.target.local_endpoint(), session)) { fail(); co_return false; }
            if (!first_sent && !tail.empty()) {
                if (session.meters_principal_bytes()) {
                    if (!co_await write_principal_payload(session, true, tail)) { fail(); co_return false; }
                } else {
                    auto sent = session.tunnel ? co_await session.tunnel->send(tail) : co_await write_all(session.target, tail, session, true);
                    if (!sent) { fail(); co_return false; }
                    if (session.tunnel) session.count_traffic(true, tail.size());
                }
            }
            co_return true;
        }

            [[gnu::noinline]] auto handshake_admit(Session& session, io::io_context& context,
                rules::RouteMatcher const& policy, ProxyHandshake mode,
                std::optional<Credentials> const& credentials) -> capy::task<bool> {
                HandshakeReader reader{session};
                std::uint8_t first = 0;
                if (!co_await reader.read_byte(first)) {
                    session.close(); session.done = true; co_return false;
                }
#ifdef NEXUS_TEST_SESSION_THROW
                nexus_test_session_throw(first);
#endif
                if (first==5 && mode!=ProxyHandshake::http)
                    co_return co_await socks_admit(session,context,policy,credentials,reader);
                if (first==4 && mode!=ProxyHandshake::http) {
                    co_await socks4_handshake(session,context,policy,credentials,reader);
                    co_return false;
                }
                if (first!=5 && first!=4 && mode!=ProxyHandshake::socks5) {
                    co_await http_handshake(session,context,policy,first,credentials,reader.tail());
                    co_return false;
                }
                session.close(); session.done = true;
                co_return false;
            }
        }
    }

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
            // HandshakeReader (1 KiB) and SOCKS5 scratch frame destroy before relay_pair begins.
            if (co_await session_detail::handshake_admit(session,context,policy,mode,credentials)) {
                session.relaying = true;
                co_await session_detail::relay_pair(session);
            }
        }
}
