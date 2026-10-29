module;
#include <proxy/proxy_macros.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/quitter.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/resolver.hpp>
#ifdef NEXUS_ENABLE_SOCKS_UDP
#include <boost/corosio/delay.hpp>
#endif

module nexus.proxy;
import proxy.v4;
import std;
import nexus.socks5;
#ifdef NEXUS_ENABLE_SOCKS_UDP
import nexus.socks5.udp_ingress;
#endif
import nexus.rules;
import nexus.http.connect;


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

namespace nexus::proxy {
    Session::Session(io::io_context& ctx) : client(ctx), target(ctx) {}
    Session::~Session() {
        if (registry) std::erase(*registry,this);
#ifdef NEXUS_TEST_FAKEIP
        // Failure leaves the pool pin held, preventing unsafe reuse.
#ifdef NEXUS_TEST_FAKEIP_ABANDON
        nexus_test_fakeip_owner_check(fakeip && fakeip->sealed());
#endif
        nexus_test_fakeip_session_release(static_cast<bool>(fakeip_target));
        close();
        if (fakeip_target) try { (void)fakeip_target->release(); } catch (...) {}
#endif
    }
    auto Session::close() noexcept -> void {
        closed = true;
        stop.request_stop();
        if (resolver) resolver->cancel();
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
                       Session& session) -> capy::task<bool> {
            while (!buffer.empty()) {
                auto [error, n] = co_await socket.write_some(capy::const_buffer(buffer.data(), buffer.size()));
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

        auto relay(Session& session, bool upstream) -> capy::quitter<bool> {
            if (session.tunnel) {
                // GCC 16 has started a direction twice with a conditional
                // expression containing both co_await calls here.
                if (upstream) co_return co_await session.tunnel->upload();
                co_return co_await session.tunnel->download();
            }
            auto& source = upstream ? session.client : session.target;
            auto& destination = upstream ? session.target : session.client;
            std::array<std::uint8_t, 16384> buffer{};
            for (;;) {
                auto [error, count] = co_await source.read_some(capy::mutable_buffer(buffer.data(), buffer.size()));
                if (error == capy::cond::eof) {
                    (void)destination.shutdown(io::shutdown_send);
                    co_return true;
                }
                if (error || count == 0) co_return false;
                session.touched = Clock::now();
                if (!co_await write_all(destination, std::span(buffer).first(count), session)) co_return false;
            }
        }

        auto relay_direction(Session& session, bool upstream) -> capy::task<capy::results<>> {
            try {
                if (co_await relay(session,upstream)) co_return capy::results<>{};
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
            std::array<std::uint8_t, 2> response{1, static_cast<std::uint8_t>(valid ? 0 : 1)};
            co_return (co_await write_all(session.client, response, session)) && valid;
        }

#ifdef NEXUS_ENABLE_SOCKS_UDP
        auto udp_control(Session& session) -> capy::task<capy::results<>> {
            std::array<std::uint8_t,256> buffer{};
            try {
                while (!session.closed) {
                    auto [error,count]=co_await session.client.read_some(capy::mutable_buffer(buffer.data(),buffer.size()));
                    if (error || !count) break;
                }
                session.close();
                co_return capy::results<>{};
            } catch (...) { session.close(); throw; }
        }
        struct UdpResolution { bool active=false, canceled=false; Clock::time_point deadline{}; };
        auto udp_drive(Session& session, socks5::UdpIngress& ingress, UdpResolution& resolution) -> capy::task<capy::results<>> {
            using namespace std::chrono_literals;
            try {
                while (!session.closed) {
                    auto result=ingress.step();
                    if (!result) { session.close(); break; }
                    if (result->output_error) { session.close(); break; }
                    if (result->forwarded || result->delivered) session.touched=Clock::now();
                    if (resolution.active && !resolution.canceled && Clock::now()>=resolution.deadline) {
                        resolution.canceled=true;
                        if (session.resolver) session.resolver->cancel();
                        if (session.cancel_dns) session.cancel_dns(session.dns_operation);
                    }
                    auto [error]=co_await io::delay(5ms);
                    if (error) { session.close(); break; }
                }
                ingress.close();
                co_return capy::results<>{};
            } catch (...) { ingress.close(); session.close(); throw; }
        }
        auto udp_resolve(Session& session, io::io_context& context, socks5::UdpIngress& ingress,
                         UdpResolution& resolution) -> capy::task<capy::results<>> {
            using namespace std::chrono_literals;
            try {
                while (!session.closed) {
                    auto packet=ingress.pending_domain();
                    if (!packet) {
                        auto [error]=co_await io::delay(5ms);
                        if (error) { session.close(); break; }
                        continue;
                    }
                    auto name=std::string(reinterpret_cast<char const*>(packet->address.data()),packet->address_length);
                    auto port=packet->port;
                    resolution={true,false,Clock::now()+10s};
                    auto endpoints=co_await resolve_udp_domain(session,context,std::move(name),port,resolution.deadline);
                    if (session.closed) break;
                    if (endpoints && !resolution.canceled) {
                        for (auto const& endpoint:*endpoints) {
                            socks5::UdpPeer candidate{endpoint.address().is_v4() ? std::uint8_t{1} : std::uint8_t{4},{},endpoint.port()};
                            if (candidate.address_type==1) {
                                auto bytes=endpoint.address().to_v4().to_bytes(); std::ranges::copy(bytes,candidate.address.begin());
                            } else {
                                auto bytes=endpoint.address().to_v6().to_bytes(); std::ranges::copy(bytes,candidate.address.begin());
                            }
                            while (!session.closed && !resolution.canceled && Clock::now()<resolution.deadline) {
                                auto sent=ingress.send_resolved(candidate);
                                if (sent) { session.touched=Clock::now(); break; }
                                auto error=std::get_if<std::error_code>(&sent.error());
                                if (!error || (*error!=std::errc::resource_unavailable_try_again && *error!=std::errc::interrupted)) break;
                                auto [delay_error]=co_await io::delay(5ms);
                                if (delay_error) { session.close(); break; }
                            }
                            if (!ingress.pending_domain() || session.closed || resolution.canceled) break;
                        }
                    }
                    ingress.discard_domain(); resolution.active=false;
                }
                co_return capy::results<>{};
            } catch (...) { session.close(); throw; }
        }
        auto udp_associate(Session& session, io::io_context& context, rules::RouteMatcher const& policy, socks5::Request const& request) -> capy::task<> {
            auto remote=session.client.remote_endpoint(); auto local=session.client.local_endpoint();
            if (!remote.address().is_v4() || !local.address().is_v4() || (request.address_type!=1 && request.address_type!=4)) {
                (void)co_await reply(session.client,8,{},session); session.close(); session.done=true; co_return;
            }
            socks5::UdpPeer tcp{1,{},remote.port()}, hint{request.address_type,{},request.port};
            auto remote_bytes=remote.address().to_v4().to_bytes();
            std::ranges::copy(remote_bytes,tcp.address.begin());
            std::copy_n(request.address.begin(),request.address_length,hint.address.begin());
            auto association=socks5::UdpAssociation::create(tcp,hint);
            if (!association) { (void)co_await reply(session.client,2,{},session); session.close(); session.done=true; co_return; }
            socks5::UdpIngress ingress(*association,policy,true);
            UdpResolution resolution;
            socks5::UdpPeer bind{1,{},0}; auto local_bytes=local.address().to_v4().to_bytes();
            std::ranges::copy(local_bytes,bind.address.begin());
            auto endpoint=ingress.open(bind);
            if (!endpoint) { (void)co_await reply(session.client,1,{},session); session.close(); session.done=true; co_return; }
            io::ipv4_address::bytes_type bytes{}; std::copy_n(endpoint->address.begin(),4,bytes.begin());
            if (!co_await reply(session.client,0,{io::ipv4_address(bytes),endpoint->port},session)) {
                ingress.close(); session.close(); session.done=true; co_return;
            }
            session.relaying=true;
            try { (void)co_await capy::when_all(udp_control(session),udp_drive(session,ingress,resolution),udp_resolve(session,context,ingress,resolution)); }
            catch (...) { ingress.close(); session.close(); session.done=true; throw; }
            ingress.close(); association->close(); session.close(); session.done=true;
        }
#endif
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
            if (request.command==3) { co_await udp_associate(session,context,policy,request); co_return; }
#endif
            auto code = co_await dial(session, context, policy, request);
            if (code != 0) {
                (void)co_await reply(session.client, code, {}, session);
                fail(); co_return;
            }
            if (!co_await reply(session.client, 0, session.tunnel ? io::endpoint{} : session.target.local_endpoint(), session)) { fail(); co_return; }
            session.relaying = true;
            co_await relay_pair(session);
        }
        auto http_response(Session& session, std::string_view text) -> capy::task<bool> {
            auto bytes = std::span(reinterpret_cast<std::uint8_t const*>(text.data()), text.size());
            co_return co_await write_all(session.client, bytes, session);
        }

        auto http_handshake(Session& session, io::io_context& context,
                            rules::RouteMatcher const& policy, std::uint8_t first) -> capy::task<> {
            auto fail = [&] { session.close(); session.done = true; };
            std::array<std::uint8_t, http::max_connect_header_bytes> buffer{};
            buffer[0] = first;
            std::size_t size = 1, scan = 0;
            http::ConnectRequest parsed;
            for (;;) {
                auto text = std::string_view(reinterpret_cast<char const*>(buffer.data()), size);
                if (text.find("\r\n\r\n", scan) != text.npos || size == buffer.size()) {
                    parsed = http::parse_connect(text);
                    break;
                }
                scan = size > 3 ? size - 3 : 0;
                auto [error, n] = co_await session.client.read_some(capy::mutable_buffer(buffer.data() + size, buffer.size() - size));
                if (error || n == 0) { fail(); co_return; }
                session.touched = Clock::now();
                size += n;
            }
            if (parsed.status == http::ConnectStatus::unsupported) {
                auto text = std::string_view(reinterpret_cast<char const*>(buffer.data()), size);
                if (!text.starts_with("CONNECT ")) {
                    co_await forward_http(session, context, policy, text);
                    co_return;
                }
            }
            if (parsed.status != http::ConnectStatus::accepted) {
                auto response = parsed.status == http::ConnectStatus::too_large ?
                    "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n" :
                    parsed.status == http::ConnectStatus::unsupported ?
                    "HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n" :
                    "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                (void)co_await http_response(session, response);
                fail(); co_return;
            }
            socks5::Request request;
            request.status = socks5::Status::accepted;
            request.port = parsed.port;
            if (parsed.kind == http::HostKind::domain) {
                request.address_type = 3;
                request.address_length = static_cast<std::uint8_t>(parsed.host.size());
                std::copy(parsed.host.begin(), parsed.host.end(), request.address.begin());
            } else {
                request.address_type = parsed.kind == http::HostKind::ipv4 ? 1 : 4;
                request.address_length = parsed.kind == http::HostKind::ipv4 ? 4 : 16;
                std::copy(parsed.address.begin(), parsed.address.end(), request.address.begin());
            }
            auto code = co_await dial(session, context, policy, request);
            if (code != 0) {
                auto response = code == 2 ? "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n" :
                                            "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                (void)co_await http_response(session, response);
                fail(); co_return;
            }
            if (!co_await http_response(session, "HTTP/1.1 200 Connection Established\r\n\r\n")) {
                fail(); co_return;
            }
            auto tail=std::span(buffer).subspan(parsed.consumed, size - parsed.consumed);
            auto sent=session.tunnel ? co_await session.tunnel->send(tail) : co_await write_all(session.target, tail, session);
            if (!sent) { fail(); co_return; }
            session.relaying = true;
            co_await relay_pair(session);
        }

    }

        auto handshake(Session& session, io::io_context& context,
                       rules::RouteMatcher const& policy, bool mixed, std::optional<Credentials> const& credentials) -> capy::task<> {
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
            if (first[0] == 5) co_await socks_handshake(session, context, policy, credentials);
            else if (mixed) co_await http_handshake(session, context, policy, first[0]);
            else { session.close(); session.done = true; }
        }
}
