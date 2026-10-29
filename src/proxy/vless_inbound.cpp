module;
#include <proxy/proxy_macros.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/quitter.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/resolver.hpp>
module nexus.proxy;
import std;
import proxy.v4;
import nexus.socks5;
import nexus.rules;
import nexus.http.connect;
import nexus.vless;
import nexus.vless.server_profile;
import nexus.vless.tls_server;
import nexus.tls.corosio_server_handshake;
import nexus.tls.corosio_application;
import nexus.thirdparty.capy;
#ifdef NEXUS_TEST_VLESS_RELAY_THROW
extern "C" void nexus_test_vless_relay_throw(unsigned);
#endif
#ifdef NEXUS_TEST_VLESS_PROFILE_LIFETIME
extern "C" void nexus_test_vless_profile_enter();
#endif
namespace nexus::proxy {
    namespace {
        using Connection=tls::detail::ApplicationConnection<io::tcp_socket>;
        using Incoming=vless::detail::TlsInbound<io::tcp_socket>;
        struct RelayState {
            Session& session;
            Incoming& incoming;
        };
        auto upload(RelayState& state) -> capy::quitter<bool> {
#ifdef NEXUS_TEST_VLESS_RELAY_THROW
            nexus_test_vless_relay_throw(3);
#endif
            std::array<std::uint8_t,16384> bytes{};
            for (;;) {
                auto n=co_await state.incoming.read(bytes);
                if (!n || state.session.closed) { co_return false; }
                if (!*n) {
                    bool ok=state.session.tunnel ? co_await state.session.tunnel->close_output() :
                        !state.session.target.shutdown(io::shutdown_send);
                    co_return ok;
                }
                state.session.touched=Clock::now();
                if (state.session.tunnel) {
                    if (!co_await state.session.tunnel->send(std::span{bytes}.first(*n))) { co_return false; }
                } else {
                    std::size_t offset=0;
                    while (offset<*n) {
                        auto [error,count]=co_await state.session.target.write_some(capy::const_buffer(bytes.data()+offset,*n-offset));
                        if (error || !count || count>*n-offset || state.session.closed) { co_return false; }
                        offset+=count;
                    }
                }
            }
        }
        auto download(RelayState& state) -> capy::quitter<bool> {
#ifdef NEXUS_TEST_VLESS_RELAY_THROW
            nexus_test_vless_relay_throw(4);
#endif
            std::array<std::uint8_t,16384> bytes{};
            for (;;) {
                std::size_t count=0;
                if (state.session.tunnel) {
                    auto result=co_await state.session.tunnel->read(bytes);
                    if (!result || state.session.closed) { co_return false; }
                    count=*result;
                } else {
                    auto [error,n]=co_await state.session.target.read_some(capy::mutable_buffer(bytes.data(),bytes.size()));
                    if (error==capy::cond::eof) count=0;
                    else if (error || !n || n>bytes.size() || state.session.closed) { co_return false; }
                    else count=n;
                }
                if (!count) { co_return co_await state.incoming.close_output(); }
                state.session.touched=Clock::now();
                if (!co_await state.incoming.send(std::span{bytes}.first(count))) { co_return false; }
            }
        }
        // A failed direction closes the session before the join cancels and
        // drains its sibling. A successful EOF preserves the other direction.
        auto relay_direction(Session& session, capy::quitter<bool> direction) -> capy::task<capy::results<>> {
            try {
                if (co_await std::move(direction)) co_return capy::results<>{};
                session.close();
                co_return capy::results<>{std::make_error_code(std::errc::io_error)};
            } catch (...) {
                session.close();
                throw;
            }
        }
        auto serve(Session& session,io::io_context& context,rules::RouteMatcher const& policy,
                   vless::ServerProfile const& profile) -> capy::task<> {
#ifdef NEXUS_TEST_VLESS_PROFILE_LIFETIME
            nexus_test_vless_profile_enter();
#endif
            auto fail=[&] { session.close(); session.done=true; };
            auto ms=[](Clock::time_point time) { return std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch()).count(); };
            auto start=ms(session.started), deadline=ms(session.started+std::chrono::seconds(10));
            if (start<0 || deadline<=start) { fail(); co_return; }
            // This bounds the handshake's accounted buffers; it is not a
            // complete per-connection memory limit.
            auto budget=std::make_shared<memory::Budget>(8u*1024*1024);
            auto handshake=profile.tls_handshake(start,deadline,budget);
            if (!handshake) { fail(); co_return; }
            auto established=co_await tls::detail::server_handshake(session.client,*handshake);
            if (!established || session.closed) { fail(); co_return; }
            Connection connection(session.client,std::move(established->records),std::move(established->unread));
            if (!established->release_unread_reservation()) { fail(); co_return; }
            auto state=profile.vless_handshake(); if (!state) { fail(); co_return; }
            Incoming incoming(connection,std::move(*state));
            auto request=co_await incoming.read_request();
            if (!request || session.closed) { fail(); co_return; }
            socks5::Request target; target.status=socks5::Status::accepted; target.port=request->port;
            target.address_type=request->kind==vless::AddressKind::ipv4 ? 1 : request->kind==vless::AddressKind::ipv6 ? 4 : 3;
            target.address_length=static_cast<std::uint8_t>(request->address.size());
            std::copy(request->address.begin(),request->address.end(),target.address.begin());
            auto result=co_await dial(session,context,policy,target);
            if (result || session.closed || !(co_await incoming.complete_dial(true))) { fail(); co_return; }
            session.relaying=true; session.touched=Clock::now();
            RelayState relay{session,incoming};
            try {
#ifdef NEXUS_TEST_VLESS_RELAY_THROW
                nexus_test_vless_relay_throw(1);
#endif
                auto first=relay_direction(session,upload(relay));
#ifdef NEXUS_TEST_VLESS_RELAY_THROW
                nexus_test_vless_relay_throw(2);
#endif
                auto second=relay_direction(session,download(relay));
                (void)co_await capy::when_all(std::move(first),std::move(second));
            } catch (...) {
                session.close();
            }
            fail();
        }
    }
    auto make_vless_inbound_factory(std::string_view certificate,std::string_view key,std::span<std::string const> users)
        -> std::expected<InboundFactory,std::string> {
        auto profile=vless::ServerProfile::load(certificate,key,users);
        if (!profile) return std::unexpected(profile.error());
        auto shared=std::make_shared<vless::ServerProfile const>(std::move(*profile));
        return InboundFactory([shared](Session& session,io::io_context& context,rules::RouteMatcher const& policy) {
            return serve(session,context,policy,*shared);
        });
    }
}
