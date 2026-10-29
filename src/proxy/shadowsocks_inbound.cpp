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
#include "../shadowsocks/probe_close.hpp"
module nexus.proxy;
import std;
import proxy.v4;
import nexus.socks5;
import nexus.rules;
import nexus.http.connect;
import nexus.crypto;
import nexus.shadowsocks.replay;
import nexus.shadowsocks.corosio_server;
import nexus.shadowsocks.corosio_inbound;
import nexus.thirdparty.capy;
namespace nexus::proxy {
    namespace {
        using Incoming=shadowsocks::detail::InboundStream<io::tcp_socket>;
        struct Profile {
            std::vector<std::uint8_t> key;
            shadowsocks::ReplayTable replay{65536};
            explicit Profile(std::span<std::uint8_t const> value) : key(value.begin(),value.end()) {}
            ~Profile() { crypto::cleanse(key); }
        };
        // Retain profiles for the process lifetime so destroying and recreating
        // a listener cannot erase live replay records for a reused key.
        auto shared_profile(std::span<std::uint8_t const> key) -> std::expected<std::shared_ptr<Profile>,std::string> {
            static std::mutex mutex;
            static std::vector<std::shared_ptr<Profile>> profiles;
            std::lock_guard lock(mutex);
            for (auto const& profile : profiles)
                if (crypto::constant_time_equal(profile->key,key)) return profile;
            if (profiles.size()>=64) return std::unexpected("Shadowsocks 2022 inbound key limit reached");
            auto profile=std::make_shared<Profile>(key);
            profiles.push_back(profile); return profile;
        }
        struct RelayState {
            Session& session;
            Incoming& incoming;
        };
        auto upload(RelayState& state) -> capy::quitter<bool> {
            std::array<std::uint8_t,16384> bytes{};
            for (;;) {
                auto n=co_await state.incoming.read(bytes,Clock::now()+std::chrono::seconds(300));
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
                if (!co_await state.incoming.send(std::span{bytes}.first(count),Clock::now()+std::chrono::seconds(300))) { co_return false; }
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
        auto serve(std::shared_ptr<Session> session,io::io_context& context,rules::RouteMatcher const& policy,
                   std::shared_ptr<Profile> profile) -> capy::task<> {
            auto fail=[&] { session->close(); session->done=true; };
            auto request=co_await shadowsocks::detail::receive_request(session->client,profile->key,profile->replay,
                                                                        session->started+std::chrono::seconds(10));
            if (!request || session->closed) {
                if (!session->closed && !request && request.error()==shadowsocks::detail::ServerReadError::invalid_request)
                    (void)shadowsocks::detail::prepare_probe_reset(session->client.native_handle());
                fail(); co_return;
            }
            Incoming incoming(session->client,profile->key,std::move(*request));
            std::vector<std::uint8_t> bytes{5,1,0};
            bytes.insert(bytes.end(),incoming.address().begin(),incoming.address().end());
            auto target=socks5::parse_request(bytes);
            if (target.status!=socks5::Status::accepted) { fail(); co_return; }
            auto result=co_await dial(*session,context,policy,target);
            if (result || session->closed) { fail(); co_return; }
            session->relaying=true; session->touched=Clock::now();
            RelayState relay{*session,incoming};
            try {
                auto first=relay_direction(*session,upload(relay));
                auto second=relay_direction(*session,download(relay));
                (void)co_await capy::when_all(std::move(first),std::move(second));
            } catch (...) {
                session->close();
            }
            fail();
        }
    }
    auto make_shadowsocks_inbound_factory(std::span<std::uint8_t const> key) -> std::expected<InboundFactory,std::string> {
        if (key.size()!=16 && key.size()!=32) return std::unexpected("invalid Shadowsocks 2022 key length");
        auto profile=shared_profile(key);
        if (!profile) return std::unexpected(profile.error());
        return InboundFactory([profile=std::move(*profile)](std::shared_ptr<Session> session,io::io_context& context,rules::RouteMatcher const& policy) {
            return serve(std::move(session),context,policy,profile);
        });
    }
}
