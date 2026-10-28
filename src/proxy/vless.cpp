module;
#include <proxy/proxy_macros.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/quitter.hpp>
#include <boost/capy/ex/run.hpp>
#include <boost/capy/ex/async_mutex.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/resolver.hpp>
#include <boost/corosio/timeout.hpp>
#include <boost/corosio/shutdown_type.hpp>

module nexus.proxy;
import proxy.v4;
import std;
import nexus.socks5;
import nexus.rules;
import nexus.http.connect;
import nexus.config;
import nexus.rulefile;
import nexus.vless;
import nexus.tls.client_handshake_io;
import nexus.tls.application_io;
import nexus.tls.corosio_client;
import nexus.vless.corosio_client;

#include "../vless/client_profile.hpp"

namespace nexus::proxy {
    namespace {
        using Profile=vless::detail::ClientProfile;
        using Client=vless::detail::TcpClient<io::tcp_socket>;
        using Relay=vless::detail::DuplexRelay<io::tcp_socket,io::tcp_socket>;
        class VlessTunnel {
            Session& session_;
            io::io_context& context_;
            std::shared_ptr<Profile const> profile_;
            std::unique_ptr<io::resolver> resolver_;
            std::unique_ptr<tls::detail::OwnedClient> owner_;
            std::unique_ptr<Client> client_;
            std::unique_ptr<Relay> relay_;
            std::optional<std::size_t> bootstrap_;
            std::stop_source stop_;
        public:
            VlessTunnel(Session& session, io::io_context& context, std::shared_ptr<Profile const> profile, std::optional<std::size_t> bootstrap)
                : session_(session),context_(context),profile_(std::move(profile)),bootstrap_(bootstrap) {}
            auto cancel() noexcept -> void {
                stop_.request_stop();
                if (resolver_) resolver_->cancel();
                if (relay_) relay_->cancel();
                if (owner_) owner_->cancel();
            }
            auto connect(io::endpoint destination) -> capy::task<TunnelConnectResult> {
                co_return co_await capy::run(stop_.get_token())(connect_impl(destination));
            }
        private:
            auto connect_impl(io::endpoint destination) -> capy::quitter<TunnelConnectResult> {
                std::vector<io::endpoint> endpoints;
                if (bootstrap_) {
                    auto result=co_await resolve_bootstrap(session_,context_,*bootstrap_,profile_->host,profile_->port);
                    if (!result) co_return TunnelConnectResult::retryable;
                    endpoints=std::move(*result);
                } else {
                    resolver_=std::make_unique<io::resolver>(context_);
                    auto [error, resolved]=co_await resolver_->resolve(profile_->host,std::to_string(profile_->port));
                    resolver_.reset();
                    if (error) co_return TunnelConnectResult::retryable;
                    endpoints=std::move(resolved);
                }
                if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                if (endpoints.empty() || endpoints.size()>64) co_return TunnelConnectResult::retryable;
                auto deadline=session_.started+std::chrono::seconds(10);
                auto deadline_ms=std::chrono::duration_cast<std::chrono::milliseconds>(deadline.time_since_epoch()).count();
                for (auto endpoint : endpoints) {
                    if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                    auto now=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
                    auto seconds=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                    if (now<0) co_return TunnelConnectResult::failed;
                    if (deadline_ms<=now) co_return TunnelConnectResult::timeout;
                    auto handshake=profile_->handshake(static_cast<std::uint64_t>(now),static_cast<std::uint64_t>(deadline_ms),seconds);
                    if (!handshake) co_return TunnelConnectResult::retryable;
                    owner_=std::make_unique<tls::detail::OwnedClient>(context_,std::move(*handshake));
                    auto connected=co_await owner_->start(endpoint);
                    if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                    if (!connected) {
                        auto timed_out=connected.error()==tls::detail::AsyncHandshakeError::timeout;
                        owner_.reset(); if (timed_out) co_return TunnelConnectResult::timeout; continue;
                    }
                    auto& connection=*owner_->client()->application();
                    client_=std::make_unique<Client>(connection);
                    vless::TcpRequest request;
                    request.user=profile_->user; request.port=destination.port();
                    auto address=destination.address();
                    if (address.is_v4()) {
                        request.kind=vless::AddressKind::ipv4;
                        auto bytes=address.to_v4().to_bytes(); request.address.assign(bytes.begin(),bytes.end());
                    } else {
                        request.kind=vless::AddressKind::ipv6;
                        auto bytes=address.to_v6().to_bytes(); request.address.assign(bytes.begin(),bytes.end());
                    }
#ifdef NEXUS_TEST_VLESS_PARTIAL_REQUEST
                    std::expected<void,vless::detail::ClientError> sent;
                    if (std::getenv("NEXUS_TEST_VLESS_PARTIAL_REQUEST")) {
                        auto header=vless::encode_tcp_request(request);
                        if (!header || !co_await connection.send_all(std::span{*header}.first(8),deadline))
                            co_return TunnelConnectResult::failed;
                        sent=std::unexpected(vless::detail::ClientError::tls);
                    } else sent=co_await client_->start(request,deadline);
#else
                    auto sent=co_await client_->start(request,deadline);
#endif
                    if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                    if (!sent) co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                    relay_=std::make_unique<Relay>(session_.client,connection,*client_,[this] { session_.touched=Clock::now(); });
                    co_return TunnelConnectResult::connected;
                }
                co_return TunnelConnectResult::retryable;
            }
        public:
            auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
                if (!relay_ || stop_.stop_requested()) co_return false;
                if (bytes.empty()) co_return true;
                co_return co_await relay_->write(bytes);
            }
            auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t,std::string>> {
                if (!relay_ || stop_.stop_requested()) co_return std::unexpected("tunnel closed");
                auto result=co_await relay_->read(bytes);
                if (!result) co_return std::unexpected("tunnel read failed");
                co_return *result;
            }
            auto close_output() -> capy::task<bool> {
                if (!relay_) co_return false;
                co_return co_await relay_->close_output();
            }
            auto upload() -> capy::task<bool> {
                if (!relay_) co_return false;
                co_return co_await relay_->upload();
            }
            auto download() -> capy::task<bool> {
                if (!relay_) co_return false;
                co_return co_await relay_->download();
            }
        };
    }
    auto make_vless_factory(std::string_view host, std::uint16_t port, std::string_view uuid_file,
                            std::string_view server_name, std::string_view ca_file, TlsKeyExchange key_exchange, std::optional<std::size_t> bootstrap)
        -> std::expected<TunnelFactory,std::string> {
        if (key_exchange!=TlsKeyExchange::x25519 && key_exchange!=TlsKeyExchange::x25519_mlkem768 && key_exchange!=TlsKeyExchange::x25519_mlkem768_only)
            return std::unexpected("invalid TLS key exchange");
        auto group=key_exchange==TlsKeyExchange::x25519 ? config::TlsKeyExchange::x25519 :
            key_exchange==TlsKeyExchange::x25519_mlkem768 ? config::TlsKeyExchange::x25519_mlkem768 : config::TlsKeyExchange::x25519_mlkem768_only;
        config::VlessOutbound config{std::string(host),port,std::string(uuid_file),std::string(server_name),std::string(ca_file),group};
        auto profile=Profile::load(config);
        if (!profile) return std::unexpected(profile.error());
        return TunnelFactory([profile=std::make_shared<Profile const>(std::move(*profile)),bootstrap](Session& session,io::io_context& context) {
            return pro::make_proxy<TunnelFacade,VlessTunnel>(session,context,profile,bootstrap);
        });
    }
}
