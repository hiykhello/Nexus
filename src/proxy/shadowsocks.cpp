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
import nexus.crypto;
import nexus.shadowsocks.corosio_client;
import nexus.shadowsocks.corosio_relay;
namespace nexus::proxy {
    namespace {
        struct Profile {
            std::string host; std::uint16_t port; std::vector<std::uint8_t> key;
            Profile(std::string_view host_,std::uint16_t port_,std::span<std::uint8_t const> key_)
                : host(host_),port(port_),key(key_.begin(),key_.end()) {}
            ~Profile() { crypto::cleanse(key); }
        };
        using Relay=shadowsocks::detail::DuplexRelay<io::tcp_socket,io::tcp_socket>;
        class ShadowsocksTunnel {
            Session& session_; io::io_context& context_; std::shared_ptr<Profile const> profile_;
            std::unique_ptr<io::resolver> resolver_; std::unique_ptr<io::tcp_socket> remote_;
            std::unique_ptr<Relay> relay_; std::optional<std::size_t> bootstrap_; std::stop_source stop_;
        public:
            ShadowsocksTunnel(Session& session,io::io_context& context,std::shared_ptr<Profile const> profile,std::optional<std::size_t> bootstrap)
                : session_(session),context_(context),profile_(std::move(profile)),bootstrap_(bootstrap) {}
            auto cancel() noexcept -> void {
                stop_.request_stop(); if (resolver_) resolver_->cancel(); if (relay_) relay_->cancel(); if (remote_) remote_->cancel();
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
                    auto [error,resolved]=co_await resolver_->resolve(profile_->host,std::to_string(profile_->port));
                    resolver_.reset();
                    if (error) co_return TunnelConnectResult::retryable;
                    endpoints=std::move(resolved);
                }
                if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                if (endpoints.empty() || endpoints.size()>64) co_return TunnelConnectResult::retryable;
                auto deadline=session_.started+std::chrono::seconds(10);
                for (auto endpoint:endpoints) {
                    if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                    if (Clock::now()>=deadline) co_return TunnelConnectResult::retryable;
                    remote_=std::make_unique<io::tcp_socket>(context_);
                    auto operation=remote_->connect(endpoint);
                    auto [connect_error]=co_await io::timeout(std::move(operation),deadline);
                    if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                    if (connect_error || Clock::now()>=deadline) { remote_->close(); remote_.reset(); continue; }
                    std::vector<std::uint8_t> address;
                    if (destination.address().is_v4()) {
                        auto bytes=destination.address().to_v4().to_bytes(); address.push_back(1); address.insert(address.end(),bytes.begin(),bytes.end());
                    } else {
                        auto bytes=destination.address().to_v6().to_bytes(); address.push_back(4); address.insert(address.end(),bytes.begin(),bytes.end());
                    }
                    address.push_back(static_cast<std::uint8_t>(destination.port()>>8)); address.push_back(static_cast<std::uint8_t>(destination.port()));
                    auto started=co_await shadowsocks::detail::start_request(*remote_,profile_->key,address,deadline);
                    if (!started || stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                    relay_=std::make_unique<Relay>(session_.client,*remote_,profile_->key,std::move(*started),[this] { session_.touched=Clock::now(); });
                    co_return TunnelConnectResult::connected;
                }
                co_return TunnelConnectResult::retryable;
            }
        public:
            auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
                if (!relay_ || stop_.stop_requested()) co_return false;
                co_return co_await relay_->write(bytes,Clock::now()+std::chrono::seconds(300));
            }
            auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t,std::string>> {
                if (!relay_ || stop_.stop_requested()) co_return std::unexpected("tunnel closed");
                auto result=co_await relay_->read(bytes,Clock::now()+std::chrono::seconds(300));
                if (!result) co_return std::unexpected("tunnel read failed");
                co_return *result;
            }
            auto close_output() -> capy::task<bool> { if (!relay_) co_return false; co_return co_await relay_->close_output(); }
            auto upload() -> capy::task<bool> { if (!relay_) co_return false; co_return co_await relay_->upload(); }
            auto download() -> capy::task<bool> { if (!relay_) co_return false; co_return co_await relay_->download(); }
        };
    }
    auto make_shadowsocks_factory(std::string_view host,std::uint16_t port,std::span<std::uint8_t const> key,std::optional<std::size_t> bootstrap)
        -> std::expected<TunnelFactory,std::string> {
        if (host.empty() || host.size()>255 || host.find('\0')!=std::string_view::npos || !port || (key.size()!=16 && key.size()!=32))
            return std::unexpected("invalid Shadowsocks 2022 server or key");
        auto profile=std::make_shared<Profile const>(host,port,key);
        return TunnelFactory([profile=std::move(profile),bootstrap](Session& session,io::io_context& context) {
            return pro::make_proxy<TunnelFacade,ShadowsocksTunnel>(session,context,profile,bootstrap);
        });
    }
}
