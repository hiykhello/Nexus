// Private implementation; include after std, nexus.crypto, nexus.rules,
// nexus.dns.message, nexus.dns.cache and nexus.shadowsocks.udp_dispatch imports.
// Caller serializes all methods on one executor and drains before destruction.
#pragma once
#include <boost/capy/buffers.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/udp_socket.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include "corosio_udp_resolve_owner.hpp"

namespace nexus::shadowsocks::detail {
    // Retain this owner across listener replacements. All access is serialized;
    // the owner must outlive every listener and its asynchronous completions.
    class UdpListenerState {
        friend class UdpListener;
        friend class UdpListenerRegistry;
        std::vector<std::uint8_t> key_;
        UdpDispatcher dispatcher_;
        bool attached_=false;
        template<class Policy>
        UdpListenerState(std::span<std::uint8_t const> key,Policy policy,
                         std::size_t sessions=64,std::size_t targets=64,std::size_t pending=64)
            : key_(key.begin(),key.end()),dispatcher_(std::move(policy),sessions,targets,pending,4*1024*1024) {}
    public:
        ~UdpListenerState() { if (attached_) std::terminate(); crypto::cleanse(key_); }
        UdpListenerState(UdpListenerState const&)=delete;
        auto operator=(UdpListenerState const&) -> UdpListenerState& = delete;
    };
    enum class UdpRegistryError { invalid_key, duplicate_key, full };
    // A service must use one registry for all UDP listeners. States cannot be
    // removed while the registry lives: replay protection survives replacement.
    // This does not coordinate separate registries or processes.
    class UdpListenerRegistry {
        std::vector<std::unique_ptr<UdpListenerState>> states_;
        std::size_t capacity_;
    public:
        explicit UdpListenerRegistry(std::size_t capacity) : capacity_(capacity) {}
        UdpListenerRegistry(UdpListenerRegistry const&)=delete;
        auto operator=(UdpListenerRegistry const&) -> UdpListenerRegistry& = delete;
        // All access is serialized. The returned pointer stays owned by this registry.
        [[nodiscard]] auto find(std::span<std::uint8_t const> key) const noexcept -> UdpListenerState* {
            for (auto const& state:states_) if (crypto::constant_time_equal(key,state->key_)) return state.get();
            return nullptr;
        }
        template<class Policy> requires (std::same_as<Policy,rules::Matcher> || std::same_as<Policy,rules::RouteMatcher>)
        [[nodiscard]] auto reconfigure(UdpListenerState& state,Policy policy) noexcept -> bool {
            if (std::ranges::none_of(states_,[&](auto const& candidate) { return candidate.get()==&state; }) || state.attached_)
                return false;
            return state.dispatcher_.replace_policy(std::move(policy));
        }
        template<class Policy> requires (std::same_as<Policy,rules::Matcher> || std::same_as<Policy,rules::RouteMatcher>)
        [[nodiscard]] auto add(std::span<std::uint8_t const> key,Policy policy,
                               std::size_t sessions=64,std::size_t targets=64,std::size_t pending=64)
            -> std::expected<UdpListenerState*,UdpRegistryError> {
            if (key.size()!=16 && key.size()!=32) return std::unexpected(UdpRegistryError::invalid_key);
            for (auto const& state:states_)
                if (crypto::constant_time_equal(key,state->key_)) return std::unexpected(UdpRegistryError::duplicate_key);
            if (states_.size()>=capacity_) return std::unexpected(UdpRegistryError::full);
            auto state=std::unique_ptr<UdpListenerState>(new UdpListenerState(key,std::move(policy),sessions,targets,pending));
            auto result=state.get(); states_.push_back(std::move(state));
            return result;
        }
    };
    struct UdpDnsServer {
        boost::corosio::endpoint endpoint; bool tcp_only=false;
        std::string host; std::optional<std::size_t> resolver;
    };
    struct UdpDnsRule { std::string domain; bool suffix=false; std::size_t server=0; };
    struct UdpDnsRouting {
        std::vector<UdpDnsServer> servers;
        std::vector<UdpDnsRule> rules;
        std::size_t fallback=0;
    };
    class UdpListener {
        using Clock=std::chrono::steady_clock;
        boost::corosio::io_context& context_;
        std::vector<std::unique_ptr<boost::corosio::udp_socket>> sockets_;
        UdpListenerState& state_;
        dns::AddressCache cache_;
        UdpResolveOwner resolver_;
        boost::corosio::endpoint upstream_;
        UdpResolveOptions dns_options_;
        std::optional<UdpDnsRouting> dns_routing_;
        bool started_=false,stopped_=false,timer_active_=false,timer_waiting_=false,attached_=false;
        std::size_t receive_active_=0;
        std::stop_source timer_stop_;
        std::chrono::milliseconds tick_interval_;
        std::size_t send_active_=0;
        static auto wall() -> std::optional<std::uint64_t> {
            auto value=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            if (value<0) return {};
            return static_cast<std::uint64_t>(value);
        }
        static auto peer(boost::corosio::endpoint const& ep) -> std::optional<UdpPeer> {
            UdpPeer out{}; out.port=ep.port();
            if (ep.address().is_v4()) { out.family=4; auto b=ep.address().to_v4().to_bytes(); std::ranges::copy(b,out.address.begin()); }
            else if (ep.address().is_v6()) {
                auto address=ep.address().to_v6();
                if (address.scope_id()!=0) return {};
                out.family=6; auto b=address.to_bytes(); std::ranges::copy(b,out.address.begin());
            }
            else return {};
            return out;
        }
        static auto endpoint(UdpPeer const& p) -> boost::corosio::endpoint {
            if (p.family==4) { boost::corosio::ipv4_address::bytes_type b{}; std::copy_n(p.address.begin(),4,b.begin());
                return {boost::corosio::ipv4_address(b),p.port}; }
            boost::corosio::ipv6_address::bytes_type b{}; std::ranges::copy(p.address,b.begin());
            return {boost::corosio::ipv6_address(b),p.port};
        }
        auto validate_dns() -> bool {
            if (!dns_routing_) return true;
            auto& routing=*dns_routing_;
            if (routing.servers.empty() || routing.servers.size()>64 || routing.rules.size()>256 ||
                routing.fallback>=routing.servers.size()) return false;
            for (auto& server:routing.servers) {
                auto const& ep=server.endpoint;
                if ((!ep.port() && (!server.host.empty() || server.resolver || server.tcp_only)) ||
                    (!ep.address().is_v4() && !ep.address().is_v6()) ||
                    (ep.address().is_v6() && ep.address().to_v6().scope_id()!=0)) return false;
                if (server.host.empty()!=!server.resolver.has_value()) return false;
                if (server.resolver && *server.resolver>=routing.servers.size()) return false;
                if (!server.host.empty()) {
                    auto normalized=rules::normalize_rule({"domain-suffix",server.host});
                    if (!normalized) return false;
                    server.host=std::move(normalized->value);
                }
            }
            for (std::size_t i=0;i<routing.servers.size();++i) {
                auto current=i; std::size_t depth=0;
                while (routing.servers[current].resolver) {
                    if (++depth>=routing.servers.size()) return false;
                    current=*routing.servers[current].resolver;
                }
            }
            for (auto& rule:routing.rules) {
                if (rule.server>=routing.servers.size()) return false;
                auto normalized=rules::normalize_rule({"domain-suffix",rule.domain});
                if (!normalized) return false;
                rule.domain=std::move(normalized->value);
            }
            return true;
        }
        auto dns_server(std::span<std::uint8_t const> address) const -> std::size_t {
            std::string name(address.begin()+2,address.end()-2);
            for (auto& c:name) if (c>='A' && c<='Z') c+=('a'-'A');
            for (auto const& rule:dns_routing_->rules)
                if (name==rule.domain || (rule.suffix && name.size()>rule.domain.size() &&
                    name.ends_with(rule.domain) && name[name.size()-rule.domain.size()-1]=='.')) return rule.server;
            return dns_routing_->fallback;
        }
        auto receive(std::size_t index) -> boost::capy::task<> {
            std::array<std::uint8_t,65536> buffer{};
            while (!stopped_) {
                boost::corosio::endpoint source;
                auto [error,n]=co_await sockets_[index]->recv_from(boost::capy::mutable_buffer(buffer.data(),buffer.size()),source);
                if (stopped_) break;
                if (error) { stop(); break; }
                auto remote=peer(source); auto seconds=wall(); auto now=Clock::now();
                if (!remote || !seconds || n>65535) continue;
                remote->ingress=index;
                auto deadline=now+std::chrono::seconds(10);
                auto pending=state_.dispatcher_.begin(state_.key_,std::span{buffer}.first(n),*remote,now,*seconds,deadline);
                if (!pending) continue;
                auto const& a=pending->address;
                if (a.empty()) { (void)state_.dispatcher_.cancel(pending->token); continue; }
                if (a[0]==3) {
                    if (a.size()<5 || a.size()!=static_cast<std::size_t>(a[1])+4) {
                        (void)state_.dispatcher_.cancel(pending->token); continue;
                    }
                    auto selected=dns_routing_ ? dns_server(a) : 0;
                    std::vector<UdpResolveHop> hops;
                    auto root=selected;
                    if (dns_routing_) {
                        std::vector<std::size_t> chain;
                        while (dns_routing_->servers[root].resolver) {
                            chain.push_back(root); root=*dns_routing_->servers[root].resolver;
                        }
                        for (auto it=chain.rbegin();it!=chain.rend();++it) {
                            auto const& server=dns_routing_->servers[*it];
                            hops.push_back({server.host,server.endpoint.port(),*it+1,server.tcp_only});
                        }
                    }
                    auto upstream=dns_routing_ ? dns_routing_->servers[root].endpoint : upstream_;
                    auto tcp=dns_routing_ ? dns_routing_->servers[root].tcp_only : dns_options_.tcp_only;
                    (void)resolver_.start(std::move(*pending),upstream,root+1,now,deadline,dns_options_.strategy,
                        tcp,dns_options_.disable_cache,dns_options_.edns,std::move(hops));
                } else {
                    if (a[0]!=1 && a[0]!=4) { (void)state_.dispatcher_.cancel(pending->token); continue; }
                    UdpPeer target{}; target.family=a[0]==1 ? 4 : 6;
                    auto size=target.family==4 ? 4u : 16u;
                    if (a.size()!=size+3) { (void)state_.dispatcher_.cancel(pending->token); continue; }
                    std::copy_n(a.begin()+1,size,target.address.begin());
                    target.port=static_cast<std::uint16_t>((static_cast<unsigned>(a[size+1])<<8)|a[size+2]);
                    std::array candidates{target}; (void)state_.dispatcher_.complete(pending->token,candidates,now);
                }
            }
        }
        // A single executor serializes timer ticks with receives and stops.
        auto drive() -> boost::capy::task<> {
            while (!stopped_) {
                timer_waiting_=true;
                auto [error]=co_await boost::corosio::delay(tick_interval_);
                timer_waiting_=false;
                if (stopped_) break;
                if (error || !tick()) { stop(); break; }
            }
        }
        auto send(UdpResponse response) -> boost::capy::task<> {
            auto target=endpoint(response.peer);
            if (response.peer.ingress>=sockets_.size()) co_return;
            (void)co_await sockets_[response.peer.ingress]->send_to(boost::capy::const_buffer(response.wire.data(),response.wire.size()),target);
        }
    public:
        UdpListener(boost::corosio::io_context& context,UdpListenerState& state,
                    boost::corosio::endpoint upstream,std::size_t pending=64,
                    std::chrono::milliseconds tick_interval=std::chrono::milliseconds(5),UdpResolveOptions dns_options={},
                    std::optional<UdpDnsRouting> dns_routing={})
            : context_(context),state_(state),cache_(256),
              resolver_(state.dispatcher_,context,cache_,pending),upstream_(upstream),dns_options_(dns_options),dns_routing_(std::move(dns_routing)),tick_interval_(tick_interval) {}
        // Stop and drain before destruction; releasing the lease earlier would
        // allow another listener to race in-flight operations on the owner.
        ~UdpListener() {
            if (attached_) {
                if (!stopped_ || !drained()) std::terminate();
                state_.attached_=false;
            }
        }
        UdpListener(UdpListener const&)=delete;
        auto operator=(UdpListener const&) -> UdpListener& = delete;
        [[nodiscard]] auto start(boost::corosio::endpoint listen) -> std::error_code {
            return start(std::span{&listen,1});
        }
        // All sockets share a single serialized session/replay owner. The
        // latest authenticated request selects the socket used for replies.
        [[nodiscard]] auto start(std::span<boost::corosio::endpoint const> listens) -> std::error_code {
            if (started_ || stopped_) return std::make_error_code(std::errc::operation_not_permitted);
            if ((state_.key_.size()!=16 && state_.key_.size()!=32) || tick_interval_<=std::chrono::milliseconds::zero() ||
                listens.empty() || listens.size()>16) return std::make_error_code(std::errc::invalid_argument);
            if (state_.attached_) return std::make_error_code(std::errc::operation_not_permitted);
            if (!validate_dns()) return std::make_error_code(std::errc::invalid_argument);
            try {
                for (auto const& listen:listens) {
                    auto socket=std::make_unique<boost::corosio::udp_socket>(context_);
                    if (auto error=socket->open(listen.address().family())) { sockets_.clear(); return error; }
                    if (auto error=socket->bind(listen)) { sockets_.clear(); return error; }
                    sockets_.push_back(std::move(socket));
                }
            } catch (...) { sockets_.clear(); throw; }
            state_.attached_=true; attached_=true; started_=true;
            for (std::size_t i=0;i<sockets_.size();++i) {
                ++receive_active_;
                try { boost::capy::run_async(context_.get_executor(),[this] { --receive_active_; },
                    [this](std::exception_ptr) noexcept { --receive_active_; stop(); })(receive(i)); }
                catch (...) { --receive_active_; stop(); throw; }
            }
            timer_active_=true;
            try { boost::capy::run_async(context_.get_executor(),timer_stop_.get_token(),[this] { timer_active_=false; },
                [this](std::exception_ptr) noexcept { timer_active_=false; stop(); })(drive()); }
            catch (...) { timer_active_=false; stop(); throw; }
            return {};
        }
        [[nodiscard]] auto local_endpoint(std::size_t index=0) const -> boost::corosio::endpoint {
            return sockets_.at(index)->local_endpoint();
        }
    private:
        // At most 16 response sends are pending; excess replies are dropped.
        [[nodiscard]] auto tick() -> bool {
            if (!started_ || stopped_) return false;
            auto now=Clock::now(); auto seconds=wall(); if (!seconds) { stop(); return false; }
            resolver_.cancel_expired(now);
            if (!state_.dispatcher_.expire(now,*seconds)) { stop(); return false; }
            for (unsigned i=0;i<64 && send_active_<16;++i) {
                auto response=state_.dispatcher_.poll(state_.key_,now,*seconds);
                if (!response) {
                    // A relay socket error has already closed that socket. Other
                    // sessions can continue on the next tick.
                    if (std::holds_alternative<UdpRelayFailure>(response.error())) break;
                    stop(); return false;
                }
                if (!*response) break;
                ++send_active_;
                try { boost::capy::run_async(context_.get_executor(),[this] { --send_active_; },
                    [this](std::exception_ptr) noexcept { --send_active_; stop(); })(send(std::move(**response))); }
                catch (...) { --send_active_; stop(); throw; }
            }
            return true;
        }
    public:
        auto stop() noexcept -> void {
            if (stopped_) return;
            stopped_=true; timer_stop_.request_stop(); resolver_.stop(); for (auto& socket:sockets_) socket->close(); if (attached_) state_.dispatcher_.close_relays();
        }
        [[nodiscard]] auto timer_waiting() const noexcept -> bool { return timer_waiting_; }
        [[nodiscard]] auto running() const noexcept -> bool { return started_ && !stopped_; }
        [[nodiscard]] auto relay_sockets() const noexcept -> std::size_t { return state_.dispatcher_.sockets(); }
        [[nodiscard]] auto drained() const noexcept -> bool { return !receive_active_ && !timer_active_ && !send_active_ && resolver_.drained(); }
    };
}
