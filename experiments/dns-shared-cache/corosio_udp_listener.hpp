// Private implementation; include after std, crypto, rules,
// nexus.dns.message, nexus.dns.cache and nexus.shadowsocks.udp_dispatch imports.
// Caller serializes all methods on one executor and drains before destruction.
#pragma once
#ifndef NEXUS_DNS_USE_MODULES
#include <boost/capy/buffers.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/udp_socket.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#endif
#include "corosio_udp_resolve_owner.hpp"
#ifdef NEXUS_TEST_UDP_PENDING
extern "C" void nexus_test_udp_pending();
#endif
#ifdef NEXUS_TEST_UDP_SEND_DELAY
extern "C" void nexus_test_udp_send_begin(std::size_t) noexcept;
extern "C" void nexus_test_udp_send_end(std::size_t) noexcept;
extern "C" void nexus_test_udp_send_queue(std::size_t,std::size_t) noexcept;
extern "C" void nexus_test_udp_send_launch();
extern "C" void nexus_test_udp_send_before_write();
#endif

namespace shadowsocks::detail {
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
        udp_io::endpoint endpoint; bool tcp_only=false;
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
        udp_io::io_context& context_;
        std::vector<std::unique_ptr<udp_io::udp_socket>> sockets_;
        UdpListenerState& state_;
#ifndef NEXUS_TEST_DNS_GROUP
        std::optional<dns::AddressCache> owned_cache_;
#endif
        UdpDnsCache& cache_;
        dns::LocalSnapshotSource& local_source_;
        std::size_t local_rotation_=0;
        UdpResolveOwner resolver_;
        udp_io::endpoint upstream_;
        UdpResolveOptions dns_options_;
        std::optional<UdpDnsRouting> dns_routing_;
        bool started_=false,stopped_=false,timer_active_=false,timer_waiting_=false,attached_=false;
        std::size_t receive_active_=0;
        std::stop_source timer_stop_;
        std::chrono::milliseconds tick_interval_;
        // A Corosio UDP socket permits one send and one receive in flight,
        // not multiple sends. Keep an independent bounded FIFO per socket.
        struct Sender {
            std::array<std::optional<UdpResponse>,16> queued;
            std::size_t head=0,count=0;
            bool active=false;
            auto push(UdpResponse response) noexcept -> void {
                queued[(head+count)%queued.size()].emplace(std::move(response)); ++count;
            }
            auto pop() noexcept -> UdpResponse {
                auto result=std::move(*queued[head]); queued[head].reset();
                head=(head+1)%queued.size(); --count; return result;
            }
            auto clear() noexcept -> void {
                while (count) { queued[head].reset(); head=(head+1)%queued.size(); --count; }
            }
        };
        static_assert(std::is_nothrow_move_constructible_v<UdpResponse>);
        std::vector<Sender> senders_;
        std::size_t send_active_=0,send_pending_=0;
#ifdef NEXUS_TEST_DNS_GROUP
        static auto select_cache(UdpDnsCache* borrowed) -> UdpDnsCache& {
            if (!borrowed) throw std::invalid_argument("experimental UDP cache required");
            return *borrowed;
        }
#else
        static auto select_cache(std::optional<dns::AddressCache>& owned,dns::AddressCache* borrowed) -> dns::AddressCache& {
            return borrowed ? *borrowed : owned.emplace(256);
        }
#endif
        static auto wall() -> std::optional<std::uint64_t> {
            auto value=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            if (value<0) return {};
            return static_cast<std::uint64_t>(value);
        }
        static auto peer(udp_io::endpoint const& ep) -> std::optional<UdpPeer> {
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
        static auto endpoint(UdpPeer const& p) -> udp_io::endpoint {
            if (p.family==4) { udp_io::ipv4_address::bytes_type b{}; std::copy_n(p.address.begin(),4,b.begin());
                return {udp_io::ipv4_address(b),p.port}; }
            udp_io::ipv6_address::bytes_type b{}; std::ranges::copy(p.address,b.begin());
            return {udp_io::ipv6_address(b),p.port};
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
                    bool absolute=server.host.ends_with('.');
                    auto hostname=server.host;
                    if (absolute) hostname.pop_back();
                    auto normalized=rules::normalize_rule({"domain-suffix",hostname});
                    if (!normalized) return false;
                    server.host=std::move(normalized->value);
                    if (absolute) server.host.push_back('.');
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
        auto receive(std::size_t index) -> udp_capy::task<> {
            std::array<std::uint8_t,65536> buffer{};
            while (!stopped_) {
                udp_io::endpoint source;
                auto [error,n]=co_await sockets_[index]->recv_from(udp_capy::mutable_buffer(buffer.data(),buffer.size()),source);
                if (stopped_) break;
                if (error) { stop(); break; }
                auto remote=peer(source); auto seconds=wall(); auto now=Clock::now();
                if (!remote || !seconds || n>65535) continue;
                remote->ingress=index;
                auto deadline=now+std::chrono::seconds(10);
                auto pending=state_.dispatcher_.begin(state_.key_,std::span{buffer}.first(n),*remote,now,*seconds,deadline);
                if (!pending) continue;
                struct PendingGuard {
                    UdpDispatcher& dispatcher; std::uint64_t token; bool transferred=false;
                    ~PendingGuard() { if (!transferred) (void)dispatcher.cancel(token); }
                } guard{state_.dispatcher_,pending->token};
#ifdef NEXUS_TEST_UDP_PENDING
                nexus_test_udp_pending();
#endif
                auto const& a=pending->address;
                if (a.empty()) continue;
                if (a[0]==3) {
                    if (a.size()<5 || a.size()!=static_cast<std::size_t>(a[1])+4) {
                        continue;
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
                    auto started=resolver_.start(std::move(*pending),upstream,root+1,now,deadline,dns_options_.strategy,
                        tcp,dns_options_.disable_cache,dns_options_.edns,std::move(hops));
                    guard.transferred=started.has_value();
                } else {
                    if (a[0]!=1 && a[0]!=4) continue;
                    UdpPeer target{}; target.family=a[0]==1 ? 4 : 6;
                    auto size=target.family==4 ? 4u : 16u;
                    if (a.size()!=size+3) continue;
                    std::copy_n(a.begin()+1,size,target.address.begin());
                    target.port=static_cast<std::uint16_t>((static_cast<unsigned>(a[size+1])<<8)|a[size+2]);
                    std::array candidates{target}; (void)state_.dispatcher_.complete(pending->token,candidates,now);
                }
            }
        }
        // A single executor serializes timer ticks with receives and stops.
        auto drive() -> udp_capy::task<> {
            while (!stopped_) {
                timer_waiting_=true;
                auto [error]=co_await udp_io::delay(tick_interval_);
                timer_waiting_=false;
                if (stopped_) break;
                if (error || !tick()) { stop(); break; }
            }
        }
        auto send(std::size_t index) -> udp_capy::task<> {
            auto& sender=senders_[index];
            while (!stopped_ && sender.count) {
                auto response=sender.pop();
                struct PendingGuard { std::size_t& count; ~PendingGuard() { --count; } } guard{send_pending_};
#ifdef NEXUS_TEST_UDP_SEND_DELAY
                nexus_test_udp_send_begin(index);
                struct SendGuard { std::size_t index; ~SendGuard() { nexus_test_udp_send_end(index); } } observed{index};
                (void)co_await udp_io::delay(std::chrono::milliseconds(20));
                if (stopped_) continue;
                nexus_test_udp_send_before_write();
#endif
                auto target=endpoint(response.peer);
                (void)co_await sockets_[index]->send_to(udp_capy::const_buffer(response.wire.data(),response.wire.size()),target);
            }
        }
        auto send_done(std::size_t index,bool failed) noexcept -> void {
            senders_[index].active=false; --send_active_;
            if (failed) { stop(); return; }
            // A completion callback can be scheduled after the worker has
            // observed an empty queue, while another task enqueues a reply.
            if (!stopped_ && senders_[index].count) {
                try { start_send(index); } catch (...) { stop(); }
            }
        }
        auto start_send(std::size_t index) -> void {
            senders_[index].active=true; ++send_active_;
            try {
#ifdef NEXUS_TEST_UDP_SEND_DELAY
                nexus_test_udp_send_launch();
#endif
                udp_capy::run_async(context_.get_executor(),[this,index] { send_done(index,false); },
                [this,index](std::exception_ptr) noexcept { send_done(index,true); })(send(index)); }
            catch (...) { senders_[index].active=false; --send_active_; throw; }
        }
    public:
        UdpListener(udp_io::io_context& context,UdpListenerState& state,
                    udp_io::endpoint upstream,std::size_t pending=64,
                    std::chrono::milliseconds tick_interval=std::chrono::milliseconds(5),UdpResolveOptions dns_options={},
                    std::optional<UdpDnsRouting> dns_routing={},UdpDnsCache* borrowed_cache=nullptr,UdpDnsCache::Reader* reader=nullptr
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
                    ,UdpDnsRefresh* refresh=nullptr
#endif
#ifdef NEXUS_TEST_DNS_COORDINATOR
                    ,dns_hp_experiment::CoordinatorOwner* coordinator=nullptr,dns_hp_experiment::ViewBinding* views=nullptr,bool optimistic=false
#endif
                    )
            : context_(context),state_(state),
#ifdef NEXUS_TEST_DNS_GROUP
              cache_(select_cache(borrowed_cache)),
#else
              cache_(select_cache(owned_cache_,borrowed_cache)),
#endif
              local_source_(dns::system_local_snapshots()),
              resolver_(state.dispatcher_,context,cache_,pending,&local_source_,&local_rotation_,reader
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
                  ,refresh
#endif
#ifdef NEXUS_TEST_DNS_COORDINATOR
                  ,coordinator,views,optimistic
#endif
              ),upstream_(upstream),dns_options_(dns_options),dns_routing_(std::move(dns_routing)),tick_interval_(tick_interval) {}
        // A borrowed cache must outlive this listener and its completions. All
        // its users must share one executor and identical DNS view assignments.
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
        [[nodiscard]] auto start(udp_io::endpoint listen) -> std::error_code {
            return start(std::span{&listen,1});
        }
        // All sockets share a single serialized session/replay owner. The
        // latest authenticated request selects the socket used for replies.
        [[nodiscard]] auto start(std::span<udp_io::endpoint const> listens) -> std::error_code {
            if (started_ || stopped_) return std::make_error_code(std::errc::operation_not_permitted);
            if ((state_.key_.size()!=16 && state_.key_.size()!=32) || tick_interval_<=std::chrono::milliseconds::zero() ||
                listens.empty() || listens.size()>16) return std::make_error_code(std::errc::invalid_argument);
            if (state_.attached_) return std::make_error_code(std::errc::operation_not_permitted);
            if (!validate_dns()) return std::make_error_code(std::errc::invalid_argument);
            try {
                for (auto const& listen:listens) {
                    auto socket=std::make_unique<udp_io::udp_socket>(context_);
                    if (auto error=socket->open(listen.address().family())) { sockets_.clear(); return error; }
                    if (auto error=socket->bind(listen)) { sockets_.clear(); return error; }
                    sockets_.push_back(std::move(socket));
                }
                senders_.resize(sockets_.size());
            } catch (...) { sockets_.clear(); throw; }
            state_.attached_=true; attached_=true; started_=true;
            for (std::size_t i=0;i<sockets_.size();++i) {
                ++receive_active_;
                try { udp_capy::run_async(context_.get_executor(),[this] { --receive_active_; },
                    [this](std::exception_ptr) noexcept { --receive_active_; stop(); })(receive(i)); }
                catch (...) { --receive_active_; stop(); throw; }
            }
            timer_active_=true;
            try { udp_capy::run_async(context_.get_executor(),timer_stop_.get_token(),[this] { timer_active_=false; },
                [this](std::exception_ptr) noexcept { timer_active_=false; stop(); })(drive()); }
            catch (...) { timer_active_=false; stop(); throw; }
            return {};
        }
        [[nodiscard]] auto local_endpoint(std::size_t index=0) const -> udp_io::endpoint {
            return sockets_.at(index)->local_endpoint();
        }
    private:
        // At most 16 responses are being sent or waiting across all sockets.
        [[nodiscard]] auto tick() -> bool {
            if (!started_ || stopped_) return false;
            auto now=Clock::now(); auto seconds=wall(); if (!seconds) { stop(); return false; }
            resolver_.cancel_expired(now);
            if (!state_.dispatcher_.expire(now,*seconds)) { stop(); return false; }
            for (unsigned i=0;i<64 && send_pending_<16;++i) {
                auto response=state_.dispatcher_.poll(state_.key_,now,*seconds);
                if (!response) {
                    // A relay socket error has already closed that socket. Other
                    // sessions can continue on the next tick.
                    if (std::holds_alternative<UdpRelayFailure>(response.error())) break;
                    stop(); return false;
                }
                if (!*response) break;
                auto index=(**response).peer.ingress;
                if (index>=senders_.size()) continue;
                auto& sender=senders_[index];
                sender.push(std::move(**response)); ++send_pending_;
#ifdef NEXUS_TEST_UDP_SEND_DELAY
                nexus_test_udp_send_queue(sender.count,send_pending_);
#endif
                if (!sender.active) {
                    try { start_send(index); } catch (...) { stop(); throw; }
                }
            }
            return true;
        }
    public:
        auto stop() noexcept -> void {
            if (stopped_) return;
            stopped_=true; timer_stop_.request_stop(); resolver_.stop();
            for (auto& sender:senders_) { send_pending_-=sender.count; sender.clear(); }
            for (auto& socket:sockets_) socket->close(); if (attached_) state_.dispatcher_.close_relays();
        }
        [[nodiscard]] auto timer_waiting() const noexcept -> bool { return timer_waiting_; }
        [[nodiscard]] auto running() const noexcept -> bool { return started_ && !stopped_; }
        [[nodiscard]] auto relay_sockets() const noexcept -> std::size_t { return state_.dispatcher_.sockets(); }
#ifdef NEXUS_TEST_UDP_PENDING
        [[nodiscard]] auto pending_for_test() const noexcept -> std::size_t { return state_.dispatcher_.pending(); }
#endif
        [[nodiscard]] auto drained() const noexcept -> bool { return !receive_active_ && !timer_active_ && !send_active_ && !send_pending_ && resolver_.drained(); }
    };
}
