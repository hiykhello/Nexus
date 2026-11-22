module;
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cstring>
#include <unistd.h>
#include <cerrno>

export module ss_udp.listener;
import std;
import containers.ring_queue;
import platform.socket_options;
import crypto;
import shadowsocks.key;
import shadowsocks.identity;
import rules;
import proxy;
import proxy.principal_limits;
import proxy.session_quota;
import net.udp_socket;
import dns.policy;
import ss_udp.ordered_route;
import ss_udp.ordered_sniff;
export import ss_udp.resolve;

#ifdef NEXUS_TEST_UDP_PENDING
extern "C" void nexus_test_udp_pending();
#endif
#ifdef NEXUS_TEST_UDP_START
extern "C" void nexus_test_udp_attached() noexcept;
#endif
#ifdef NEXUS_TEST_UDP_SEND_DELAY
extern "C" void nexus_test_udp_send_begin(std::size_t) noexcept;
extern "C" void nexus_test_udp_send_end(std::size_t) noexcept;
extern "C" void nexus_test_udp_send_queue(std::size_t,std::size_t) noexcept;
extern "C" void nexus_test_udp_send_launch();
extern "C" void nexus_test_udp_send_before_write();
#endif


export namespace shadowsocks::detail {
#include "listener_state.hpp"
#include "listener_ingress.hpp"
    using UdpDnsServer=UdpResponseServer;
    using UdpDnsRule=policy::DnsRule;
    using UdpDnsRouting=UdpResponseRouting;
    // The sender must consume the token synchronously or transfer it to an
    // independently bounded owner. stop is idempotent, and drained remains
    // false until that owner's tasks have completed; finish releases its
    // routing sessions after drain and is idempotent. Candidate views are valid
    // only in the call; asynchronous work must own the data it needs.
    enum class UdpTunnelReplyResult { delivered,dropped,busy,error };
    using UdpTunnelReplySink=std::function<UdpTunnelReplyResult(UdpSessionHandle const&,UdpPeer,std::span<std::uint8_t const>)>;
    struct UdpOrderedRouting {
        std::shared_ptr<rules::RouteProgram const> program;
        std::size_t fallback=0;
        bool skip_unknown=false;
        std::chrono::milliseconds sniff_timeout{200};
        std::function<bool(std::size_t)> allows;
        std::function<std::expected<void,UdpResolveError>(udp_io::io_context&,UdpDispatcher&,std::uint64_t,std::size_t,
            std::span<UdpPeer const>,std::optional<std::string_view>,std::chrono::steady_clock::time_point,UdpTunnelReplySink)> send;
        std::function<void()> stop;
        std::function<bool()> drained;
        std::function<void()> finish;
    };
#include "listener_traffic.hpp"
    template<class Lookup>
    class BasicUdpListener {
        using Clock=std::chrono::steady_clock;
        using Cache=typename Lookup::Cache;
        using OwnedCache=std::conditional_t<std::same_as<Cache,dns::AddressCache>,std::optional<dns::AddressCache>,std::monostate>;
        udp_io::io_context& context_;
        UdpListenerIngress* ingress_;
        std::uint64_t generation_;
        std::vector<udp_io::endpoint> endpoints_;
        std::span<std::optional<UdpIdentityRoute> const> identities_;
        std::vector<std::stop_source> receive_stops_;
        std::vector<std::unique_ptr<udp_io::udp_socket>> sockets_;
        // Borrowed policies remain stable until the listener and all DNS work drain.
        std::span<rules::RouteMatcher const> policies_;
        UdpListenerState& state_;
        std::optional<UdpListenerTraffic> traffic_;
        [[no_unique_address]] OwnedCache owned_cache_;
        Cache& cache_;
        dns::LocalSnapshotSource& local_source_;
        std::size_t local_rotation_=0;
        BasicUdpResolveOwner<Lookup> resolver_;
        udp_io::endpoint upstream_;
        UdpResolveOptions dns_options_;
        std::optional<UdpDnsRouting> dns_routing_;
        std::optional<UdpOrderedRouting> ordered_;
        std::optional<OrderedUdpSniffOwner> sniff_owner_;
#ifdef NEXUS_DNS_RESPONSE
        bool has_response_program_=false;
#endif
        bool started_=false,stopped_=false,timer_active_=false,timer_waiting_=false,attached_=false;
        std::size_t receive_active_=0;
        std::stop_source timer_stop_;
        std::chrono::milliseconds tick_interval_;
        // A Corosio UDP socket permits one send and one receive in flight,
        // not multiple sends. Keep an independent bounded FIFO per socket.
        struct Sender {
            static constexpr std::size_t capacity=16;
            std::array<std::optional<UdpResponse>,capacity> queued;
            containers::RingQueue<capacity> slots;
            bool active=false;

            auto push(UdpResponse response) noexcept -> void {
                queued[slots.tail()].emplace(std::move(response));
                slots.commit();
            }

            auto pop() noexcept -> UdpResponse {
                auto& front=queued[slots.front()];
                auto result=std::move(*front);
                front.reset();
                slots.consume();
                return result;
            }

            auto clear() noexcept -> void {
                while (!slots.empty()) {
                    queued[slots.front()].reset();
                    slots.consume();
                }
            }
        };
        static_assert(std::is_nothrow_move_constructible_v<UdpResponse>);
        std::vector<Sender> senders_;
        std::size_t send_active_=0,send_pending_=0;
        static auto select_cache(OwnedCache& owned,Cache* borrowed) -> Cache& {
            if (borrowed) return *borrowed;
            if constexpr (std::same_as<Cache,dns::AddressCache>) return owned.emplace(256);
            else throw std::invalid_argument("experimental UDP cache required");
        }
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
            for (auto& rule:routing.rules)
                if (!policy::normalize_dns_rule(rule,routing.servers.size())) return false;
            if (!policy::validate_dns_response_tags(routing.rules)) return false;
            if (!policy::validate_dns_concurrency(routing.rules)) return false;
#ifdef NEXUS_DNS_RESPONSE
            has_response_program_=policy::dns_has_response_program(routing.rules);
#endif
            return true;
        }
        auto dns_plan(std::size_t selected) const -> UdpResolvePlan {
            UdpResolvePlan result;
            auto root=selected;
            std::vector<std::size_t> chain;
            while (dns_routing_->servers[root].resolver) {
                chain.push_back(root); root=*dns_routing_->servers[root].resolver;
            }
            for (auto it=chain.rbegin();it!=chain.rend();++it) {
                auto const& server=dns_routing_->servers[*it];
                result.hops.push_back({server.host,server.endpoint.port(),*it+1,server.tcp_only});
            }
            result.upstream=dns_routing_->servers[root].endpoint;
            result.view=root+1;
            result.tcp=dns_routing_->servers[root].tcp_only;
            return result;
        }
#include "listener_route.hpp"
#include "listener_receive.hpp"
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
            while (!stopped_ && !sender.slots.empty()) {
                auto response=sender.pop();
                struct PendingGuard { std::size_t& count; ~PendingGuard() { --count; } } guard{send_pending_};
#ifdef NEXUS_TEST_UDP_SEND_DELAY
                nexus_test_udp_send_begin(index);
                struct SendGuard { std::size_t index; ~SendGuard() { nexus_test_udp_send_end(index); } } observed{index};
                (void)co_await udp_io::delay(std::chrono::milliseconds(20));
                if (stopped_) continue;
                nexus_test_udp_send_before_write();
#endif
                if (traffic_ && !state_.dispatcher_.current(response.session)) continue;
                auto credit=state_.dispatcher_.reserve_bytes(response.session,false,response.payload_size,Clock::now());
                if (!credit) continue;
                auto target=endpoint(response.peer);
                credit->submit();
                auto [error,size]=co_await sockets_[index]->send_to(
                    udp_capy::const_buffer(response.wire.data(),response.wire.size()),target);
                if (!error && size==response.wire.size()) {
                    credit->complete(response.payload_size);
                    state_.dispatcher_.delivered(response.session,false,response.payload_size);
                }
            }
        }
        auto send_done(std::size_t index,bool failed) noexcept -> void {
            senders_[index].active=false; --send_active_;
            if (failed) { stop(); return; }
            // A completion callback can be scheduled after the worker has
            // observed an empty queue, while another task enqueues a reply.
            if (!stopped_ && !senders_[index].slots.empty()) {
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
        // The sender must verify its committed source authorization before
        // calling this sink. It is serialized on the listener executor.
        auto queue_tunnel_reply(UdpSessionHandle const& session,UdpPeer source,std::span<std::uint8_t const> payload)
            -> UdpTunnelReplyResult {
            if(stopped_)return UdpTunnelReplyResult::error;
            if(send_pending_>=16)return UdpTunnelReplyResult::busy;
            auto seconds=wall();if(!seconds)return UdpTunnelReplyResult::error;
            auto response=state_.dispatcher_.tunnel_response(state_.key_,session,source,payload,Clock::now(),*seconds);
            if(!response)return UdpTunnelReplyResult::error;
            if(!*response)return UdpTunnelReplyResult::dropped;
            auto index=(**response).peer.ingress;
            if(index>=senders_.size())return UdpTunnelReplyResult::error;
            auto& sender=senders_[index];sender.push(std::move(**response));++send_pending_;
            if(!sender.active) {
                try {start_send(index);} catch (...) {stop();return UdpTunnelReplyResult::error;}
            }
            return UdpTunnelReplyResult::delivered;
        }
    public:
        BasicUdpListener(udp_io::io_context& context,UdpListenerState& state,
                    udp_io::endpoint upstream,std::size_t pending=64,
                    std::chrono::milliseconds tick_interval=std::chrono::milliseconds(5),UdpResolveOptions dns_options={},
                    std::optional<UdpDnsRouting> dns_routing={},Cache* borrowed_cache=nullptr,
                    typename Lookup::Reader* reader=nullptr,typename Lookup::Extra extra={},std::optional<UdpOrderedRouting> ordered={},
                    UdpListenerIngress* ingress=nullptr,std::uint64_t generation=0)
            : context_(context),ingress_(ingress),generation_(generation),state_(state),cache_(select_cache(owned_cache_,borrowed_cache)),
              local_source_(dns::system_local_snapshots()),
              resolver_(state.dispatcher_,context,cache_,pending,&local_source_,&local_rotation_,reader,extra),
              upstream_(upstream),dns_options_(dns_options),dns_routing_(std::move(dns_routing)),ordered_(std::move(ordered)),tick_interval_(tick_interval) {}
        // A borrowed cache must outlive this listener and its completions. All
        // its users must share one executor and identical DNS view assignments.
        // Stop and drain before destruction; releasing the lease earlier would
        // allow another listener to race in-flight operations on the owner.
        ~BasicUdpListener() {
            if (attached_) {
                if (!stopped_ || !drained()) std::terminate();
                if (ordered_) { try { ordered_->finish(); } catch (...) { std::terminate(); } }
                traffic_.reset();
                state_.attached_=false;
            }
        }
        BasicUdpListener(BasicUdpListener const&)=delete;
        auto operator=(BasicUdpListener const&) -> BasicUdpListener& = delete;
        [[nodiscard]] auto start(udp_io::endpoint listen) -> std::error_code {
            return start(std::span{&listen,1});
        }
        // All sockets share a single serialized session/replay owner. The
        // latest authenticated request selects the socket used for replies.
        [[nodiscard]] auto start(std::span<udp_io::endpoint const> listens,std::span<rules::RouteMatcher const> policies={},
            std::span<proxy::Server* const> traffic_listeners={},std::span<std::optional<UdpIdentityRoute> const> identities={})
            -> std::error_code {
            if (started_ || stopped_) return std::make_error_code(std::errc::operation_not_permitted);
            if ((state_.key_.size()!=16 && state_.key_.size()!=32) || tick_interval_<=std::chrono::milliseconds::zero() ||
                listens.empty() || listens.size()>16 || (!policies.empty() && policies.size()!=listens.size())) return std::make_error_code(std::errc::invalid_argument);
            if (state_.attached_) return std::make_error_code(std::errc::operation_not_permitted);
            if (!traffic_listeners.empty() && traffic_listeners.size()!=listens.size())
                return std::make_error_code(std::errc::invalid_argument);
            if (!identities.empty() && identities.size()!=listens.size())
                return std::make_error_code(std::errc::invalid_argument);
            if (!ingress_ && std::ranges::any_of(identities,[](auto const& identity) {return identity.has_value();}))
                return std::make_error_code(std::errc::invalid_argument);
            if (ordered_ && ((ordered_->program && ordered_->sniff_timeout<=Clock::duration::zero()) || !ordered_->allows || !ordered_->send || !ordered_->stop || !ordered_->drained || !ordered_->finish))
                return std::make_error_code(std::errc::invalid_argument);
            if (!validate_dns()) return std::make_error_code(std::errc::invalid_argument);
            if (ordered_ && ordered_->program) sniff_owner_.emplace(state_.dispatcher_,ordered_->sniff_timeout);
            std::bitset<16> receivers;
            identities_=identities;
            try {
                for (std::size_t index=0;index<listens.size();++index) {
                    auto socket=std::make_unique<udp_io::udp_socket>(context_);
                    auto receiver=bind_socket(*socket,listens[index],identity_route(index)!=nullptr);
                    if (!receiver) {sockets_.clear();return receiver.error();}
                    receivers.set(index,*receiver);
                    sockets_.push_back(std::move(socket));
                }
                if (ingress_) endpoints_.assign(listens.begin(),listens.end());
                receive_stops_.resize(sockets_.size());
                senders_.resize(sockets_.size());
                if (std::ranges::any_of(traffic_listeners,[](auto* listener) {return listener!=nullptr;}))
                    traffic_.emplace(state_.dispatcher_,traffic_listeners,state_.session_limit_);
                register_ingress();
            } catch (...) {
                if (ingress_) ingress_->remove(this);
                sockets_.clear();
                throw;
            }
            policies_=policies;
            state_.attached_=true; attached_=true; started_=true;
#ifdef NEXUS_TEST_UDP_START
            nexus_test_udp_attached();
#endif
            for (std::size_t i=0;i<sockets_.size();++i) {
                if (!receivers.test(i)) continue;
                ++receive_active_;
                try { udp_capy::run_async(context_.get_executor(),receive_stops_[i].get_token(),[this] { --receive_active_; },
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
            if (traffic_) traffic_->maintain(now);
            if (sniff_owner_) {sniff_owner_->tick(now);drain_ordered();now=Clock::now();}
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
                nexus_test_udp_send_queue(sender.slots.size(),send_pending_);
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
            stopped_=true;
            if (ingress_) ingress_->remove(this);
            for (auto& receive : receive_stops_) receive.request_stop();
            timer_stop_.request_stop();
            resolver_.stop();
            if (sniff_owner_) sniff_owner_->stop();
            if (ordered_) { try { ordered_->stop(); } catch (...) { std::terminate(); } }
            for (auto& sender:senders_) { send_pending_-=sender.slots.size(); sender.clear(); }
            for (auto& socket:sockets_) socket->close(); if (attached_) state_.dispatcher_.close_relays();
        }
        [[nodiscard]] auto timer_waiting() const noexcept -> bool { return timer_waiting_; }
        [[nodiscard]] auto running() const noexcept -> bool { return started_ && !stopped_; }
        [[nodiscard]] auto relay_sockets() const noexcept -> std::size_t { return state_.dispatcher_.sockets(); }
#ifdef NEXUS_TEST_UDP_PENDING
        [[nodiscard]] auto pending_for_test() const noexcept -> std::size_t { return state_.dispatcher_.pending(); }
#endif
        [[nodiscard]] auto idle() const noexcept -> bool {
            return !state_.dispatcher_.active() && !send_pending_ && resolver_.drained() &&
                (!sniff_owner_ || sniff_owner_->empty());
        }
        [[nodiscard]] auto drained() const noexcept -> bool {
            if (ordered_) { try { if (!ordered_->drained()) return false; } catch (...) { std::terminate(); } }
            return !receive_active_ && !timer_active_ && !send_active_ && !send_pending_ && resolver_.drained() &&
                (!sniff_owner_ || sniff_owner_->empty());
        }
    };
    using UdpListener=BasicUdpListener<UdpDefaultLookup>;
}
