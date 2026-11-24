module;
#include <sys/eventfd.h>
export module endpoint.owner;
import std;
import endpoint.host_dns_types;
import endpoint.config;
import endpoint.credentials;
import endpoint.route_probe;
import platform.socket_options;
import platform.netlink_abi;
import platform.netlink_codec;
import platform.netlink_socket;
import packet.tun_linux;
import packet.tun_network;
import packet.tun_default_policy;
import packet.tun_network_types;
import packet.tun_network_view;
import wireguard;
import wireguard.crypto;
import wireguard.endpoint;
import wireguard.port_types;
import wireguard.port;
import wireguard.tun;
import net.udp_socket;

export namespace endpoint {
    namespace owner_detail {
        inline auto open_eventfd() noexcept -> int { return ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC); }
        inline auto signal_eventfd(int fd) noexcept -> void {
            if (fd < 0) return;
            std::uint64_t one = 1;
            while (platform::netlink_abi::write(fd, &one, sizeof(one)) < 0 &&
                   *platform::netlink_abi::__errno_location() == std::to_underlying(std::errc::interrupted)) {}
        }
        class SignalBlockGuard {
            platform::netlink_abi::sigset_t previous_{};
            bool active_ = false;
        public:
            SignalBlockGuard() noexcept {
                namespace a = platform::netlink_abi;
                a::sigset_t mask{};
                if (a::sigemptyset(&mask)) return;
                for (auto sig : {a::SIGINT, a::SIGTERM, a::SIGHUP}) if (a::sigaddset(&mask, sig)) return;
                active_ = a::pthread_sigmask(a::SIG_BLOCK, &mask, &previous_) == 0;
            }
            ~SignalBlockGuard() {
                if (active_) (void)platform::netlink_abi::pthread_sigmask(platform::netlink_abi::SIG_SETMASK, &previous_, nullptr);
            }
            SignalBlockGuard(SignalBlockGuard const&) = delete;
            auto operator=(SignalBlockGuard const&) -> SignalBlockGuard& = delete;
        };
        struct EmptyDnsMonitor {};
        template<class DnsPolicy> class DnsMonitor {
            using Clock = std::chrono::steady_clock;
            using Failure = typename DnsPolicy::Failure;
            int wake_fd_ = -1;
            int alert_fd_ = -1;
            std::atomic_bool stop_{false};
            std::atomic_bool failed_{false};
            std::atomic_bool descriptor_failed_{false};
            std::optional<Failure> error_;
            std::thread worker_;
            auto close_fds() noexcept -> void {
                if (wake_fd_ >= 0) { (void)platform::netlink_abi::close(wake_fd_); wake_fd_ = -1; }
                if (alert_fd_ >= 0) { (void)platform::netlink_abi::close(alert_fd_); alert_fd_ = -1; }
            }
            auto loop(DnsPolicy& dns) noexcept -> void {
                namespace a = platform::netlink_abi;
                constexpr auto kPollBudget = std::chrono::milliseconds(500);
                unsigned timeouts = 0;
                auto check_once = [&]() noexcept -> bool {
                    try {
                        auto now = Clock::now();
                        auto checked = dns.poll(now, now + kPollBudget);
                        if (checked) { timeouts = 0; return true; }
                        if (stop_.load(std::memory_order_acquire)) return false;
                        if (DnsPolicy::is_timeout(checked.error()) && ++timeouts < 3) return true;
                        error_ = checked.error();
                        failed_.store(true, std::memory_order_release);
                        signal_eventfd(alert_fd_);
                        return false;
                    } catch (...) {
                        descriptor_failed_.store(true, std::memory_order_release);
                        signal_eventfd(alert_fd_);
                        return false;
                    }
                };
                if (!check_once()) return;
                while (!stop_.load(std::memory_order_acquire)) {
                    auto now = Clock::now();
                    auto next = dns.next_poll();
                    auto delay = next <= now ? std::int64_t{0} : std::chrono::ceil<std::chrono::milliseconds>(next - now).count();
                    if (timeouts && delay < 100) delay = 100;
                    if (delay > 250) delay = 250;
                    std::array<a::pollfd, 2> fds{{{dns.native_handle(), a::POLLIN, 0}, {wake_fd_, a::POLLIN, 0}}};
                    int ready = a::poll(fds.data(), fds.size(), static_cast<int>(delay));
                    if (stop_.load(std::memory_order_acquire)) break;
                    if (ready < 0) {
                        if (*a::__errno_location() == std::to_underlying(std::errc::interrupted)) continue;
                        descriptor_failed_.store(true, std::memory_order_release);
                        signal_eventfd(alert_fd_);
                        return;
                    }
                    if (fds[1].revents) break;
                    if (fds[0].revents & (a::POLLERR | a::POLLHUP | a::POLLNVAL)) {
                        if (!check_once()) return;
                        descriptor_failed_.store(true, std::memory_order_release);
                        signal_eventfd(alert_fd_);
                        return;
                    }
                    if (fds[0].revents || Clock::now() >= dns.next_poll()) {
                        if (!check_once()) return;
                    }
                }
            }
        public:
            DnsMonitor() = default;
            ~DnsMonitor() { stop(); }
            DnsMonitor(DnsMonitor const&) = delete;
            auto operator=(DnsMonitor const&) -> DnsMonitor& = delete;
            [[nodiscard]] auto start(DnsPolicy& dns) noexcept -> bool {
                wake_fd_ = open_eventfd();
                alert_fd_ = open_eventfd();
                if (wake_fd_ < 0 || alert_fd_ < 0) { close_fds(); return false; }
                try {
                    SignalBlockGuard block_signals;
                    worker_ = std::thread([this, &dns] { loop(dns); });
                    return true;
                } catch (...) {
                    close_fds();
                    return false;
                }
            }
            auto stop() noexcept -> void {
                stop_.store(true, std::memory_order_release);
                signal_eventfd(wake_fd_);
                if (worker_.joinable()) worker_.join();
                close_fds();
            }
            [[nodiscard]] auto alert_fd() const noexcept -> int { return alert_fd_; }
            [[nodiscard]] auto has_alert() const noexcept -> bool {
                return failed_.load(std::memory_order_acquire) || descriptor_failed_.load(std::memory_order_acquire);
            }
            [[nodiscard]] auto take_error() const noexcept -> std::optional<Failure> {
                if (!failed_.load(std::memory_order_acquire)) return std::nullopt;
                return error_;
            }
            [[nodiscard]] auto descriptor_failed() const noexcept -> bool {
                return descriptor_failed_.load(std::memory_order_acquire);
            }
        };
    }
    struct OuterPolicy {
        Wireguard const* config=nullptr;
        [[nodiscard]] auto allows(net::UdpEndpoint const& peer) const noexcept -> bool { return config && outer_allowed(*config,peer); }
    };
    struct SplitRoutePolicy {};
    template<class NetlinkHooks=platform::netlink::NoHooks,class PortHooks=wireguard::PortNoHooks,class Policy=SplitRoutePolicy,class WireProfile=wireguard::PortStandardWire,class DnsPolicy=NoHostDns>
    class Owner {
        using Clock=std::chrono::steady_clock;
        using Port=wireguard::UdpPort<32,32,2048,1024,PortHooks,OuterPolicy,WireProfile>;
        using Tun=wireguard::LinuxTunPort<Port>;
        using Lease=packet::TunNetworkLease<NetlinkHooks>;
        static constexpr bool default_policy=!std::same_as<Policy,SplitRoutePolicy>;
        static constexpr bool dns_policy=DnsPolicy::enabled;
        [[no_unique_address]] Policy policy_;
        Wireguard const& config_;
        std::expected<Port,wireguard::PortFailure> port_;
        std::optional<Tun> tun_;
        std::optional<Lease> lease_;
        [[no_unique_address]] DnsPolicy dns_;
        bool started_=false,stopped_=false,early_unverified_=false;
        std::uint64_t input_drops_=0;
        static auto options(Wireguard const& config) -> wireguard::PortOptions {
            wireguard::PortOptions result; result.business_packets=config.queue_packets; result.business_bytes=config.queue_bytes; result.require_cookie=config.require_cookie;result.auto_cookie=config.auto_cookie;
            return result;
        }
        static auto profile_matches(Wireguard const& config,WireProfile const& profile) noexcept -> bool {
            if constexpr(std::same_as<WireProfile,wireguard::PortStandardWire>)
                return config.provider_profile==wireguard::Provider::standard && std::ranges::all_of(config.reserved,[](auto byte){return byte==0;});
            else if constexpr(std::same_as<WireProfile,wireguard::ReservedProfile>) {
                auto selected=wireguard::ReservedProfile::create(config.provider_profile,config.reserved);
                return selected && profile==*selected;
            } else return false;
        }
        static auto budget(Clock::time_point deadline) -> std::expected<void,std::string> {
            if constexpr(requires { NetlinkHooks::cancelled(); }) if (NetlinkHooks::cancelled()) return std::unexpected("endpoint startup canceled");
            if (Clock::now()>=deadline) return std::unexpected("endpoint startup deadline expired");
            return {};
        }
        auto early_cleanup() const noexcept -> packet::TunCleanupReport {
            packet::TunCleanupReport result;
            result.device_closed=!tun_ || tun_->native_handle()<0; result.device_removed=!early_unverified_; result.socket_closed=!port_ || port_->native_handle()<0;
            if (early_unverified_) result.add({packet::TunNetworkError::readback,packet::TunNetworkStage::close,{}});
            return result;
        }
        auto policy_cleanup(packet::TunCleanupReport report) const noexcept -> packet::TunCleanupReport {
            if constexpr(default_policy) {
                auto policy=policy_.cleanup();
                if(policy.uncertain || policy.preserved || policy.settings_preserved)report.add({packet::TunNetworkError::ownership,packet::TunNetworkStage::remove_route,{}});
            }
            if constexpr(dns_policy) {
                auto dns=dns_.cleanup();
                if(dns.preserved || dns.uncertain || !dns.descriptors_closed)report.add({packet::TunNetworkError::ownership,packet::TunNetworkStage::close,dns.failure ? dns.failure->system : std::error_code{}});
            }
            return report;
        }
      public:
        // Config and this owner remain stable until run/checked stop finish.
        // The expected is a direct Port member, with no heap/Impl facade.
        Owner(Wireguard const& config,Prepared& material,WireProfile profile={}) : config_(config),port_(profile_matches(config,profile) ? Port::create(material.private_key.view(),options(config),OuterPolicy{&config},std::move(profile)) : std::unexpected(wireguard::PortFailure{.code=wireguard::PortError::configuration})) { material.private_key.clear(); }
        Owner(Owner const&)=delete;
        auto operator=(Owner const&) -> Owner& = delete;
        Owner(Owner&&)=delete;
        auto operator=(Owner&&) -> Owner& = delete;
        ~Owner() {
            // Rules outlive a TUN fd. Exceptional default-policy abandonment
            // therefore receives the same bounded cleanup grace as CLI stop.
            if constexpr(default_policy || dns_policy)(void)stop(Clock::now()+std::chrono::seconds(2));
            else (void)stop(Clock::now());
        }
        [[nodiscard]] auto start(Prepared& material,Clock::time_point deadline,Clock::time_point rollback_deadline) -> std::expected<void,std::string> {
            auto failure=[&](std::string message) -> std::unexpected<std::string> { (void)stop(rollback_deadline); return std::unexpected(std::move(message)); };
            if (started_ || stopped_) return std::unexpected("endpoint owner cannot restart");
            if(config_.default_route!=default_policy)return failure("endpoint owner route-mode mismatch");
            if(!config_.host_dns.valid() || config_.host_dns.enabled()!=dns_policy)return failure("endpoint owner host-dns policy mismatch");
            auto checked=budget(deadline); if (!checked) return failure(checked.error());
            if (!port_) return failure(port_.error().code==wireguard::PortError::configuration ? "invalid endpoint configuration or provider-profile mismatch" : "cannot initialize WireGuard identity");
            if (material.count!=config_.peers.size() || material.count>material.peers.size()) return failure("endpoint credentials are incomplete");
            for (std::size_t i=0;i<material.count;++i) {
                if (config_.peers[i].server && (!material.peers[i].selected || !outer_allowed(config_,*material.peers[i].selected)))
                    return failure("peer endpoint is unresolved or captured");
            }
            std::expected<void,wireguard::PortFailure> opened;
            if (config_.binding.configured()) {
                auto prepare=[&](int fd) noexcept { return platform::apply_socket_binding(fd,config_.binding,true); };
                opened=port_->open(config_.listen,Clock::now(),Clock::time_point::max(),prepare);
            } else opened=port_->open(config_.listen,Clock::now());
            if (!opened) return failure("cannot bind endpoint UDP socket"+(opened.error().system ? ": "+opened.error().system.message() : ""));
            if constexpr(default_policy) {
                auto mark=platform::socket_detail::get<std::uint32_t>(port_->native_handle(),platform::linux_socket_abi::socket_level,platform::linux_socket_abi::mark);
                if(!mark || !config_.binding.routing_mark || *mark!=*config_.binding.routing_mark)return failure("outer UDP routing mark readback failed");
            }
            {
                auto local=port_->local_endpoint(); if (!local) return failure("cannot inspect bound endpoint UDP socket");
                RouteProbe<NetlinkHooks> probe;
                for (std::size_t i=0;i<material.count;++i) if (material.peers[i].selected) {
                    auto selected=probe.inspect(config_,*material.peers[i].selected,*local,deadline);
                    if (!selected) return failure(selected.error());
                }
            }
            for (std::size_t i=0;i<material.count;++i) {
                checked=budget(deadline); if (!checked) return failure(checked.error());
                auto const& peer=config_.peers[i]; auto& prepared=material.peers[i];
                wireguard::EndpointConfig settings{.peer_public=prepared.public_key,.allowed_ips=peer.allowed_ips,.peer=prepared.selected,
                    .mtu=config_.network.mtu,.queue_packets=config_.queue_packets,.queue_bytes=config_.queue_bytes,
                    .persistent_keepalive=std::chrono::seconds(peer.persistent_keepalive_seconds)};
                auto added=port_->add_peer(std::move(settings),prepared.preshared_key.view()); prepared.preshared_key.clear();
                if (!added) return failure("cannot configure peer "+peer.name);
                for (auto const& prefix:peer.allowed_ips) if (!port_->assign_route(*added,prefix)) return failure("cannot assign peer cryptokey route");
            }
            checked=budget(deadline); if (!checked) return failure(checked.error());
            auto device=Tun::emplace_into(tun_,*port_,config_.device,config_.network.mtu);
            if (!device) {
                std::string error="cannot create exclusive endpoint TUN device";
                if (auto problem=std::get_if<packet::TunFailure>(&device.error())) if (auto system=std::get_if<std::error_code>(problem)) error+=": "+system->message();
                return failure(std::move(error));
            }
            auto token=tun_->claim_network(); if (!token) return failure("cannot claim endpoint TUN network ownership");
            auto created=Lease::emplace_into(lease_,std::move(*token),config_.network); if (!created) return failure("cannot construct endpoint network lease");
            auto enabled=lease_->start(deadline,rollback_deadline);
            if (!enabled) return failure(enabled.error().netlink && enabled.error().netlink->code==platform::netlink::Error::canceled ? "endpoint startup canceled" :
                                         enabled.error().netlink && enabled.error().netlink->code==platform::netlink::Error::timeout ? "endpoint startup deadline expired" : "cannot configure endpoint network lease");
            if constexpr(default_policy) {
                packet::TunDefaultOptions settings;settings.mark=*config_.binding.routing_mark;
                auto captured=policy_.start(*lease_,settings,deadline,rollback_deadline);
                if(!captured) {
                    std::string message="cannot establish owned default-route capture and physical outer bypass";
                    auto const& reason=captured.error();
                    if(reason.code==packet::TunPolicyError::conflict)message="default-route tables, priorities or mark are already in use";
                    else if(reason.code==packet::TunPolicyError::unsupported)message="physical routes or links cannot be reproduced safely";
                    else if(reason.code==packet::TunPolicyError::ownership || reason.code==packet::TunPolicyError::drift)message="default-route ownership changed during startup";
                    else if(reason.code==packet::TunPolicyError::readback)message="default-route independent readback mismatch";
                    if(reason.netlink) {
                        if(reason.netlink->code==platform::netlink::Error::canceled)message="endpoint startup canceled";
                        else if(reason.netlink->code==platform::netlink::Error::timeout)message="endpoint startup deadline expired";
                        else if(reason.netlink->system)message+=": "+reason.netlink->system.message();
                    }
                    return failure(std::move(message));
                }
                auto local=port_->local_endpoint();if(!local)return failure("cannot inspect marked outer UDP port");
                RouteProbe<NetlinkHooks> probe;
                for(std::size_t i=0;i<material.count;++i)if(material.peers[i].selected) {
                    auto selected=probe.inspect(config_,*material.peers[i].selected,*local,deadline);
                    if(!selected || (selected->table!=settings.bypass_table && selected->table!=platform::netlink_abi::RT_TABLE_LOCAL))
                        return failure("marked outer UDP route is not the verified physical bypass");
                }
            }
            if constexpr(dns_policy) {
                auto installed=dns_.start(*lease_,config_.host_dns,default_policy,deadline,rollback_deadline);
                if(!installed){std::string message(DnsPolicy::describe(installed.error(),true));if(installed.error().system)message+=": "+installed.error().system.message();return failure(std::move(message));}
            }
            checked=budget(deadline); if (!checked) return failure(checked.error());
            started_=true; return {};
        }
        template<class Cancel> [[nodiscard]] auto run(Cancel cancel) -> std::expected<void,std::string> {
            namespace a=platform::netlink_abi;
            if (!started_ || !tun_ || !port_) return std::unexpected("endpoint is not active");
            static_assert(noexcept(cancel()));
            if constexpr(default_policy)if(!policy_.check())return std::unexpected("endpoint default-route policy changed");
            std::conditional_t<dns_policy,owner_detail::DnsMonitor<DnsPolicy>,owner_detail::EmptyDnsMonitor> dns_monitor;
            if constexpr(dns_policy) {
                if (cancel()) return {};
                if (!dns_monitor.start(dns_)) return std::unexpected("endpoint DNS monitor setup failed");
            }
            while (!cancel()) {
                auto now=Clock::now(); auto progress=tun_->step(now,std::chrono::system_clock::now());
                if (!progress) return std::unexpected("endpoint packet step failed");
                if (progress->device.output_error) return std::unexpected("endpoint TUN output failed");
                if (progress->device.input_error) {
                    auto error=std::get_if<wireguard::PortFailure>(&*progress->device.input_error);
                    if (!error || (error->code!=wireguard::PortError::no_route && error->code!=wireguard::PortError::configuration)) return std::unexpected("endpoint TUN input failed");
                    ++input_drops_;
                }
                short network=static_cast<short>((progress->network.read_paused ? 0 : a::POLLIN)|(progress->network.write_blocked ? a::POLLOUT : 0));
                short device=static_cast<short>((progress->device.input_backpressured ? 0 : a::POLLIN)|(progress->device.output_backpressured ? a::POLLOUT : 0));
                std::array<a::pollfd,2+std::size_t(default_policy)+std::size_t(dns_policy)> descriptors{{{port_->native_handle(),network,0},{tun_->native_handle(),device,0}}};
                if constexpr(default_policy)descriptors[2]={policy_.native_handle(),a::POLLIN,0};
                if constexpr(dns_policy)descriptors[2+std::size_t(default_policy)]={dns_monitor.alert_fd(),a::POLLIN,0};
                auto next=progress->network.next_poll;now=Clock::now();
                auto delay=next<=now ? 0 : std::chrono::ceil<std::chrono::milliseconds>(next-now).count();
                if (cancel()) break;
                int ready=a::poll(descriptors.data(),descriptors.size(),static_cast<int>(std::min<std::int64_t>(delay,std::numeric_limits<int>::max())));
                if (ready<0) {
                    if (*a::__errno_location()==std::to_underlying(std::errc::interrupted)) continue;
                    return std::unexpected("endpoint readiness wait failed");
                }
                if constexpr(default_policy)if(descriptors[2].revents&a::POLLIN)if(!policy_.check())return std::unexpected("endpoint default-route policy changed");
                if constexpr(dns_policy)if(descriptors[2+std::size_t(default_policy)].revents || dns_monitor.has_alert()) {
                    if (cancel()) break;
                    if (auto problem=dns_monitor.take_error()) {
                        std::string message(DnsPolicy::describe(*problem,false));
                        if (problem->system) message+=": "+problem->system.message();
                        return std::unexpected(std::move(message));
                    }
                    if (dns_monitor.descriptor_failed()) return std::unexpected("endpoint descriptor became unavailable");
                }
                for (auto const& descriptor:descriptors) if (descriptor.revents&(a::POLLERR|a::POLLHUP|a::POLLNVAL)) return std::unexpected("endpoint descriptor became unavailable");
            }
            return {};
        }
        [[nodiscard]] auto stop(Clock::time_point deadline) noexcept -> packet::TunCleanupReport {
            if (stopped_) return policy_cleanup(lease_ ? lease_->cleanup() : early_cleanup());
            if constexpr(dns_policy)(void)dns_.stop(deadline);
            if (tun_) tun_->quiesce();
            if (port_) port_->stop();
            started_=false; stopped_=true;
            if constexpr(default_policy)(void)policy_.stop(deadline);
            if (lease_) { auto report=lease_->stop(deadline); if (tun_) tun_->stop(); return policy_cleanup(report); }
            if (tun_) {
                tun_->stop(); early_unverified_=true;
                platform::netlink::Socket<> control;
                auto opened=control.open();
                if (opened) {
                    auto remaining=packet::tun_network_detail::View(control,0,deadline).link(config_.device);
                    early_unverified_=!remaining || bool(*remaining);
                }
            }
            return policy_cleanup(early_cleanup());
        }
        [[nodiscard]] auto local_endpoint() const -> std::expected<net::UdpEndpoint,std::error_code> {
            if (!port_) return std::unexpected(std::make_error_code(std::errc::not_connected)); return port_->local_endpoint();
        }
        [[nodiscard]] auto drained() noexcept -> bool { return (!default_policy || [&]{if constexpr(default_policy)return policy_.drained();else return true;}()) && (!dns_policy || [&]{if constexpr(dns_policy)return dns_.drained();else return true;}()) && stopped_ && !early_unverified_ && (!port_ || port_->drained()) && (!tun_ || tun_->drained()) && (!lease_ || lease_->drained()); }
    };
}
