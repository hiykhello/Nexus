export module endpoint.resolved_dns;
import std;
import endpoint.host_dns_types;
import platform.sd_bus_abi;
import platform.netlink_abi;
import platform.netlink_codec;
import platform.netlink_socket;
import platform.resolved_bus;
import platform.resolved_types;
import platform.resolved_client;
import packet.tun_network;
import packet.tun_network_types;
import packet.tun_network_records;

export namespace endpoint {
    namespace host_dns_detail {
        template<class KernelHooks> struct Cancellation {
            static auto canceled() noexcept -> bool {if constexpr(requires{KernelHooks::cancelled();})return KernelHooks::cancelled();else return false;}
        };
    }
    struct HostDnsCleanup {
        bool restored=false,preserved=false,uncertain=false,descriptors_closed=false;
        std::optional<platform::resolved::Failure> failure;
    };
    template<class KernelHooks=platform::netlink::NoHooks> class ResolvedHostDns {
        using Clock=platform::resolved::Clock;
        using Lease=packet::TunNetworkLease<KernelHooks>;
        using Snapshot=platform::resolved::Snapshot;
        using Failure=platform::resolved::Failure;
        using Error=platform::resolved::Error;
        Lease* lease_=nullptr;
        platform::resolved::Client<host_dns_detail::Cancellation<KernelHooks>> client_;
        Snapshot desired_;
        packet::tun_network_detail::LinkRecord link_;
        Clock::time_point next_check_{};
        HostDnsCleanup cleanup_;
        bool servers_attempted_=false,domains_attempted_=false,started_=false,stopped_=false;
        static auto failure(Error code,int native=0) noexcept -> std::unexpected<Failure> {return platform::resolved::fail(code,native);}
        auto issue(Failure problem,bool uncertain=true) noexcept -> void {if(!cleanup_.failure)cleanup_.failure=problem;cleanup_.uncertain|=uncertain;}
        static auto kernel_failure(packet::TunNetworkFailure const& problem) noexcept -> Failure {
            if(problem.netlink && problem.netlink->code==platform::netlink::Error::canceled)return Failure{Error::canceled,problem.system};
            if(problem.netlink && problem.netlink->code==platform::netlink::Error::timeout)return Failure{Error::timeout,problem.system};
            return Failure{Error::ownership,problem.system};
        }
        template<bool Cleanup=false> auto identity(Clock::time_point deadline) -> std::expected<void,Failure> {
            if(!lease_ || lease_->native_handle()<0)return failure(Error::ownership);
            auto proof=[&]{if constexpr(Cleanup)return lease_->verified_device_for_cleanup(deadline);else return lease_->verified_device(deadline);}();
            if(!proof)return std::unexpected(kernel_failure(proof.error()));
            if(proof->index!=link_.index || proof->type!=link_.type || proof->mtu!=link_.mtu || proof->name!=link_.name || proof->alias!=link_.alias || proof->ipv6_generation!=link_.ipv6_generation || !(proof->flags&platform::netlink_abi::IFF_UP))return failure(Error::ownership);
            return {};
        }
        [[nodiscard]] auto expected(bool domains) const noexcept -> Snapshot {
            Snapshot result;result.servers=desired_.servers;result.server_count=desired_.server_count;
            if(domains){result.domains=desired_.domains;result.domain_count=desired_.domain_count;}return result;
        }
        [[nodiscard]] auto recognizes(Snapshot const& observed) const noexcept -> bool {
            bool servers=observed.server_count==0 || (servers_attempted_ && observed.server_count==desired_.server_count && observed.servers==desired_.servers);
            bool domains=observed.domain_count==0 || (domains_attempted_ && observed.domain_count==desired_.domain_count && observed.domains==desired_.domains);
            return servers && domains;
        }
      public:
        static constexpr bool enabled=true;
        [[nodiscard]] static auto describe(Failure const& problem,bool startup) noexcept -> std::string_view {
            switch(problem.code) {
                case Error::canceled:return startup ? "endpoint startup canceled" : "host DNS check canceled";
                case Error::timeout:return startup ? "endpoint startup deadline expired" : "host DNS check deadline expired";
                case Error::conflict:return "host DNS settings conflict with existing link settings, routing domains or TUN coverage";
                case Error::ownership:return "host DNS settings or resolver service ownership changed";
                case Error::capacity:return "host DNS resolver data exceeds its bounded capacity";
                case Error::protocol:return "host DNS configuration or resolver reply is invalid";
                case Error::state:return "host DNS owner is not in the required state";
                default:return "host DNS resolver operation failed";
            }
        }
        ResolvedHostDns()=default;
        ~ResolvedHostDns(){(void)stop(Clock::now()+std::chrono::seconds(2));}
        ResolvedHostDns(ResolvedHostDns const&)=delete;
        auto operator=(ResolvedHostDns const&) -> ResolvedHostDns& = delete;
        ResolvedHostDns(ResolvedHostDns&&)=delete;
        auto operator=(ResolvedHostDns&&) -> ResolvedHostDns& = delete;
        [[nodiscard]] auto start(Lease& lease,HostDnsOptions const& options,bool default_route,Clock::time_point deadline,Clock::time_point rollback_deadline,bool local_stub=false) -> std::expected<void,Failure> {
            if(started_ || stopped_)return failure(Error::state);
            auto abort=[&](Failure problem)->std::expected<void,Failure>{(void)stop(rollback_deadline);return std::unexpected(problem);};
            if(options.backend!=HostDnsBackend::resolved || !options.valid())return abort(Failure{Error::protocol});
            auto const& network=lease.network_options();
            for(std::size_t i=0;i<options.server_count;++i) {
                auto const& server=options.servers[i];auto family=server.ipv6 ? std::uint8_t{6} : std::uint8_t{4};
                packet::TunAddress address{family,server.address,server.ipv6 ? std::uint8_t{128} : std::uint8_t{32}};
                bool family_configured=false,local=false,covered=default_route;
                for(std::size_t j=0;j<network.address_count;++j){auto const& item=network.addresses[j];family_configured|=item.family==family;local|=item.family==family && item.bytes==server.address;}
                for(std::size_t j=0;j<network.route_count;++j)covered|=packet::tun_network_detail::contains(network.routes[j],address);
                if (!family_configured || (local_stub ? !local : local || !covered))
                    return abort(Failure{Error::conflict});
                auto& desired=desired_.servers[i];desired.address=server.address;desired.family=family;desired.port=0;
            }
            desired_.server_count=options.server_count;desired_.domain_count=1;desired_.domains[0].name[0]='.';desired_.domains[0].route_only=true;
            auto proof=lease.verified_device(deadline);if(!proof)return abort(kernel_failure(proof.error()));link_=*proof;lease_=&lease;
            auto opened=client_.open(link_.index,deadline);if(!opened)return abort(opened.error());
            auto baseline=client_.snapshot(deadline);if(!baseline)return abort(baseline.error());
            if(baseline->server_count || baseline->domain_count)return abort(Failure{Error::conflict});
            auto competing=client_.competing_domains(deadline);if(!competing)return abort(competing.error());if(*competing)return abort(Failure{Error::conflict});
            auto owner=identity(deadline);if(!owner)return abort(owner.error());
            servers_attempted_=true;
            auto changed=client_.set_servers(desired_,deadline);
            if(!changed){servers_attempted_=changed.error().submitted;cleanup_.uncertain|=changed.error().submitted;return abort(changed.error());}
            auto current=client_.snapshot(deadline);if(!current)return abort(current.error());
            if(*current!=expected(false)){cleanup_.preserved=true;return abort(Failure{Error::ownership});}
            owner=identity(deadline);if(!owner)return abort(owner.error());
            domains_attempted_=true;changed=client_.set_domains(desired_,deadline);
            if(!changed){domains_attempted_=changed.error().submitted;cleanup_.uncertain|=changed.error().submitted;return abort(changed.error());}
            current=client_.snapshot(deadline);if(!current)return abort(current.error());
            if(*current!=desired_){cleanup_.preserved=true;return abort(Failure{Error::ownership});}
            owner=identity(deadline);if(!owner)return abort(owner.error());
            client_.mark_clean();next_check_=Clock::now()+std::chrono::milliseconds(250);started_=true;return {};
        }
        [[nodiscard]] auto poll(Clock::time_point now,Clock::time_point deadline) -> std::expected<void,Failure> {
            if(!started_ || stopped_)return failure(Error::state);
            auto events=client_.process(deadline);if(!events)return std::unexpected(events.error());
            if(client_.revoked())return failure(Error::ownership);
            if(!client_.dirty() && now<next_check_)return {};
            auto owner=identity(deadline);if(!owner)return owner;
            auto current=client_.snapshot(deadline);if(!current)return std::unexpected(current.error());
            if(*current!=desired_)return failure(Error::ownership);
            auto competing=client_.competing_domains(deadline);if(!competing)return std::unexpected(competing.error());if(*competing)return failure(Error::conflict);
            owner=identity(deadline);if(!owner)return owner;
            client_.mark_clean();next_check_=Clock::now()+std::chrono::milliseconds(250);return {};
        }
        [[nodiscard]] auto next_poll() const noexcept -> Clock::time_point {return next_check_;}
        [[nodiscard]] auto native_handle() const noexcept -> int {return client_.native_handle();}
        [[nodiscard]] auto stop(Clock::time_point deadline) noexcept -> HostDnsCleanup {
            if(stopped_)return cleanup_;started_=false;
            if(servers_attempted_ || domains_attempted_) {
                auto proof=identity<true>(deadline);
                if(!proof)issue(proof.error());
                else {
                    auto current=client_.template snapshot<false>(deadline);
                    if(!current)issue(current.error());
                    else if(cleanup_.preserved || !recognizes(*current)){cleanup_.preserved=true;issue(Failure{Error::ownership},false);}
                    else {
                        Snapshot empty;
                        if(current->domain_count) {
                            auto changed=client_.template set_domains<false>(empty,deadline);if(!changed)issue(changed.error());
                            auto verified=client_.template snapshot<false>(deadline);
                            if(!verified || verified->domain_count || verified->server_count!=current->server_count || verified->servers!=current->servers)issue(verified ? Failure{Error::ownership} : verified.error());
                            else current=std::move(verified);
                        }
                        if(!cleanup_.preserved && current && !current->domain_count && current->server_count) {
                            proof=identity<true>(deadline);
                            if(!proof)issue(proof.error());
                            else {
                                auto changed=client_.template set_servers<false>(empty,deadline);if(!changed)issue(changed.error());
                                auto verified=client_.template snapshot<false>(deadline);
                                if(!verified || *verified!=empty)issue(verified ? Failure{Error::ownership} : verified.error());
                                else {servers_attempted_=domains_attempted_=false;cleanup_.restored=true;}
                            }
                        } else if(current && !current->server_count && !current->domain_count){servers_attempted_=domains_attempted_=false;cleanup_.restored=true;}
                    }
                }
            } else cleanup_.restored=true;
            client_.close();stopped_=true;cleanup_.descriptors_closed=client_.native_handle()<0;return cleanup_;
        }
        [[nodiscard]] auto cleanup() const noexcept -> HostDnsCleanup {return cleanup_;}
        [[nodiscard]] auto drained() const noexcept -> bool {return stopped_ && cleanup_.descriptors_closed && !cleanup_.uncertain;}
    };
}
