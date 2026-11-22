import std;
import platform.netlink_abi;
import platform.netlink_codec;
import platform.netlink_socket;
import platform.routing_rule;
import packet.tun_linux;
import packet.tun_network_types;
import packet.tun_network_records;
import packet.tun_network_requests;
import packet.tun_network_view;
import packet.tun_network;
import packet.tun_default_policy;
import nexus.test.lease_support;
namespace {
    namespace p = ::packet;
    namespace a = ::platform::netlink_abi;
    namespace n = ::platform::netlink;
    namespace r = ::platform::routing;
    namespace d = ::packet::tun_network_detail;
    namespace t=nexus::test::lease;
    auto explain(p::TunPolicyFailure const& failure) -> void {
        std::println("policy failure={} netlink={} system={}",int(failure.code),failure.netlink?int(failure.netlink->code):-1,failure.netlink?failure.netlink->system.message():"");
    }
}
auto main(int argc,char** argv)->int {
    try {
        t::isolation(argc,argv);std::string_view mode=argc>3?argv[3]:"normal";
        auto settings=t::options();settings.route_count=0;
        auto device=p::LinuxTun::create("nx-policy");t::require(device.has_value());
        auto lease=p::TunNetworkLease<>::create(*device,settings);t::require(lease.has_value());
        t::require(lease->start(t::deadline()).has_value());
        p::TunDefaultPolicy<> policy;auto started=policy.start(*lease,{},t::deadline(),t::deadline());
        if(mode=="reject") {
            t::require(!started && (started.error().code==p::TunPolicyError::conflict || started.error().code==p::TunPolicyError::unsupported));
            auto report=policy.stop(t::deadline());t::require(!report.removed&&!report.preserved&&!report.uncertain&&!report.settings_restored&&!report.settings_preserved);
            auto cleanup=lease->stop(t::deadline());t::require(!cleanup.total&&lease->drained());
            std::println("preflight rejected conflicting or unsupported state before any route/rule/sysctl mutation");return 0;
        }
        if(!started)explain(started.error());t::require(started.has_value());t::require(policy.check().has_value());
        n::Socket<> foreign;t::require(foreign.open().has_value());
        if(mode=="hold") {
            std::cout<<"ready"<<std::endl;std::string release;std::getline(std::cin,release);
            std::array<std::uint8_t,65536> input;bool ipv4=false,ipv6=false;unsigned packets=0;
            while(true) {
                auto size=a::read(device->native_handle(),input.data(),input.size());
                if(size<0){t::require(*a::__errno_location()==std::to_underlying(std::errc::resource_unavailable_try_again));break;}
                t::require(size>0);++packets;
                std::string_view bytes(reinterpret_cast<char const*>(input.data()),size);
                ipv4|=bytes.contains("captured-v4");ipv6|=bytes.contains("captured-v6");
                t::require(!bytes.contains("marked-outer"));
            }
            t::require(ipv4&&ipv6);std::println("actual TUN captured dual-family UDP packets={} and zero marked outer payload",packets);
        }
        if(mode=="overflow") {
            r::Rule unrelated{.family=4,.action=a::FR_ACT_TO_TBL,.protocol=a::RTPROT_STATIC,.table=65000,.priority=50000};
            for(unsigned i=0;i<512;++i) {
                t::require(foreign.acknowledge(r::rule_request(unrelated,true),t::deadline()).has_value());
                t::require(foreign.acknowledge(r::rule_request(unrelated,false),t::deadline()).has_value());
            }
            auto checked=policy.check();t::require(!checked);
            auto report=policy.stop(t::deadline());
            t::require(report.preserved==8 && report.uncertain==8 && report.descriptors_closed && !policy.drained());
            auto cleanup=lease->stop(t::deadline());t::require(!cleanup.total&&lease->drained());
            std::println("real kernel NETLINK_ROUTE monitor overflow revoked all8 ownership proofs; preserved8 uncertain8; owned TUN closed, no foreign-object delete");return 0;
        }
        if(mode=="replace") {
            r::Rule rule{.family=4,.action=a::FR_ACT_TO_TBL,.protocol=a::RTPROT_STATIC,.table=60000,.priority=10002,.mark=0x6e780001,.mask=0xffffffffU,.flags=a::FIB_RULE_INVERT};
            t::require(foreign.acknowledge(r::rule_request(rule,false),t::deadline()).has_value());
            t::require(foreign.acknowledge(r::rule_request(rule,true),t::deadline()).has_value());
            auto checked=policy.check();t::require(!checked&&checked.error().code==p::TunPolicyError::drift);
        }
        auto report=policy.stop(t::deadline());
        std::println("policy cleanup mode={} removed={} preserved={} uncertain={} owner={} baselineLease={} settings_restored={} settings_preserved={}",mode,report.removed,report.preserved,report.uncertain,sizeof(policy),sizeof(*lease),report.settings_restored,report.settings_preserved);
        t::require(report.descriptors_closed && !report.uncertain && report.preserved==(mode=="replace"?1u:0u));
        std::size_t remaining=0;
        for(std::uint8_t family:{4,6})t::require(foreign.dump(a::RTM_GETRULE,d::native_family(family),t::deadline(),[&](n::Message message)->std::expected<void,n::Failure>{
            auto parsed=r::parse_rule(message);if(!parsed)return std::unexpected(parsed.error());if(parsed->priority>=10000&&parsed->priority<=10002)++remaining;return {};
        }).has_value());
        t::require(remaining==(mode=="replace"?1u:0u));
        auto cleanup=lease->stop(t::deadline());t::require(!cleanup.total&&lease->drained());
        std::println("default policy lifecycle exact native rule/route readback and foreign replacement preservation passed");
    }catch(int code){return code;}
}
