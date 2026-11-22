import std;
import platform.netlink_abi;
import platform.netlink_codec;
import platform.netlink_socket;
import platform.routing_rule;
import packet.tun_linux;
import packet.tun_network_types;
import packet.tun_network_records;
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
    struct Faults : n::NoHooks {
        static inline std::string_view effect;
        static inline unsigned mutations=0,dumps=0,target=0;
        static inline bool used=false,dump_mode=false;
        static auto before_send(std::span<std::uint8_t const>,bool mutation) noexcept -> std::error_code {
            if(mutation)++mutations;else ++dumps;
            if(!used && mutation!=dump_mode && (dump_mode?dumps:mutations)==target && effect=="send") {
                used=true;return std::make_error_code(std::errc::permission_denied);
            }
            return {};
        }
        static auto after_receive(std::span<std::uint8_t>,bool mutation) noexcept -> n::ReceiveFault {
            if(dump_mode && !mutation && dumps==target && effect=="loss"){used=true;return n::ReceiveFault::lost_ack;}
            if(used || mutation==dump_mode || (dump_mode?dumps:mutations)!=target || effect=="send")return n::ReceiveFault::none;
            used=true;
            if(effect=="loss")return n::ReceiveFault::lost_ack;
            if(effect=="overflow")return n::ReceiveFault::overflow;
            if(effect=="truncated")return n::ReceiveFault::truncated;
            if(effect=="sequence")return n::ReceiveFault::wrong_sequence;
            if(effect=="sender")return n::ReceiveFault::wrong_sender;
            if(effect=="malformed")return n::ReceiveFault::malformed;
            std::terminate();
        }
    };
    auto clean(n::Socket<>& control) -> bool {
        bool empty=true;
        for(std::uint8_t family:{4,6}) {
            t::require(control.dump(a::RTM_GETRULE,d::native_family(family),t::deadline(),[&](n::Message message)->std::expected<void,n::Failure> {
                auto parsed=r::parse_rule(message);if(!parsed)return std::unexpected(parsed.error());
                if((parsed->priority>=10000&&parsed->priority<=10002)||parsed->table==60000||parsed->table==60001)empty=false;return {};
            }).has_value());
            t::require(d::View(control,0,t::deadline()).template routes<d::GatewayRouteRecord>(family,[&](auto const& route)->std::expected<void,n::Failure> {
                if(route.table==60000||route.table==60001)empty=false;return {};
            }).has_value());
        }
        return empty;
    }
}
auto main(int argc,char**argv)->int {
    try {
        t::isolation(argc,argv);t::require(argc==6);
        Faults::effect=argv[3];Faults::target=t::number(argv[4]);Faults::dump_mode=std::string_view(argv[5])=="dump";
        auto settings=t::options();settings.route_count=0;
        auto device=p::LinuxTun::create("nx-fault");t::require(device.has_value());
        auto lease=p::TunNetworkLease<>::create(*device,settings);t::require(lease.has_value());t::require(lease->start(t::deadline()).has_value());
        p::TunDefaultPolicy<Faults> policy;
        auto started=policy.start(*lease,{},t::deadline(),t::deadline());
        t::require(Faults::used || Faults::effect=="none");
        auto startup_mutations=Faults::mutations,startup_dumps=Faults::dumps;
        auto report=policy.stop(t::deadline());
        if(report.uncertain || report.preserved)std::println("cleanup incomplete uncertain={} preserved={}",report.uncertain,report.preserved);
        t::require(!report.uncertain && !report.preserved && policy.drained());
        n::Socket<> control;t::require(control.open().has_value()&&clean(control));
        // Same-context recovery with fresh concrete ownership and original TUN.
        p::TunDefaultPolicy<> recovered;t::require(recovered.start(*lease,{},t::deadline(),t::deadline()).has_value());
        auto recovery=recovered.stop(t::deadline());t::require(!recovery.uncertain&&!recovery.preserved&&recovered.drained()&&clean(control));
        auto cleanup=lease->stop(t::deadline());t::require(!cleanup.total&&lease->drained());
        std::println("policy fault={} phase={} ordinal={} original_success={} startup_mutations={} startup_dumps={} independent readback, rollback and fresh owner recovery passed",Faults::effect,argv[5],Faults::target,started.has_value(),startup_mutations,startup_dumps);
    }catch(int code){return code;}
}
