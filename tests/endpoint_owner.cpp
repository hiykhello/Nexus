import std;
import platform.netlink_abi;
import packet.tun_network;
import packet.tun_network_types;
import wireguard;
import wireguard.crypto;
import wireguard.port;
import wireguard.tun;
import nexus.test.lease_support;
namespace a = ::platform::netlink_abi;
namespace p = ::packet;
namespace w=wireguard;
namespace t=nexus::test::lease;
auto main(int argc,char**argv) -> int {
    try {
        t::isolation(argc,argv);
        using Port=w::UdpPort<2,4,2048,8>;
        using Tun=w::LinuxTunPort<Port>;
        using Lease=p::TunNetworkLease<>;
        std::array<std::uint8_t,32> key{}; key[0]=42;
        auto port=Port::create(key); t::require(port.has_value());
        t::require(port->open({4,{127,0,0,1},0},w::Clock::now()).has_value());
        std::optional<Tun> tun;
        t::require(Tun::emplace_into(tun,*port,"nx-single",1420).has_value());
        auto fd=tun->native_handle(); auto token=tun->claim_network(); t::require(token.has_value());
        t::require(!tun->claim_network() && !Tun::emplace_into(tun,*port,"nx-other",1420));
        std::optional<Lease> lease;
        t::require(Lease::emplace_into(lease,std::move(*token),t::options()).has_value());
        t::require(lease->start(t::deadline()).has_value());
        auto progress=tun->step(w::Clock::now(),std::chrono::system_clock::now()); t::require(progress.has_value());
        tun->quiesce();
        t::require(port->drained() && tun->native_handle()==fd && a::fcntl(fd,a::F_GETFD)>=0 && !tun->step(w::Clock::now(),{}));
        auto report=lease->stop(t::deadline());
        t::require(lease->drained() && !report.total && a::fcntl(fd,a::F_GETFD)<0);
        tun->stop(); t::require(tun->drained() && !tun->claim_network());
        std::println("one stable private LinuxTun served both Port pump and sealed network lease; quiesce preserves fd until checked cleanup, no second device; sizeof adapter={} lease={}",sizeof(Tun),sizeof(Lease));
    } catch (int value) { return value; }
}
