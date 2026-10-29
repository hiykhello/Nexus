#include <net/if.h>
import std;
import nexus.transport.tun_linux;
namespace p=nexus::packet; namespace tr=nexus::transport;
int main() {
    auto tun=p::LinuxTun::create("nx-driver");
    if (!tun || !if_nametoindex("nx-driver")) return 1;
    tr::TunLimits invalid; invalid.udp.idle_ms=0;
    auto rejected=tr::LinuxTunDirect::create(std::move(*tun),nexus::rules::Matcher{},invalid);
    if (rejected || !std::holds_alternative<tr::TunDriverError>(rejected.error()) ||
        std::get<tr::TunDriverError>(rejected.error())!=tr::TunDriverError::invalid_limits || tun->native_handle()<0) return 2;
    invalid={}; invalid.mtu=64;
    rejected=tr::LinuxTunDirect::create(std::move(*tun),nexus::rules::Matcher{},invalid);
    if (rejected || !std::holds_alternative<tr::TunDriverError>(rejected.error()) || tun->native_handle()<0) return 2;
    invalid={}; invalid.tcp_buffer=0;
    rejected=tr::LinuxTunDirect::create(std::move(*tun),nexus::rules::Matcher{},invalid);
    if (rejected || !std::holds_alternative<nexus::tcp::TableError>(rejected.error()) || tun->native_handle()<0) return 3;
    auto driver=tr::LinuxTunDirect::create(std::move(*tun),nexus::rules::Matcher{});
    if (!driver || tun->native_handle()!=-1 || !if_nametoindex("nx-driver")) return 4;
    auto step=(*driver)->step(10,42);
    if (!step || step->device.input_error || step->device.output_error) return 5;
    auto reversed=(*driver)->step(9,42);
    if (reversed || !std::holds_alternative<tr::TunDriverError>(reversed.error()) ||
        std::get<tr::TunDriverError>(reversed.error())!=tr::TunDriverError::time_reversed) return 6;
    auto early=(*driver)->stop(9);
    if (early || !if_nametoindex("nx-driver")) return 7;
    if (!(*driver)->stop(10) || !(*driver)->stop(10) || if_nametoindex("nx-driver")) return 8;
    auto stopped=(*driver)->step(10,42);
    if (stopped || !std::holds_alternative<tr::TunDriverError>(stopped.error()) ||
        std::get<tr::TunDriverError>(stopped.error())!=tr::TunDriverError::stopped) return 9;
    { auto next=p::LinuxTun::create("nx-scoped"); if (!next) return 10;
      auto scoped=tr::LinuxTunDirect::create(std::move(*next),nexus::rules::Matcher{});
      if (!scoped || !if_nametoindex("nx-scoped")) return 11; }
    if (if_nametoindex("nx-scoped")) return 12;
    std::println("owned TUN transport validates limits, stops and releases its device");
}
