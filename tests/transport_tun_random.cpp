#include <cerrno>
#include <cstring>
#include <sys/random.h>
import std;
import nexus.transport.tun_linux;
namespace p=nexus::packet; namespace tr=nexus::transport;
namespace { int mode=0, calls=0; }
extern "C" ssize_t __wrap_getrandom(void* data,size_t size,unsigned flags) {
    ++calls;
    if (flags!=GRND_NONBLOCK) { errno=EINVAL; return -1; }
    if (mode==1) { errno=EAGAIN; return -1; }
    if (mode==2) return 0;
    if (mode==3 && calls==1) { errno=EINTR; return -1; }
    auto count=std::min<size_t>(size,1); std::memset(data,0x5a,count); return static_cast<ssize_t>(count);
}
int main() {
    auto tun=p::LinuxTun::create("nx-random"); if (!tun) return 1;
    auto driver=tr::LinuxTunDirect::create(std::move(*tun),nexus::rules::Matcher{}); if (!driver) return 2;
    mode=1; auto failure=(*driver)->step(10);
    if (failure || !std::holds_alternative<tr::TunRandomFailure>(failure.error()) ||
        std::get<tr::TunRandomFailure>(failure.error()).error!=std::error_code(EAGAIN,std::generic_category())) return 3;
    mode=2; failure=(*driver)->step(10);
    if (failure || !std::holds_alternative<tr::TunRandomFailure>(failure.error()) ||
        std::get<tr::TunRandomFailure>(failure.error()).error!=std::errc::io_error) return 4;
    mode=3; calls=0; auto success=(*driver)->step(9);
    if (!success || calls!=5 || success->device.input_error || success->device.output_error) return 5;
    calls=0; auto reversed=(*driver)->step(8);
    if (reversed || !std::holds_alternative<tr::TunDriverError>(reversed.error()) ||
        std::get<tr::TunDriverError>(reversed.error())!=tr::TunDriverError::time_reversed || calls) return 6;
    if (!(*driver)->stop(9)) return 7;
    auto stopped=(*driver)->step(10);
    if (stopped || !std::holds_alternative<tr::TunDriverError>(stopped.error()) ||
        std::get<tr::TunDriverError>(stopped.error())!=tr::TunDriverError::stopped || calls) return 8;
    std::println("TUN entropy errors are reported before advancing; interrupted and short reads retry");
}
