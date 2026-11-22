#include <cerrno>
#include <sys/random.h>
import std;
import platform.linux_random;
import transport.tun_linux;
import nexus.tests.random_fault;
namespace p = ::packet; namespace tr=transport;
static_assert(std::same_as<decltype(&::getrandom),::platform::linux_random_abi::GetrandomSignature>);
static_assert(std::same_as<decltype(&::__errno_location),::platform::linux_random_abi::ErrnoLocationSignature>);
static_assert(GRND_NONBLOCK==::platform::linux_random_abi::nonblocking_flag);
static_assert(EINTR==std::to_underlying(std::errc::interrupted));
static_assert(EAGAIN==std::to_underlying(std::errc::resource_unavailable_try_again));
static_assert(EPERM==std::to_underlying(std::errc::operation_not_permitted));
static_assert(EIO==std::to_underlying(std::errc::io_error));
int main() {
    using namespace nexus::tests;
    auto tun=p::LinuxTun::create("nx-random"); if (!tun) return 1;
    auto driver=tr::LinuxTunDirect::create(std::move(*tun),::rules::Matcher{}); if (!driver) return 2;
    set_random_fault(RandomFault::unavailable); auto failure=(*driver)->step(10);
    if (failure || !std::holds_alternative<tr::TunRandomFailure>(failure.error()) ||
        std::get<tr::TunRandomFailure>(failure.error()).error!=std::error_code(EAGAIN,std::generic_category()) || random_bad_flag()) return 3;
    set_random_fault(RandomFault::zero); failure=(*driver)->step(10);
    if (failure || !std::holds_alternative<tr::TunRandomFailure>(failure.error()) ||
        std::get<tr::TunRandomFailure>(failure.error()).error!=std::errc::io_error || random_bad_flag()) return 4;
    set_random_fault(RandomFault::interrupted_short); auto success=(*driver)->step(9);
    if (!success || random_calls()!=5 || random_bad_flag() || success->device.input_error || success->device.output_error) return 5;
    set_random_fault(RandomFault::interrupted_short); auto reversed=(*driver)->step(8);
    if (reversed || !std::holds_alternative<tr::TunDriverError>(reversed.error()) ||
        std::get<tr::TunDriverError>(reversed.error())!=tr::TunDriverError::time_reversed || random_calls()) return 6;
    if (!(*driver)->stop(9)) return 7;
    auto stopped=(*driver)->step(10);
    if (stopped || !std::holds_alternative<tr::TunDriverError>(stopped.error()) ||
        std::get<tr::TunDriverError>(stopped.error())!=tr::TunDriverError::stopped || random_calls()) return 8;
    std::println("TUN entropy errors are reported before advancing; interrupted and short reads retry");
}
