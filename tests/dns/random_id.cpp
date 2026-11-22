import std;
import dns.corosio_resolver;
import nexus.tests.random_fault;

auto main() -> int {
    using namespace nexus::tests;
    namespace dns=dns::detail;
#ifdef NEXUS_TEST_LINUX_RANDOM
    for (auto mode:{RandomFault::unavailable,RandomFault::permission,RandomFault::zero}) {
        set_random_fault(mode);
        auto id=dns::random_id();
        if (id || id.error()!=dns::ResolveError::random || random_calls()!=1 || random_bad_flag()) return 1;
    }
    set_random_fault(RandomFault::interrupted_short);
    auto id=dns::random_id();
    if (!id || *id!=0x5a5b || random_calls()!=3 || random_bad_flag()) return 2;
    set_random_fault(RandomFault::disabled);
#endif
    if (!dns::random_id()) return 3;
    std::println("DNS ID uses nonblocking system entropy and fails closed");
}
