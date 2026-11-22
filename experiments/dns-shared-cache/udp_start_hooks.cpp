import std;
#ifdef NEXUS_TEST_UDP_START
namespace { thread_local std::size_t attached=0; }
extern "C" void nexus_test_udp_attached() noexcept { ++attached; }
auto udp_reset_attached() noexcept -> void { attached=0; }
auto udp_attached_count() noexcept -> std::size_t { return attached; }
#endif
