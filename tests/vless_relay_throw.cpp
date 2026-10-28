#include <cstdlib>
#include <stdexcept>
#include <cstdint>
extern "C" void nexus_test_start_throw() {}
extern "C" void nexus_test_session_throw(std::uint8_t) {}
extern "C" void nexus_test_vless_relay_throw(unsigned point) {
    auto value=std::getenv("NEXUS_TEST_VLESS_RELAY_THROW");
    if (value && std::strtoul(value,nullptr,10)==point) throw std::runtime_error("injected relay failure");
}
