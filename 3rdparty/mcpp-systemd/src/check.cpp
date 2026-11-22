// A native link provider only. The enabled resolved backend uses direct C ABI
// declarations verified independently against installed systemd/sd-bus.h.
extern "C" int nexus_systemd_system_link_anchor() noexcept {return 1;}
