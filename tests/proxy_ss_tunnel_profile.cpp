#include <memory>
#include <cstdio>
std::weak_ptr<void const> profile;
bool destroyed=false, alive_on_destroy=false;
extern "C" void nexus_test_tunnel_profile_owner(std::weak_ptr<void const> owner) { profile=std::move(owner); }
extern "C" bool nexus_test_tunnel_profile_is_alive() { return profile.use_count()==1; }
extern "C" void nexus_test_tunnel_profile_destroy() { destroyed=true; alive_on_destroy=profile.use_count()==1; }
extern "C" bool nexus_test_skip_server_stop() { return false; }
extern "C" void nexus_test_ss_profile_owner(std::weak_ptr<void>) {}
extern "C" void nexus_test_ss_profile_frame_enter() {}
extern "C" void nexus_test_ss_profile_frame_exit() {}
extern "C" int nexus_test_ss_tunnel_profile();
int main() {
    if (nexus_test_ss_tunnel_profile() || !destroyed || !alive_on_destroy || !profile.expired()) return 1;
    std::puts("SS-2022 tunnel is destroyed before its factory-owned profile");
}
