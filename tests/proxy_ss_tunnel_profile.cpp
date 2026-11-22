import std;
bool profile_alive=false;
bool destroyed=false, alive_on_destroy=false;
extern "C" void nexus_test_tunnel_profile_created() { profile_alive=true; }
extern "C" void nexus_test_tunnel_profile_released() { profile_alive=false; }
extern "C" bool nexus_test_tunnel_profile_is_alive() { return profile_alive; }
extern "C" void nexus_test_tunnel_profile_destroy() { destroyed=true; alive_on_destroy=profile_alive; }
extern "C" bool nexus_test_skip_server_stop() { return false; }
extern "C" void nexus_test_ss_profile_created() {}
extern "C" void nexus_test_ss_profile_released() {}
extern "C" void nexus_test_ss_profile_frame_enter() {}
extern "C" void nexus_test_ss_profile_frame_exit() {}
extern "C" int nexus_test_ss_tunnel_profile();
int main() {
    if (nexus_test_ss_tunnel_profile() || !destroyed || !alive_on_destroy || profile_alive) return 1;
    std::println("SS-2022 tunnel is destroyed before its factory-owned profile");
}
