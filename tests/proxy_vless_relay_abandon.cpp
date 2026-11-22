#include <cstdio>
import std;
import proxy;
using namespace std::chrono_literals;
bool profile_alive=false;
int entered=0, exited=0;
bool parent_exited=false, ordered=true, skip_stop=false;
extern "C" void nexus_test_vless_profile_created() { profile_alive=true; }
extern "C" void nexus_test_vless_profile_destroyed() { profile_alive=false; }
extern "C" void nexus_test_vless_profile_frame_enter() {}
extern "C" void nexus_test_vless_profile_frame_exit() { parent_exited=true; ordered &= exited==2 && profile_alive; }
extern "C" void nexus_test_vless_relay_frame_enter() { ++entered; }
extern "C" void nexus_test_vless_relay_frame_exit() { ++exited; ordered &= !parent_exited && profile_alive; }
extern "C" bool nexus_test_skip_server_stop() { return skip_stop; }
int main(int argc,char** argv) {
    if (argc!=4) return 1;
    {
        proxy::Server server;
        std::array<std::string,1> users{argv[3]};
        if (!server.prepare_vless_inbound(argv[1],argv[2],users)) return 2;
        auto port=server.start(0,proxy::Inbound::vless,1); if (!port) return 3;
        std::println("{}",*port); std::fflush(stdout);
        for (int i=0;i<1000 && entered<2;++i) server.poll(10ms);
        if (entered!=2 || exited || parent_exited || !profile_alive) return 4;
        for (int i=0;i<5;++i) server.poll(10ms);
        if (exited || parent_exited) return 5;
        skip_stop=true;
    }
    if (exited!=2 || !parent_exited || !ordered || profile_alive) return 6;
    std::println("both VLESS relay frames destroyed before their parent and profile");
}
