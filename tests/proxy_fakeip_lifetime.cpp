#include <cstdio>
extern "C" int nexus_test_fakeip_lifetime(unsigned,unsigned);
extern "C" void nexus_test_fakeip_blocked() {}
extern "C" void nexus_test_fakeip_dns_received() {}
extern "C" void nexus_test_fakeip_watcher_done() {}
extern "C" void nexus_test_fakeip_session_release(bool) {}
int main() {
    for (unsigned backend=0; backend<2; ++backend) {
        for (unsigned mode=0; mode<2; ++mode) {
            auto result=nexus_test_fakeip_lifetime(backend,mode);
            if (result==77) { std::puts("io_uring unavailable"); break; }
            if (result) { std::fprintf(stderr,"backend %u mode %u: %d\n",backend,mode,result); return 1; }
            std::printf("%s: fake-IP pin released after %s\n",backend ? "io_uring" : "epoll",mode ? "exception drain" : "context abandonment");
        }
    }
}
