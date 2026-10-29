#include <cstdio>
extern "C" int nexus_test_fakeip_lifetime(unsigned);
extern "C" void nexus_test_fakeip_blocked() {}
int main() {
    for (unsigned backend=0; backend<2; ++backend) {
        auto result=nexus_test_fakeip_lifetime(backend);
        if (result==77) { std::puts("io_uring unavailable"); continue; }
        if (result) { std::fprintf(stderr,"backend %u: %d\n",backend,result); return 1; }
        std::printf("%s: fake-IP pin released after child teardown\n",backend ? "io_uring" : "epoll");
    }
}
