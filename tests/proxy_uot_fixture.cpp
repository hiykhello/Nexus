#include <cstdlib>
extern "C" int nexus_test_proxy_uot(unsigned, unsigned, bool);
extern "C" int nexus_test_proxy_uot_policy(unsigned, unsigned);
extern "C" int nexus_test_proxy_uot_flood(unsigned, unsigned);
extern "C" int nexus_test_proxy_uot_cross(unsigned, unsigned, bool);
extern "C" int nexus_test_proxy_uot_end(unsigned, unsigned);
extern "C" int nexus_test_proxy_uot_rotate(unsigned, unsigned);
extern "C" int nexus_test_proxy_uot_empty(unsigned, unsigned);
extern "C" int nexus_test_proxy_uot_empty_echo(unsigned, unsigned);
extern "C" int nexus_test_proxy_uot_one(unsigned, unsigned);
extern "C" int nexus_test_proxy_uot_large(unsigned, unsigned);
extern "C" int nexus_test_proxy_uot_numeric_flood(unsigned, unsigned);
extern "C" int nexus_test_proxy_uot_invalid(unsigned, unsigned, unsigned);
extern "C" int nexus_test_proxy_uot_downstream_fault(unsigned, unsigned);
extern "C" int nexus_test_proxy_uot_slow(unsigned, unsigned);
extern "C" int nexus_test_proxy_uot_resume(unsigned, unsigned);
int main(int argc,char** argv) {
    if (argc!=4 && argc!=5) return 64;
    auto server=std::strtoul(argv[1],nullptr,10), target=std::strtoul(argv[2],nullptr,10);
    if (!server || server>65535 || !target || target>65535) return 64;
    if (argv[3][0]!='0' && argv[3][0]!='1') return 64;
    if (argc==5) {
        if (argv[4][0]=='h') return nexus_test_proxy_uot_empty_echo(server,target);
        if (argv[4][0]=='j') return nexus_test_proxy_uot_rotate(server,target);
        if (argv[4][0]=='g') return nexus_test_proxy_uot_empty(server,target);
        if (argv[4][0]=='e') return nexus_test_proxy_uot_end(server,target);
        if (argv[4][0]=='f') return nexus_test_proxy_uot_flood(server,target);
        if (argv[4][0]=='c') return nexus_test_proxy_uot_cross(server,target,argv[3][0]=='1');
        if (argv[4][0]=='r') return nexus_test_proxy_uot_one(server,target);
        if (argv[4][0]=='l') return nexus_test_proxy_uot_large(server,target);
        if (argv[4][0]=='n') return nexus_test_proxy_uot_numeric_flood(server,target);
        if (argv[4][0]=='i') return nexus_test_proxy_uot_invalid(server,target,argv[4][1]-'0');
        if (argv[4][0]=='d') return nexus_test_proxy_uot_downstream_fault(server,target);
        if (argv[4][0]=='s') return nexus_test_proxy_uot_slow(server,target);
        if (argv[4][0]=='t') return nexus_test_proxy_uot_resume(server,target);
        return nexus_test_proxy_uot_policy(server,target);
    }
    return nexus_test_proxy_uot(server,target,argv[3][0]=='1');
}
