import std;
extern "C" int nexus_test_proxy_xudp(unsigned,unsigned,unsigned,char const*,char const*,bool);
int main(int argc,char** argv) {
    if (argc!=7) return 64;
    auto server=std::strtoul(argv[1],nullptr,10),a=std::strtoul(argv[2],nullptr,10),b=std::strtoul(argv[3],nullptr,10);
    if (!server || server>65535 || !a || a>65535 || !b || b>65535) return 64;
    return nexus_test_proxy_xudp(server,a,b,argv[4],argv[5],argv[6][0]=='1');
}
