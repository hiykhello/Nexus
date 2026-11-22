import std;
extern "C" int nexus_test_chain_vless(unsigned,unsigned,unsigned,char const*,char const*,bool,bool,unsigned);
int main(int argc,char** argv) {
    if (argc!=9) return 64;
    std::array<unsigned,3> ports{};
    for (std::size_t i=0;i<ports.size();++i) { auto n=std::strtoul(argv[i+1],nullptr,10); if (!n || n>65535) return 64; ports[i]=n; }
    auto mode=std::string_view(argv[8]); if (mode!="data" && mode!="timeout" && mode!="cancel" && mode!="xudp") return 64;
    return nexus_test_chain_vless(ports[0],ports[1],ports[2],argv[4],argv[5],std::string_view(argv[6])=="vision",std::string_view(argv[7])=="uring",mode=="timeout" ? 1 : mode=="cancel" ? 2 : mode=="xudp" ? 3 : 0);
}
