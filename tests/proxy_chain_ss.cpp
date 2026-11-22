import std;
extern "C" int nexus_test_chain_ss(unsigned,unsigned,unsigned,unsigned,bool,unsigned);
int main(int argc,char** argv) {
    if (argc!=6 && argc!=7) return 64;
    auto hops=static_cast<std::size_t>(argc-4);
    std::array<unsigned,4> ports{};
    for (std::size_t i=0;i<hops+1;++i) {
        auto value=std::strtoul(argv[i+1],nullptr,10);
        if (!value || value>65535) return 64;
        ports[i]=static_cast<unsigned>(value);
    }
    auto mode=std::string_view(argv[argc-1]);
    if (mode!="reply" && mode!="timeout" && mode!="large" && mode!="uot" && mode!="cancel") return 64;
    return nexus_test_chain_ss(ports[0],ports[1],hops==3 ? ports[2] : 0,ports[hops],std::string_view(argv[argc-2])=="uring",mode=="timeout" ? 1 : mode=="large" ? 2 : mode=="uot" ? 3 : mode=="cancel" ? 4 : 0);
}
