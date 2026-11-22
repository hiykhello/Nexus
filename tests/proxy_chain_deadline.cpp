import std;
extern "C" int nexus_test_chain_deadline(unsigned,char const*,char const*);
int main(int argc,char** argv) {
    if (argc!=4) return 64;
    auto port=std::strtoul(argv[1],nullptr,10);
    if (!port || port>65535) return 64;
    return nexus_test_chain_deadline(port,argv[2],argv[3]);
}
