import std;
import vision;
int main(int argc,char** argv) {
    namespace v=vision;
    if (argc!=2) return 1;
    auto mode=std::string_view(argv[1]);
    v::UserId user{}; std::iota(user.begin(),user.end(),std::uint8_t{0});
    std::vector<std::uint8_t> data(8192,0x55); v::TrafficFilter filter;
    if (mode=="direct" || mode=="end" || mode=="records") {
        data[0]=0x17; data[1]=3; data[2]=3; data[3]=0x1f; data[4]=0xfb;
        std::vector<std::uint8_t> hello(85); hello[0]=0x16; hello[1]=hello[2]=3; hello[4]=80; hello[5]=2;
        if (mode=="records") { data[3]=0x1f; data[4]=0x9f; data[8100]=0x17; data[8101]=3; data[8102]=3; data[8103]=0; data[8104]=87; }
        hello[43]=32; hello[76]=0x13; hello[77]=mode!="end" ? 1 : 5;
        std::array<std::uint8_t,6> extension{0,0x2b,0,2,3,4}; std::ranges::copy(extension,hello.begin()+79);
        filter.observe(hello);
    } else if (mode=="plain") {
        for (int i=0;i<7;++i) filter.observe(std::array<std::uint8_t,1>{42});
    } else return 2;
    v::Sender sender(user); auto block=sender.prepare_large(filter,data,{0,0});
    if (!block || !sender.commit(true)) return 3;
    std::cout.write(reinterpret_cast<char const*>(block->wire.data()),static_cast<std::streamsize>(block->wire.size()));
    return std::cout ? 0 : 4;
}
