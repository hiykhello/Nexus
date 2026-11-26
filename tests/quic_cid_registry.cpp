import std;
import quic.cid_registry;
namespace q=quic;
auto main() -> int {
    q::CidRegistry<2,3> registry;auto a=registry.reserve(),b=registry.reserve();if(!a||!b||registry.reserve().error()!=q::CidError::capacity)return 1;
    std::array<std::uint8_t,8> first{1},second{2},third{3},fourth{4};
    if(!registry.insert(*a,first)||!registry.insert(*a,first)||!registry.insert(*a,second)||!registry.insert(*a,third))return 2;
    if(registry.insert(*a,fourth).error()!=q::CidError::capacity||registry.insert(*b,first).error()!=q::CidError::collision)return 3;
    if(registry.find(first)!=*a||registry.remove(*b,first)||!registry.remove(*a,second)||!registry.insert(*a,fourth))return 4;
    auto stale=*a;if(!registry.release(*a)||registry.find(first)||registry.live(stale)||registry.release(stale))return 5;
    auto next=registry.reserve();if(!next||next->slot!=stale.slot||next->generation==stale.generation)return 6;
    if(registry.insert(stale,first).error()!=q::CidError::invalid_owner||!registry.insert(*next,first)||registry.find(first)!=*next)return 7;
    std::array<std::uint8_t,21> long_id{};if(registry.insert(*next,long_id).error()!=q::CidError::invalid_cid||registry.find(long_id)||registry.find({}))return 8;
    registry.clear();if(registry.size()||registry.live(*next)||registry.find(first))return 9;
    auto after=registry.reserve();if(!after||after->generation==next->generation)return 10;
    for(unsigned i=0;i<100000;++i){if(!registry.insert(*after,first)||registry.find(first)!=*after||!registry.release(*after))return 11;after=registry.reserve();if(!after)return 12;}
    q::CidRegistry<8,8> dense;
    std::array<q::SessionHandle,8> owners{};
    for(std::size_t i=0;i<owners.size();++i){auto h=dense.reserve();if(!h)return 13;owners[i]=*h;}
    auto make_cid=[](std::size_t k){std::array<std::uint8_t,8> c{};c[0]=static_cast<std::uint8_t>(k);c[1]=static_cast<std::uint8_t>(k>>8);c[7]=0xa5;return c;};
    for(std::size_t i=0;i<64;++i)if(!dense.insert(owners[i/8],make_cid(i)))return 14;
    for(std::size_t i=0;i<64;i+=2)if(!dense.remove(owners[i/8],make_cid(i))||dense.find(make_cid(i)))return 15;
    for(std::size_t i=1;i<64;i+=2)if(dense.find(make_cid(i))!=owners[i/8])return 16;
    for(std::size_t i=0;i<64;i+=2)if(!dense.insert(owners[i/8],make_cid(i+1000))||dense.find(make_cid(i+1000))!=owners[i/8])return 17;
    for(std::size_t i=0;i<4;++i)if(!dense.release(owners[i]))return 18;
    for(std::size_t i=0;i<32;++i)if(dense.find(make_cid(i%2?i:i+1000)))return 19;
    for(std::size_t i=32;i<64;++i)if(dense.find(make_cid(i%2?i:i+1000))!=owners[i/8])return 20;
    std::println("bounded QUIC CID registry: collisions, per-owner/port limits, exact public IDs, retirement, 100000 nonreviving slot generations; owner={} bytes",sizeof(registry));
}
