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
    std::println("bounded QUIC CID registry: collisions, per-owner/port limits, exact public IDs, retirement, 100000 nonreviving slot generations; owner={} bytes",sizeof(registry));
}
