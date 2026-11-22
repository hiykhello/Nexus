// Check the pinned mm_hp scan's allocation-failure fallback.
#include "mm_hp.hpp"
#include <atomic>
#include <cstdlib>
#include <new>
namespace { bool fail=false; unsigned failed_allocations=0; std::atomic<unsigned> deleted=0; }
void* operator new(std::size_t n) {
    if (fail) { ++failed_allocations; throw std::bad_alloc(); }
    if (auto* p=std::malloc(n ? n : 1)) return p;
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { std::free(p); }
struct Node : std::hazard_pointer_obj_base<Node> { ~Node() { ++deleted; } };
int main() {
    auto guard=std::make_hazard_pointer();
    for (unsigned i=0;i<999;++i) (new Node)->retire();
    auto* last=new Node;
    fail=true;
    last->retire();
    fail=false;
    return failed_allocations>0 && deleted==1000 ? 0 : 1;
}
