// Demonstrate the pinned reclaimer's noexcept scan on allocation failure.
#include <xenium/reclamation/hazard_pointer.hpp>
#include <cstdlib>
#include <exception>
#include <new>
namespace { bool fail=false; }
void* operator new(std::size_t n) {
    if (fail) throw std::bad_alloc();
    if (auto* p=std::malloc(n ? n : 1)) return p;
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { std::free(p); }
using Reclaimer=xenium::reclamation::hazard_pointer<>::with<
    xenium::policy::allocation_strategy<xenium::reclamation::hp_allocation::static_strategy<3,0,1>>>;
struct Node : Reclaimer::enable_concurrent_ptr<Node> {};
int main() {
    std::set_terminate([] { std::_Exit(42); });
    using Slot=Reclaimer::concurrent_ptr<Node>;
    Slot::guard_ptr guard{Slot::marked_ptr(new Node)};
    fail=true;
    guard.reclaim();
    fail=false;
    return 0;
}
