// Isolate the pinned Xenium hazard_pointer empty-guard destruction path.
#include <xenium/reclamation/hazard_pointer.hpp>
using Reclaimer=xenium::reclamation::hazard_pointer<>;
struct Node : Reclaimer::enable_concurrent_ptr<Node> {};
int main() {
    using Slot=Reclaimer::concurrent_ptr<Node>;
    Slot::guard_ptr empty;
}
