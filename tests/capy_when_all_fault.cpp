#include <boost/capy/ex/recycling_memory_resource.hpp>
#include <cstddef>
#include <new>

namespace capy = boost::capy;

int fail_after = -1;
int allocations = 0;
int releases = 0;
// Override the weak process-frame allocation functions in this test binary.
// Production targets keep Capy's normal recycling allocator implementation.
extern "C" void* test_frame_new(std::size_t size)
    asm("_ZN5boost4capy6detail19process_frame_mixinnwEm");
extern "C" void test_frame_delete(void* p, std::size_t size)
    asm("_ZN5boost4capy6detail19process_frame_mixindlEPvm");
extern "C" void* test_frame_new(std::size_t size) {
    if (fail_after == 0) throw std::bad_alloc{};
    if (fail_after > 0) --fail_after;
    auto* resource = static_cast<capy::recycling_memory_resource*>(capy::get_recycling_memory_resource());
    auto* p = resource->allocate_fast(size, alignof(std::max_align_t));
    if (fail_after >= 0) ++allocations;
    return p;
}
extern "C" void test_frame_delete(void* p, std::size_t size) {
    if (fail_after >= 0) ++releases;
    auto* resource = static_cast<capy::recycling_memory_resource*>(capy::get_recycling_memory_resource());
    resource->deallocate_fast(p, size, alignof(std::max_align_t));
}

