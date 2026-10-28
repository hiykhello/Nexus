import std;
import nexus.http2.server;

namespace nh = nexus::http2;

// The linker wraps calls from the statically linked session module, allowing a
// deterministic failure after budget admission without affecting setup.
static bool fail_realloc = false;
extern "C" void* __real_realloc(void*, std::size_t);
extern "C" void* __wrap_realloc(void* ptr, std::size_t size) {
    if (fail_realloc) { fail_realloc=false; return nullptr; }
    return __real_realloc(ptr,size);
}

extern "C" std::size_t probe_overhead();
extern "C" void* probe_allocate(nh::ServerSession*,std::size_t);
extern "C" void* probe_resize(nh::ServerSession*,void*,std::size_t);
extern "C" void probe_release(nh::ServerSession*,void*);

auto headers(void*,std::int32_t,std::span<nh::Header const>,bool,bool) noexcept -> bool { return true; }
auto data(void*,std::int32_t,std::span<std::byte const>) noexcept -> nh::DataDisposition { return nh::DataDisposition::accepted; }
auto end(void*,std::int32_t) noexcept -> bool { return true; }
void closed(void*,std::int32_t,std::uint32_t) noexcept {}

int main() {
    nh::ServerEvents events{nullptr,headers,data,end,closed};
    nh::ServerLimits limits{8,4,128,64,64};
    auto reference=nh::ServerSession::create(limits,events);
    if (!reference) return 1;
    auto baseline=(**reference).library_memory_used();
    auto creation_peak=(**reference).library_memory_peak();
    reference->reset();
    constexpr std::size_t old_size=32, new_size=64, competing=37;
    auto old_charge=old_size+probe_overhead(), new_charge=new_size+probe_overhead();
    auto threshold=baseline+old_charge+new_charge;
    if (creation_peak>threshold) return 2;

    // Both limits admit exactly the combined old and replacement allocations;
    // one byte less must preserve the old block and its accounting.
    for (bool shared : {false,true}) for (bool enough : {false,true}) {
        limits.library_memory_bytes=shared ? 4*1024*1024 : threshold-(enough ? 0 : 1);
        limits.shared_memory_bytes=shared ? threshold+competing-(enough ? 0 : 1) : 4*1024*1024;
        auto session=nh::ServerSession::create(limits,events);
        if (!session || (**session).library_memory_used()!=baseline) return 3;
        if (shared && !(**session).reserve_output(competing)) return 4;
        auto p=static_cast<unsigned char*>(probe_allocate(session->get(),old_size));
        if (!p) return 5;
        std::memset(p,0x5a,old_size);
        auto before=(**session).library_memory_used();
        auto resized=static_cast<unsigned char*>(probe_resize(session->get(),p,new_size));
        if (enough) {
            if (!resized || (**session).library_memory_used()!=baseline+new_charge ||
                (**session).library_memory_peak()!=threshold) return 6;
            p=resized;
        } else if (resized || (**session).library_memory_used()!=before) return 7;
        if (!std::ranges::all_of(std::span{p,old_size},[](auto c) { return c==0x5a; })) return 8;
        probe_release(session->get(),p);
        if ((**session).library_memory_used()!=baseline) return 9;
        if (shared) (**session).release_output();
    }

    limits.library_memory_bytes=4*1024*1024;
    limits.shared_memory_bytes=4*1024*1024;
    auto session=nh::ServerSession::create(limits,events);
    if (!session) return 10;
    auto p=static_cast<unsigned char*>(probe_allocate(session->get(),old_size));
    if (!p) return 11;
    std::memset(p,0xa5,old_size);
    auto before=(**session).library_memory_used(), peak=(**session).library_memory_peak();
    fail_realloc=true;
    auto resized=probe_resize(session->get(),p,new_size);
    if (fail_realloc || resized || (**session).library_memory_used()!=before || (**session).library_memory_peak()!=peak ||
        !std::ranges::all_of(std::span{p,old_size},[](auto c) { return c==0xa5; })) return 12;
    auto retry=static_cast<unsigned char*>(probe_resize(session->get(),p,new_size));
    if (!retry || (**session).library_memory_used()!=baseline+new_charge ||
        !std::ranges::all_of(std::span{retry,old_size},[](auto c) { return c==0xa5; })) return 14;
    p=retry;
    probe_release(session->get(),p);
    if ((**session).library_memory_used()!=baseline) return 13;
    std::println("HTTP/2 allocator resize limits and failure passed");
}
