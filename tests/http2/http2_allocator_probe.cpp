module http2.server;
import std;

namespace http2::detail {
    struct ServerAllocatorTest {
        static auto overhead() -> std::size_t { return sizeof(ServerSession::Allocation); }
        static auto allocate(ServerSession& s, std::size_t n) -> void* { return ServerSession::allocate(n,&s); }
        static auto resize(ServerSession& s, void* p, std::size_t n) -> void* { return ServerSession::resize(p,n,&s); }
        static void release(ServerSession& s, void* p) { ServerSession::deallocate(p,&s); }
    };
}
extern "C" std::size_t probe_overhead() { return http2::detail::ServerAllocatorTest::overhead(); }
extern "C" void* probe_allocate(http2::ServerSession* s,std::size_t n) { return http2::detail::ServerAllocatorTest::allocate(*s,n); }
extern "C" void* probe_resize(http2::ServerSession* s,void* p,std::size_t n) { return http2::detail::ServerAllocatorTest::resize(*s,p,n); }
extern "C" void probe_release(http2::ServerSession* s,void* p) { http2::detail::ServerAllocatorTest::release(*s,p); }
