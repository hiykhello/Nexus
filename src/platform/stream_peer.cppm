#if !defined(__linux__) || (!defined(__x86_64__) && !defined(__aarch64__)) || !defined(__LP64__)
#error "The stream peer boundary is verified for Linux x86-64 / aarch64 LP64 only"
#endif
export module platform.stream_peer;
import std;

export namespace platform::stream_peer_abi {
    struct Descriptor { int fd; short events,revents; };
    using Count=unsigned long;
    inline constexpr short read_hangup=0x2000,hangup=0x10,error=0x8,invalid=0x20;
}
namespace platform::stream_peer_abi {
    extern "C" int poll(Descriptor*,Count,int);
}
export namespace platform {
    // Detect terminal socket state under application backpressure without
    // consuming buffered bytes or adding a read to the ordinary packet path.
    inline auto stream_peer_closed(int fd) noexcept -> bool {
        using namespace stream_peer_abi;
        Descriptor descriptor{fd,read_hangup,0};
        return poll(&descriptor,1,0)>0 && (descriptor.revents&(read_hangup|hangup|error|invalid));
    }
}
