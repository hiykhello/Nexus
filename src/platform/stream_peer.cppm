module;
#if defined(__linux__)
#if (!defined(__x86_64__) && !defined(__aarch64__)) || !defined(__LP64__)
#error "The stream peer boundary is verified for Linux x86-64 / aarch64 LP64 only"
#endif
#include <poll.h>
#elif defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#if defined(_MSC_VER)
#pragma comment(lib, "ws2_32.lib")
#endif
#else
#include <poll.h>
#endif
export module platform.stream_peer;
import std;

export namespace platform::stream_peer_abi {
    struct Descriptor { int fd; short events,revents; };
    using Count=unsigned long;
    inline constexpr short read_hangup=0x2000,hangup=0x10,error=0x8,invalid=0x20;
}
export namespace platform {
    // Detect terminal socket state under application backpressure without
    // consuming buffered bytes or adding a read to the ordinary packet path.
    inline auto stream_peer_closed(int fd) noexcept -> bool {
        if (fd<0) return false;
#if defined(__linux__)
        using namespace stream_peer_abi;
        Descriptor descriptor{fd,read_hangup,0};
        static_assert(sizeof(Descriptor)==sizeof(::pollfd));
        return ::poll(reinterpret_cast<::pollfd*>(&descriptor),1,0)>0 &&
            (descriptor.revents&(read_hangup|hangup|error|invalid));
#elif defined(_WIN32)
        WSAPOLLFD descriptor{static_cast<SOCKET>(fd),0,0};
        return ::WSAPoll(&descriptor,1,0)>0 && (descriptor.revents&(POLLHUP|POLLERR|POLLNVAL));
#else
        short events=0;
        short mask=POLLHUP|POLLERR|POLLNVAL;
#ifdef POLLRDHUP
        events=POLLRDHUP;
        mask|=POLLRDHUP;
#endif
        ::pollfd descriptor{fd,events,0};
        return ::poll(&descriptor,1,0)>0 && (descriptor.revents&mask);
#endif
    }
}
