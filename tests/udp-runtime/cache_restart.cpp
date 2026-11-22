#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
import std;
import proxy;
import rules;
import ss_udp.inbounds;

namespace {
    thread_local int fail_after=-1;
    thread_local std::uint16_t watched_port=0;
    thread_local bool failed_after_second_bind=false;
}
void* operator new(std::size_t size) {
    if (fail_after>=0 && fail_after--==0) {
        fail_after=-1;
        for (int fd=3;fd<256;++fd) {
            sockaddr_in address{}; socklen_t length=sizeof(address);
            if (::getsockname(fd,reinterpret_cast<sockaddr*>(&address),&length)==0 &&
                address.sin_family==AF_INET && ntohs(address.sin_port)==watched_port)
                failed_after_second_bind=true;
        }
        throw std::bad_alloc();
    }
    if (void* memory=std::malloc(size ? size : 1)) return memory;
    throw std::bad_alloc();
}
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete(void* memory,std::size_t) noexcept { std::free(memory); }

int main(int argc,char** argv) {
    if (argc!=5) return 1;
    auto parse_port=[](char const* text) -> std::optional<std::uint16_t> {
        auto value=std::strtoul(text,nullptr,10);
        if (!value || value>65535) return std::nullopt;
        return static_cast<std::uint16_t>(value);
    };
    std::array<std::uint16_t,4> ports{};
    for (std::size_t i=0;i<ports.size();++i) {
        auto value=parse_port(argv[i+1]);
        if (!value) return 2;
        ports[i]=*value;
    }
    auto policy=::rules::RouteMatcher::compile({},0,1);
    if (!policy) return 3;
    std::array<std::uint8_t,16> first{},second{};
    std::iota(first.begin(),first.end(),0); std::iota(second.begin(),second.end(),16);
    proxy::udp_runtime::UdpInbounds owner;
    if (!owner.add(first,ports[0],*policy) || !owner.add(second,ports[1],*policy)) return 4;
    proxy::DnsRouting routing;
    routing.strategy=proxy::DnsStrategy::ipv4_only;
    proxy::DnsServer upstream;
    upstream.address[0]=127; upstream.address[3]=1; upstream.port=ports[2];
    routing.servers.push_back(std::move(upstream));
    // Fail each allocation during start and prove the same owner can be
    // started again. Reaching the second bind proves the first listener has
    // already started and has tasks that must be canceled and drained.
    watched_port=ports[1];
    bool exhausted=false; unsigned failures=0;
    for (int position=0;position<256;++position) {
        fail_after=position;
        try {
            auto error=owner.start(routing);
            fail_after=-1;
            owner.stop();
            if (!error) { exhausted=true; break; }
            ++failures;
        } catch (std::bad_alloc const&) {
            fail_after=-1;
            ++failures;
        }
        if (owner.start(routing)) return 11;
        owner.stop();
    }
    if (!exhausted || !failures || !failed_after_second_bind) return 12;
    std::cerr << "SS UDP start allocation failures checked: " << failures << '\n';
    if (owner.start(routing)) return 5;
    if (owner.start(routing)!=std::make_error_code(std::errc::operation_in_progress) ||
        owner.add(first,ports[0],*policy)) return 6;
    std::cout << "ready" << std::endl;
    for (;;) {
        owner.poll(std::chrono::milliseconds(2));
        if (!owner.healthy()) return 7;
        pollfd input{0,POLLIN,0};
        if (::poll(&input,1,0)<0) return 8;
        if (input.revents & (POLLIN|POLLHUP)) {
            std::string command;
            if (!std::getline(std::cin,command) || command=="stop") break;
            if (command!="restart") return 9;
            owner.stop();
            routing.servers[0].port=ports[3];
            if (owner.start(routing)) return 10;
            std::cout << "ready" << std::endl;
        }
    }
    owner.stop();
    return 0;
}
