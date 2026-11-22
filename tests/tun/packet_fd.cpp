#include <cerrno>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import packet.fd;
namespace p = ::packet;
static bool fail_packet_allocation=false;
void* operator new(std::size_t size) {
    if (fail_packet_allocation && size==3) { fail_packet_allocation=false; throw std::bad_alloc{}; }
    if (auto p=std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { std::free(p); }
struct Pair { int fd[2]{-1,-1}; ~Pair() { for (int n:fd) if (n>=0) ::close(n); } };
int main() {
    Pair pair;
    if (::socketpair(AF_UNIX,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair.fd)) return 1;
    p::MemoryLink link({128,1,128});
    auto invalid=p::FdPump::create(-1,link,128);
    if (invalid || std::get<p::FdError>(invalid.error())!=p::FdError::invalid_fd) return 1;
    Pair blocking; if (::socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,blocking.fd)) return 1;
    auto denied=p::FdPump::create(blocking.fd[0],link,128);
    if (denied || std::get<p::FdError>(denied.error())!=p::FdError::blocking_fd) return 1;
    auto pump=p::FdPump::create(pair.fd[0],link,128); if (!pump) return 1;
    p::Bytes first{1,2,3}, second{4,5};
    if (!link.send(p::Side::first,first) || ::send(pair.fd[1],second.data(),second.size(),0)!=2) return 1;
    auto blocked=pump->step(); if (!blocked.input || !blocked.input_backpressured) return 1;
    auto consumed=link.receive(p::Side::second); if (!consumed || !*consumed || **consumed!=first) return 1;
    auto retried=pump->step(); if (!retried.input_delivered || retried.input) return 1;
    consumed=link.receive(p::Side::second); if (!consumed || !*consumed || **consumed!=second) return 1;
    p::Bytes large(129,8);
    if (::send(pair.fd[1],large.data(),large.size(),0)!=129) return 1;
    auto oversized=pump->step();
    if (!oversized.input_error || std::get<p::FdError>(*oversized.input_error)!=p::FdError::packet_too_large) return 1;
    if (::send(pair.fd[1],first.data(),first.size(),0)!=3 || !pump->step().input_delivered) return 1;
    consumed=link.receive(p::Side::second); if (!consumed || !*consumed || **consumed!=first) return 1;
    if (::send(pair.fd[1],first.data(),first.size(),0)!=3) return 1;
    fail_packet_allocation=true;
    auto failed=pump->step();
    if (fail_packet_allocation || !failed.input || !failed.input_backpressured || failed.input_delivered) return 1;
    auto empty=link.receive(p::Side::second); if (!empty || *empty) return 1;
    auto recovered=pump->step(); if (recovered.input || !recovered.input_delivered) return 1;
    consumed=link.receive(p::Side::second); if (!consumed || !*consumed || **consumed!=first) return 1;
    empty=link.receive(p::Side::second); if (!empty || *empty) return 1;
    p::Bytes filler(100,7); int filled=0;
    while (::send(pair.fd[0],filler.data(),filler.size(),0)==static_cast<ssize_t>(filler.size())) ++filled;
    if (!filled || (errno!=EAGAIN && errno!=EWOULDBLOCK) || !link.send(p::Side::second,second)) return 1;
    auto full=pump->step(); if (!full.output_backpressured || full.output_delivered) return 1;
    std::array<std::uint8_t,128> buffer{};
    for (int i=0;i<filled;++i) if (::recv(pair.fd[1],buffer.data(),buffer.size(),0)!=100) return 1;
    auto drained=pump->step();
    if (!drained.output_delivered || ::recv(pair.fd[1],buffer.data(),buffer.size(),0)!=2 ||
        !std::ranges::equal(std::span(buffer).first(2),second)) return 1;
    while (::send(pair.fd[0],filler.data(),filler.size(),0)==static_cast<ssize_t>(filler.size())) {}
    if (errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
    std::weak_ptr<p::TcpGeneration> lifetime;
    {
        auto scoped=p::FdPump::create(pair.fd[0],link,128); if (!scoped) return 1;
        auto token=std::make_shared<p::TcpGeneration>(); lifetime=token;
        if (!link.send(p::Side::second,second,p::PacketKind::ordinary,0,token)) return 1;
        token.reset();
        auto pending=scoped->step(); if (!pending.output_backpressured || lifetime.expired()) return 1;
    }
    if (!lifetime.expired()) return 1;
    while (::recv(pair.fd[1],buffer.data(),buffer.size(),0)>0) {}
    if (errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
    auto stale=std::make_shared<p::TcpGeneration>(); stale->valid=false;
    if (!link.send(p::Side::second,second,p::PacketKind::ordinary,0,stale)) return 1;
    auto discarded=pump->step();
    if (!discarded.output_discarded || discarded.output_delivered ||
        ::recv(pair.fd[1],buffer.data(),buffer.size(),0)!=-1 || (errno!=EAGAIN && errno!=EWOULDBLOCK)) return 1;
    int filled_again=0;
    while (::send(pair.fd[0],filler.data(),filler.size(),0)==static_cast<ssize_t>(filler.size())) ++filled_again;
    if (!filled_again || (errno!=EAGAIN && errno!=EWOULDBLOCK)) return 1;
    auto retry_token=std::make_shared<p::TcpGeneration>();
    if (!link.send(p::Side::second,second,p::PacketKind::ordinary,0,retry_token)) return 1;
    if (!pump->step().output_backpressured) return 1;
    retry_token->valid=false;
    for (int i=0;i<filled_again;++i) if (::recv(pair.fd[1],buffer.data(),buffer.size(),0)!=100) return 1;
    discarded=pump->step();
    if (!discarded.output_discarded || discarded.output_delivered ||
        ::recv(pair.fd[1],buffer.data(),buffer.size(),0)!=-1 || (errno!=EAGAIN && errno!=EWOULDBLOCK)) return 1;
    if (!link.send(p::Side::second,second) || !pump->step().output_delivered ||
        ::recv(pair.fd[1],buffer.data(),buffer.size(),0)!=2 || !std::ranges::equal(std::span(buffer).first(2),second)) return 1;
    std::cout << "packet descriptor pump preserves packets through backpressure\n";
}
