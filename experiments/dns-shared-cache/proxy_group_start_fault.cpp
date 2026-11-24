// Allocation-failure rollback for the test-only shared DNS refresh integration.
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/udp_socket.hpp>
#include <boost/corosio/timeout.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
import std;
import containers.inplace_vector;
import dns.corosio_local;
import dns.message;
import dns.corosio_query;
import dns.cache;
import dns.shared_cache;
import relay;
import config;
import crypto;
import rules;
import dns.local_config;
import shadowsocks.udp_dispatch;
#include "udp_inbound.hpp"

namespace {
thread_local int fail_after=-1;
thread_local bool injected=false,late_failure=false;
thread_local bool watch_tcp=false;
thread_local std::uint16_t watched_udp=0;
enum class FaultStage { none,refresh,launch };
FaultStage stage=FaultStage::none;
unsigned target_call=0,hook_calls=0;
auto inject_hook(FaultStage where) -> void {
    if (stage==where && ++hook_calls==target_call) throw std::bad_alloc();
}

// This runs during operator new and must not allocate itself.
auto observe_sockets() noexcept -> bool {
    unsigned tcp_listeners=0;
    bool udp_found=false;
    for (int fd=3;fd<1024;++fd) {
        int type=0,accepting=0; socklen_t size=sizeof(type);
        if (::getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&size)) continue;
        if (watch_tcp && type==SOCK_STREAM) {
            size=sizeof(accepting);
            if (!::getsockopt(fd,SOL_SOCKET,SO_ACCEPTCONN,&accepting,&size) && accepting) ++tcp_listeners;
        }
        if (watched_udp && type==SOCK_DGRAM) {
            sockaddr_in address{}; size=sizeof(address);
            if (!::getsockname(fd,reinterpret_cast<sockaddr*>(&address),&size) &&
                address.sin_family==AF_INET && ntohs(address.sin_port)==watched_udp) udp_found=true;
        }
    }
    return watch_tcp ? tcp_listeners>=2 : udp_found;
}
}
void* operator new(std::size_t size) {
    if (fail_after>=0 && fail_after--==0) {
        fail_after=-1; injected=true; late_failure|=observe_sockets();
        throw std::bad_alloc();
    }
    if (auto* memory=std::malloc(size ? size : 1)) return memory;
    throw std::bad_alloc();
}
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete(void* memory,std::size_t) noexcept { std::free(memory); }
extern "C" void nexus_test_dns_shared_access(void const*) noexcept {}
extern "C" void nexus_test_group_refresh_construct() { inject_hook(FaultStage::refresh); }
extern "C" void nexus_test_start_throw() { inject_hook(FaultStage::launch); }

namespace {
using Cache=dns_hp_experiment::GroupSnapshot;
using Budget=dns::detail::RefreshBudget;
namespace p = relay;

auto count(std::string_view path) -> std::size_t {
    return std::ranges::distance(std::filesystem::directory_iterator(path),std::filesystem::directory_iterator{});
}
auto free_udp_port() -> std::uint16_t {
    int fd=::socket(AF_INET,SOCK_DGRAM,0);
    if (fd<0) throw std::runtime_error("cannot allocate UDP port");
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    socklen_t size=sizeof(address);
    if (::bind(fd,reinterpret_cast<sockaddr*>(&address),size) ||
        ::getsockname(fd,reinterpret_cast<sockaddr*>(&address),&size)) {
        ::close(fd); throw std::runtime_error("cannot bind UDP port");
    }
    ::close(fd); return ntohs(address.sin_port);
}
auto ensure(bool value,char const* reason) -> void {
    if (!value) throw std::runtime_error(reason);
}
auto claim_readers(Cache& cache,std::size_t first,std::size_t count) -> void {
    for (std::size_t index=first;index<first+count;++index) {
        auto reader=cache.reader(index);
    }
}
auto routing() -> p::DnsRouting {
    p::DnsServer upstream; upstream.address[0]=127; upstream.address[3]=1; upstream.port=53;
    p::DnsRouting result; result.servers.push_back(upstream); return result;
}
auto settled_threads(std::size_t maximum) -> bool {
    using namespace std::chrono_literals;
    for (unsigned attempt=0;attempt<50;++attempt) {
        if (count("/proc/self/task")<=maximum) return true;
        std::this_thread::sleep_for(2ms);
    }
    return false;
}
auto tcp_faults(unsigned workers) -> void {
    std::array<std::size_t,2> capacities{16,16};
    Cache old(capacities,3,10000,1024*1024),fresh(capacities,3,10000,1024*1024);
    Budget old_budget(8),fresh_budget(8);
    p::Server server;
    ensure(server.set_dns_routing(routing()).has_value(),"TCP routing setup failed");
    auto bind=[&](Cache& cache,Budget& budget) {
        ensure(server.set_dns_group_for_test(cache,0,0,&budget).has_value(),"TCP owner rebind failed");
    };
    auto start=[&] {
        auto result=server.start(0,p::Inbound::socks5,workers);
        ensure(result.has_value() && server.healthy(),"TCP start failed");
    };
    bind(fresh,fresh_budget); start(); server.stop(); bind(old,old_budget);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    auto fds=count("/proc/self/fd"),threads=count("/proc/self/task");
    unsigned failures=0;
    for (auto selected:{FaultStage::refresh,FaultStage::launch}) {
        for (unsigned ordinal=1;ordinal<=workers;++ordinal) {
            stage=selected; target_call=ordinal; hook_calls=0;
            bool caught=false;
            try { (void)server.start(0,p::Inbound::socks5,workers); }
            catch (std::bad_alloc const&) { caught=true; }
            stage=FaultStage::none;
            ensure(caught && hook_calls==ordinal,"TCP fault hook did not fire");
            ++failures; server.stop();
            ensure(!old_budget.active(),"old TCP refresh budget still active");
            bind(fresh,fresh_budget); claim_readers(old,0,workers);
            start(); server.stop();
            ensure(!fresh_budget.active(),"new TCP refresh budget still active");
            bind(old,old_budget); claim_readers(fresh,0,workers);
            ensure(count("/proc/self/fd")==fds && settled_threads(threads),"TCP start leaked resources");
        }
    }
    bind(fresh,fresh_budget); claim_readers(old,0,workers);
    std::println("TCP {} worker(s): {} refresh construction/launch faults recovered",workers,failures);
}
// A separate diagnostic intentionally leaves failures inside third-party
// noexcept code observable. Some allocation positions may terminate the process.
auto tcp_allocation_probe(int position) -> void {
    std::array<std::size_t,2> capacities{16,16};
    Cache old(capacities,3,10000,1024*1024),fresh(capacities,3,10000,1024*1024);
    Budget old_budget(8),fresh_budget(8); p::Server server;
    ensure(server.set_dns_routing(routing()).has_value(),"probe routing failed");
    ensure(server.set_dns_group_for_test(fresh,0,0,&fresh_budget).has_value(),"probe fresh bind failed");
    ensure(server.start(0,p::Inbound::socks5,2).has_value(),"probe warmup failed");
    server.stop();
    ensure(server.set_dns_group_for_test(old,0,0,&old_budget).has_value(),"probe old bind failed");
    injected=false; late_failure=false; watch_tcp=true; fail_after=position;
    try { (void)server.start(0,p::Inbound::socks5,2); }
    catch (std::bad_alloc const&) {}
    fail_after=-1; watch_tcp=false; server.stop();
    std::println("allocation position {}: injected={}, reached two listeners={}",position,injected,late_failure);
}
auto udp_faults() -> void {
    std::array<std::size_t,2> capacities{16,16};
    Cache old(capacities,3,10000,1024*1024),fresh(capacities,3,10000,1024*1024);
    Budget old_budget(8),fresh_budget(8);
    UdpInbounds owner;
    auto policy=::rules::RouteMatcher::compile({},0,1);
    ensure(policy.has_value(),"UDP policy failed");
    auto first=free_udp_port(),second=free_udp_port();
    while (first==second) second=free_udp_port();
    std::array<std::uint8_t,16> a{},b{}; std::iota(a.begin(),a.end(),0); std::iota(b.begin(),b.end(),16);
    ensure(owner.add(a,first,*policy).has_value() && owner.add(b,second,*policy).has_value(),"UDP listener setup failed");
    auto settings=routing();
    auto bind=[&](Cache& cache,Budget& budget) {
        ensure(owner.set_dns_group_for_test(cache,1,2,&budget),"UDP owner rebind failed");
    };
    auto start=[&] { ensure(!owner.start(settings) && owner.healthy(),"UDP start failed"); };
    bind(fresh,fresh_budget); start(); owner.stop(); bind(old,old_budget);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    auto fds=count("/proc/self/fd"),threads=count("/proc/self/task");
    unsigned failures=0; bool exhausted=false; late_failure=false; watched_udp=second;
    for (int position=0;position<256;++position) {
        injected=false; fail_after=position;
        try {
            auto error=owner.start(settings);
            fail_after=-1;
            if (!injected) { ensure(!error,"UDP uninjected start failed"); exhausted=true; }
            else ensure(static_cast<bool>(error),"UDP injected start unexpectedly succeeded");
        } catch (std::bad_alloc const&) {
            fail_after=-1; ensure(injected,"unexpected UDP allocation failure");
        }
        owner.stop();
        if (injected) ++failures;
        ensure(!old_budget.active(),"old UDP refresh budget still active");
        bind(fresh,fresh_budget); claim_readers(old,2,1);
        start(); owner.stop();
        ensure(!fresh_budget.active(),"new UDP refresh budget still active");
        bind(old,old_budget); claim_readers(fresh,2,1);
        ensure(count("/proc/self/fd")==fds && settled_threads(threads),"UDP start leaked resources");
        if (exhausted) break;
    }
    ensure(exhausted && failures && late_failure,"UDP allocation sweep did not reach second listener");
    watched_udp=0;
    bind(fresh,fresh_budget); claim_readers(old,2,1);
    std::println("two SS UDP groups: {} startup allocation failures recovered",failures);
}
}
int main(int argc,char** argv) {
    try {
        if (argc==3 && std::string_view(argv[1])=="--tcp-allocation") {
            auto position=std::stoi(argv[2]);
            ensure(position>=0 && position<256,"invalid allocation position");
            tcp_allocation_probe(position);
        } else {
            ensure(argc==1,"unexpected arguments");
            tcp_faults(1); tcp_faults(2); udp_faults();
        }
    }
    catch (std::exception const& error) { fail_after=-1; std::println(stderr,"group startup fault: {}",error.what()); return 1; }
}
