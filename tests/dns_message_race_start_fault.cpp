import std;
import dns.message;
import dns.message_exchange;
import dns.message_race_program;
import dns.response_race_walk;
import dns.race_admission;
import dns.policy;
import dns.corosio_resolver;
import capy;
import corosio;
extern "C" int fcntl(int,int,...);
extern "C" int getsockopt(int,int,int,void*,unsigned int*);
namespace io = ::corosio;
using namespace std::chrono_literals;
namespace {
    thread_local int fail_after=-1;
    thread_local int seen=0,fd_at_failure=-1;
    thread_local int fail_phase=0;
    thread_local int* frame_remaining=nullptr;
    auto open_sockets() noexcept -> int {
        int count=0;
        for(int fd=0;fd<1024;++fd) {
            if(fcntl(fd,1)<0)continue;
            int type=0;unsigned int length=sizeof(type);
            if(getsockopt(fd,1,3,&type,&length)==0)++count; // SOL_SOCKET, SO_TYPE
        }
        return count;
    }
}
auto operator new(std::size_t size) -> void* {
    if(fail_after>=0 && size==sizeof(dns::EvaluatedMessageExchange)) {
        ++seen;
        if(fail_after--==0){
            fail_after=-1;fd_at_failure=open_sockets();
            if(!fail_phase)throw std::bad_alloc();
            *frame_remaining=fail_phase-1;
        }
    }
    if(auto* value=std::malloc(size ? size : 1))return value;
    throw std::bad_alloc();
}
auto operator new[](std::size_t size) -> void* {return ::operator new(size);}
void operator delete(void* p) noexcept {std::free(p);}
void operator delete(void* p,std::size_t) noexcept {std::free(p);}
void operator delete[](void* p) noexcept {std::free(p);}
void operator delete[](void* p,std::size_t) noexcept {std::free(p);}
class Frames final : public std::pmr::memory_resource {
    auto do_allocate(std::size_t n,std::size_t a) -> void* override {
        if(remaining==0){remaining=-1;++failures;throw std::bad_alloc();}
        if(remaining>0)--remaining;
        auto* p=std::pmr::new_delete_resource()->allocate(n,a);++live;return p;
    }
    auto do_deallocate(void* p,std::size_t n,std::size_t a) -> void override {--live;std::pmr::new_delete_resource()->deallocate(p,n,a);}
    auto do_is_equal(std::pmr::memory_resource const& other) const noexcept -> bool override {return this==&other;}
public:int live=0,remaining=-1,failures=0;
};
auto work(io::io_context& context,Frames& frames,std::uint16_t port,int position,int phase,bool& ok) -> capy::task<> {
    ::policy::DnsRule a;a.match_all=true;a.action=::policy::DnsAction::evaluate;a.evaluate_tag="slow";
    ::policy::DnsRule judge;judge.match_all=true;judge.match_response=true;judge.match_response_tag="slow";judge.action=::policy::DnsAction::respond;
    auto b=a;b.evaluate_tag="second";
    std::array rules{a,judge,b};
    std::array modes{dns::ResponseRaceMode{},dns::ResponseRaceMode{true,false},dns::ResponseRaceMode{false,true}};
    std::array<dns::MessageUpstream,1> upstreams{{{{io::ipv4_address::loopback(),port},false,nullptr}}};
    dns::MessageRaceProgram program(context,rules,modes,upstreams,0);
    auto baseline=open_sockets();seen=0;fd_at_failure=-1;fail_phase=phase;frame_remaining=&frames.remaining;frames.failures=0;fail_after=position;
    auto result=co_await program.run({42,0x0100,{"race.test",1},{}},std::chrono::steady_clock::now()+3s,{});
    fail_after=-1;frame_remaining=nullptr;
    ok=!result && result.error()==dns::detail::ResolveError::limit && seen==position+1 &&
        fd_at_failure==(baseline+(position ? 1 : 0)) && open_sockets()==baseline && frames.failures==(phase ? 1 : 0);
    if(!ok)std::cerr<<"position="<<position<<" phase="<<phase<<" result="<<(result ? -1 : static_cast<int>(result.error()))
        <<" seen="<<seen<<" sockets_at_failure="<<fd_at_failure<<" baseline="<<baseline<<" final="<<open_sockets()<<" frame_failures="<<frames.failures<<'\n';
}
auto main(int argc,char** argv) -> int {
    if(argc!=3)return 2;
    bool uring=std::string_view(argv[1])=="uring";
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    if(uring)return 77;io::io_context context(io::epoll);
#endif
    auto port=static_cast<std::uint16_t>(std::strtoul(argv[2],nullptr,10));
    Frames frames;context.set_frame_allocator(&frames);
    // Phase 3 fails the first child frame inside the running owner task,
    // after the two launch frames were allocated successfully.
    for(int position=0;position<2;++position)for(int phase=0;phase<4;++phase) {
        bool done=false,ok=false;
        capy::run_async(context.get_executor(),[&]() noexcept {done=true;},[&](std::exception_ptr) noexcept {done=true;})(work(context,frames,port,position,phase,ok));
        context.restart();(void)context.run_for(4s);
        if(!done || !ok || frames.live){std::cerr<<"done="<<done<<" ok="<<ok<<" frames="<<frames.live<<'\n';return 3;}
        std::array<std::optional<dns::RaceAdmission>,dns::RaceAdmission::maximum> leases;
        for(auto& lease:leases){lease.emplace();if(!lease->acquired())return 4;}
    }
    context.set_frame_allocator(std::pmr::new_delete_resource());
    std::cout<<"message race first/second allocation failure: socket, frames, admission drained\n";
}
