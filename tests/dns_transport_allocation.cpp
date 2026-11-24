import std;
import dns.message;
import dns.corosio_query;
import dns.response_query;
import dns.corosio_resolver;
import dns.message_program;
import dns.message_cache;
import dns.policy;
import capy;
import corosio;
namespace io = ::corosio;
using namespace std::chrono_literals;
namespace {
    struct alignas(std::max_align_t) Header {bool large;};
    std::atomic<int> large_live=0;
}
auto operator new(std::size_t size) -> void* {
    auto* p=static_cast<Header*>(std::malloc(sizeof(Header)+(size ? size : 1)));
    if(!p)throw std::bad_alloc();p->large=size>=60000;if(p->large)++large_live;return p+1;
}
void operator delete(void* value) noexcept {
    if(!value)return;auto* p=static_cast<Header*>(value)-1;if(p->large)--large_live;std::free(p);
}
void operator delete(void* value,std::size_t) noexcept {::operator delete(value);}
auto operator new[](std::size_t size) -> void* {return ::operator new(size);}
void operator delete[](void* value) noexcept {::operator delete(value);}
void operator delete[](void* value,std::size_t) noexcept {::operator delete(value);}

auto main(int argc,char** argv) -> int {
    if(argc!=4)return 2;
    bool uring=std::string_view(argv[1])=="uring";
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    if(uring)return 77;io::io_context context(io::epoll);
#endif
    auto port=static_cast<std::uint16_t>(std::strtoul(argv[2],nullptr,10));
    auto mode=std::string_view(argv[3]);bool tcp=mode.ends_with("tcp"),message=mode.starts_with("message-"),program_mode=mode.starts_with("program-");
    dns::detail::FallbackQuery operation(context,tcp);
    dns::detail::MessageQuery message_query(context,tcp);
    ::policy::DnsRule route;route.match_all=true;route.action=::policy::DnsAction::route;
    std::array rules{route};std::array<dns::MessageUpstream,1> upstreams{{{{io::ipv4_address::loopback(),port},tcp,nullptr}}};
    dns::MessageCache cache;dns::MessageProgram program(context,rules,upstreams,0,&cache);
    dns::QueryMessage query{42,0x0100,{"allocation.test",1},dns::QueryEdns{1232,0,false,{{65001,dns::Bytes(60000,0x5a)}}}};
    auto baseline=large_live.load();if(baseline!=1)return 3;
    bool done=false,observed=false,canceled=false,failed=false;
    auto work=[&]() -> capy::task<> {
        if(program_mode) {
            auto result=co_await program.run(std::move(query),std::chrono::steady_clock::now()+3s,{});
            canceled=!result && result.error()==dns::detail::ResolveError::canceled;
        } else if(message) {
            auto result=co_await message_query.run({io::ipv4_address::loopback(),port},std::move(query),std::chrono::steady_clock::now()+3s);
            canceled=!result && result.error()==dns::detail::ResolveError::canceled;
        } else {
            auto result=co_await operation.query({io::ipv4_address::loopback(),port},std::move(query),std::chrono::steady_clock::now()+3s);
            canceled=!result && result.error()==dns::detail::UdpError::canceled;
        }
        done=true;
    };
    auto stop=[&]() -> capy::task<> {
        io::steady_timer timer(context);timer.expires_at(std::chrono::steady_clock::now()+200ms);
        auto [error]=co_await timer.wait();if(!error){observed=large_live.load()==1;if(program_mode)program.cancel();else if(message)message_query.cancel();else operation.cancel();}
    };
    capy::run_async(context.get_executor(),[]() noexcept {},[&](std::exception_ptr) noexcept {failed=true;done=true;})(work());
    capy::run_async(context.get_executor())(stop());
    (void)context.run_for(4s);
    if(!done || failed || !observed || !canceled || large_live.load()!=0) {
        std::cerr<<"done="<<done<<" failed="<<failed<<" observed="<<observed<<" canceled="<<canceled<<" live="<<large_live.load()<<'\n';return 4;
    }
    std::cout<<"one owned large query while waiting, released after cancellation\n";
}
