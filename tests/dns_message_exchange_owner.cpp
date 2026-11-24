import std;
import dns.evaluate_owner;
import dns.message_exchange;
import dns.message;
import dns.response_program;
import dns.corosio_resolver;
import capy;
import corosio;

namespace io = ::corosio;
using Result=std::expected<dns::Bytes,dns::detail::ResolveError>;
using Owner=dns::EvaluateOwner<dns::MessageExchange,Result,2>;
auto check(Owner& owner,Owner::Handle first,Owner::Handle second,bool& ok) -> capy::task<> {
    for(;;) {
        auto epoch=owner.epoch();auto result=owner.inspect(second);
        if(!result)co_return;
        if(result->ready) {
            auto pending=owner.inspect(first);
            if(!result->result || !*result->result || result->exception || !pending || pending->ready)co_return;
            break;
        }
        auto [error]=co_await owner.wait(epoch);if(error)co_return;
    }
    if(!owner.cancel(first))co_return;
    while(!owner.drained()) {
        auto epoch=owner.epoch();if(owner.drained())break;
        auto [error]=co_await owner.wait(epoch);if(error)co_return;
    }
    auto canceled=owner.inspect(first),success=owner.inspect(second);
    ok=canceled && canceled->ready && canceled->result && !*canceled->result &&
        canceled->result->error()==dns::detail::ResolveError::canceled && success && success->ready &&
        canceled->completion>success->completion && owner.release(first) && owner.release(second);
}
auto main(int argc,char** argv) -> int {
    if(argc!=4)return 2;
    auto port=[](char const* text)->std::uint16_t {return static_cast<std::uint16_t>(std::strtoul(text,nullptr,10));};
    bool uring=std::string_view(argv[3])=="uring";
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    if(uring)return 77;io::io_context context(io::epoll);
#endif
    std::array<dns::MessageUpstream,2> upstreams{{
        {{io::ipv4_address::loopback(),port(argv[1])},false,nullptr},
        {{io::ipv4_address::loopback(),port(argv[2])},false,nullptr}}};
    dns::QueryMessage query{42,0x0100,{"owner.test",1},{}};
    auto make=[&](std::size_t index) {
        dns::ResponseStep step{.action=dns::ResponseAction::evaluate,.server=index};
        return std::make_unique<dns::MessageExchange>(context,upstreams,nullptr,
            query,step,std::chrono::steady_clock::now()+std::chrono::seconds(3));
    };
    Owner owner(context);auto first=owner.start(make(0));auto second=owner.start(make(1));
    if(!first || !second)return 3;
    bool ok=false,done=false;
    capy::run_async(context.get_executor(),[&]() noexcept {done=true;},[&](std::exception_ptr) noexcept {done=true;})(check(owner,*first,*second,ok));
    (void)context.run_for(std::chrono::seconds(5));
    if(!done || !owner.drained()){owner.stop();context.restart();(void)context.run();return 4;}
    return ok ? 0 : 5;
}
