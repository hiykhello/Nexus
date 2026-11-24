import std;
import dns.evaluate_owner;
import dns.response_query;
import dns.corosio_resolver;
import dns.message;
import capy;
import corosio;

namespace io = ::corosio;
using Result=std::expected<dns::Bytes,dns::detail::ResolveError>;
struct Operation {
    dns::detail::MessageQuery query;
    io::endpoint upstream;
    Operation(io::io_context& ctx,std::uint16_t port):query(ctx,false),upstream(io::ipv4_address::loopback(),port) {}
    auto cancel() noexcept -> void {query.cancel();}
    auto run() -> capy::task<Result> {
        co_return co_await query.run(upstream,{42,0x0100,{"owner.test",1},{}},std::chrono::steady_clock::now()+std::chrono::seconds(3));
    }
};
using Owner=dns::EvaluateOwner<Operation,Result,2>;
auto check(Owner& owner,Owner::Handle first,Owner::Handle second,bool& ok) -> capy::task<> {
    for(;;) {
        auto epoch=owner.epoch();auto result=owner.inspect(second);
        if(!result)co_return;
        if(result->ready) {
            auto slow=owner.inspect(first);
            if(!result->result || !*result->result || result->exception || !slow || slow->ready)co_return;
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
    Owner owner(context);auto first=owner.start(std::make_unique<Operation>(context,port(argv[1])));
    auto second=owner.start(std::make_unique<Operation>(context,port(argv[2])));
    if(!first || !second)return 3;
    bool ok=false,done=false;
    capy::run_async(context.get_executor(),[&]() noexcept {done=true;},[&](std::exception_ptr) noexcept {done=true;})(check(owner,*first,*second,ok));
    (void)context.run_for(std::chrono::seconds(5));
    if(!done || !owner.drained()) {owner.stop();context.restart();(void)context.run();return 4;}
    return ok ? 0 : 5;
}
