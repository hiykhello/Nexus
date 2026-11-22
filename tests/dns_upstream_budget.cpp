import std;
import dns.input_budget;
import dns.corosio_query;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace dns=dns;namespace io=nex::corosio;namespace capy=nex::capy;
using namespace std::chrono_literals;
auto work(io::io_context& context,std::uint16_t port,bool tcp,bool& ok) -> capy::task<> {
    auto capacity=tcp ? std::size_t{60000} : std::size_t{1233};
    dns::InputBudget budget(capacity);
    dns::detail::FallbackQuery first(context,tcp,&budget),second(context,tcp,&budget),third(context,tcp,&budget);
    dns::QueryMessage query{42,0x0100,{"budget.test",1},dns::QueryEdns{1232,0,false,{}}};
    auto endpoint=io::endpoint(io::ipv4_address::loopback(),port);
    auto deadline=std::chrono::steady_clock::now()+3s;
    using Result=std::expected<dns::Response,dns::detail::UdpError>;
    std::optional<Result> a,c;capy::async_event first_done,third_done;
    auto launch=[&](dns::detail::FallbackQuery& operation,std::optional<Result>& result,capy::async_event& finished) -> capy::task<> {
        result=co_await operation.query_borrowed(endpoint,query,deadline);finished.set();
    };
    auto pause=[&]() -> capy::task<bool> {
        io::steady_timer timer(context);timer.expires_at(std::chrono::steady_clock::now()+100ms);
        auto [error]=co_await timer.wait();co_return !error;
    };
    capy::run_async(context.get_executor())(launch(first,a,first_done));
    if(!co_await pause() || budget.used()!=capacity){first.cancel();auto [error]=co_await first_done.wait();(void)error;co_return;}
    auto denied=co_await second.query_borrowed(endpoint,query,deadline);
    first.cancel();auto [error]=co_await first_done.wait();
    if(error || denied || denied.error()!=dns::detail::UdpError::budget_exhausted || !a || *a || a->error()!=dns::detail::UdpError::canceled || budget.used())co_return;
    capy::run_async(context.get_executor())(launch(third,c,third_done));
    auto ready=co_await pause();auto held=budget.used()==capacity;
    third.cancel();auto [last_error]=co_await third_done.wait();
    ok=ready && held && !last_error && c && !*c && c->error()==dns::detail::UdpError::canceled && budget.used()==0;
}
auto main(int argc,char** argv) -> int {
    if(argc!=4)return 2;bool uring=std::string_view(argv[1])=="uring";
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    if(uring)return 77;io::io_context context(io::epoll);
#endif
    auto port=static_cast<std::uint16_t>(std::strtoul(argv[2],nullptr,10));bool done=false,ok=false;
    capy::run_async(context.get_executor(),[&]() noexcept {done=true;},[&](std::exception_ptr) noexcept {done=true;})(work(context,port,std::string_view(argv[3])=="tcp",ok));
    (void)context.run_for(5s);if(!done || !ok)return 3;
    std::cout<<"upstream receive capacity, contention, cancel and reuse passed\n";
}
