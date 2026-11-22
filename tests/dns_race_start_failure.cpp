import std;
import dns.input_budget;
import dns.local_response;
import dns.evaluate_owner;
import dns.address_race_program;
import dns.response_program;
import dns.response_race_walk;
import dns.policy;
import dns.corosio_resolver;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace dns=dns;
namespace io=nex::corosio;
namespace capy=nex::capy;
using namespace std::chrono_literals;

class FailingFrames final : public std::pmr::memory_resource {
    std::pmr::memory_resource* upstream_=std::pmr::new_delete_resource();
    auto do_allocate(std::size_t size,std::size_t align) -> void* override {
        if(remaining==0){remaining=-1;throw std::bad_alloc();}
        if(remaining>0)--remaining;
        auto* result=upstream_->allocate(size,align);++live;return result;
    }
    auto do_deallocate(void* ptr,std::size_t size,std::size_t align) -> void override {--live;upstream_->deallocate(ptr,size,align);}
    auto do_is_equal(std::pmr::memory_resource const& other) const noexcept -> bool override {return this==&other;}
public:
    int remaining=-1;int live=0;
};
struct State {capy::async_event event;bool canceled=false,fail=false,allocation=false;unsigned destroyed=0,calls=0;};
struct Operation {
    State& state;
    ~Operation(){++state.destroyed;}
    auto cancel() noexcept -> void {++state.calls;state.canceled=true;state.event.set();}
    auto run() -> capy::task<dns::AddressRaceResult> {
        if(!state.canceled){auto [error]=co_await state.event.wait();(void)error;}
        if(!state.canceled && state.fail) {
            if(state.allocation)throw std::bad_alloc();
            throw std::runtime_error("injected task failure");
        }
        co_return std::unexpected(dns::detail::ResolveError::canceled);
    }
};
using Owner=dns::EvaluateOwner<Operation,dns::AddressRaceResult,2>;
static auto pump(io::io_context& context) -> void {context.restart();(void)context.run_for(20ms);}
static auto owner_failure(io::io_context& context,FailingFrames& frames,int fail_at) -> bool {
    State pending,failed;Owner owner(context);
    auto first=owner.start(std::make_unique<Operation>(pending));if(!first)return false;
    pump(context);auto baseline=frames.live;
    auto candidate=std::make_unique<Operation>(failed);
    auto* saved=capy::get_current_frame_allocator();frames.remaining=fail_at;
    auto rejected=owner.start(std::move(candidate));frames.remaining=-1;
    if(rejected || rejected.error()!=Owner::StartError::allocation || owner.active()!=1 || failed.destroyed!=1 ||
       frames.live!=baseline || capy::get_current_frame_allocator()!=saved || !owner.inspect(*first))std::terminate();
    owner.stop();pump(context);
    auto view=owner.inspect(*first);
    if(!owner.drained() || !view || !view->ready || !view->result || !owner.release(*first) ||
       pending.destroyed!=1 || pending.calls!=1 || frames.live!=0)return false;
    return true;
}
static auto partial_failure(io::io_context& context,int mode,bool& ok) -> capy::task<> {
    State state;int starts=0;
    ::policy::DnsRule evaluate;evaluate.match_all=true;evaluate.action=::policy::DnsAction::evaluate;evaluate.evaluate_tag="slow";
    ::policy::DnsRule match;match.match_all=true;match.match_response=true;match.match_response_tag="slow";match.action=::policy::DnsAction::respond;
    auto second=evaluate;second.evaluate_tag="second";
    std::array rules{evaluate,match,second};
    std::array modes{dns::ResponseRaceMode{},dns::ResponseRaceMode{true,false},dns::ResponseRaceMode{false,true}};
    dns::AddressRaceProgram<Operation> program(context,rules,modes,0);
    auto factory=[&](dns::ResponseStep,std::chrono::steady_clock::time_point) -> std::unique_ptr<Operation> {
        if(++starts==2) {
            if(mode==0)throw std::bad_alloc();
            if(mode==1)throw std::runtime_error("injected");
            return {};
        }
        return std::make_unique<Operation>(state);
    };
    auto result=co_await program.run(factory,"start.test",1,{},std::chrono::steady_clock::now()+2s);
    auto expected=mode==0 ? dns::detail::ResolveError::limit : dns::detail::ResolveError::state;
    ok=!result && result.error()==expected && starts==2 && state.canceled && state.calls==1 && state.destroyed==1;
}
static auto result_budget(io::io_context& context,bool route,bool& ok) -> capy::task<> {
    struct Immediate {
        bool route;
        auto cancel() noexcept -> void {}
        auto run() -> capy::task<dns::AddressRaceResult> {
            if(route) {
                dns::AddressAnswer answer;answer.canonical_name="answer.test";
                answer.chain.push_back("answer.test");answer.addresses.push_back({});
                co_return dns::AddressRaceValue{std::move(answer)};
            }
            dns::Response response{};response.wire.resize(1024);
            co_return dns::AddressRaceValue{dns::detail::LocalResponseSelection{std::move(response),{},false,"answer.test",false}};
        }
    };
    auto& budget=dns::default_address_race_result_budget();
    auto all=budget.acquire(budget.limit());if(!all)co_return;
    ::policy::DnsRule evaluate;evaluate.match_all=true;evaluate.action=::policy::DnsAction::evaluate;evaluate.evaluate_tag="a";
    ::policy::DnsRule judge;judge.match_all=true;judge.match_response=true;judge.match_response_tag="a";judge.action=::policy::DnsAction::respond;
    ::policy::DnsRule speculative;speculative.match_all=true;speculative.action=::policy::DnsAction::route;
    std::array rules{evaluate,judge,speculative};
    std::array modes{dns::ResponseRaceMode{},dns::ResponseRaceMode{true,false},dns::ResponseRaceMode{false,true}};
    auto factory=[&](dns::ResponseStep step,auto) {return std::make_unique<Immediate>(step.action==::policy::DnsAction::route);};
    dns::AddressRaceProgram<Immediate> program(context,rules,modes,0);
    if(route) {
        // Let the evaluation fail normally so the speculative route is selected.
        struct RouteOnly {
            dns::ResponseStep step;
            auto cancel() noexcept -> void {}
            auto run() -> capy::task<dns::AddressRaceResult> {
                if(step.action==::policy::DnsAction::evaluate)co_return std::unexpected(dns::detail::ResolveError::transport);
                dns::AddressAnswer answer;answer.canonical_name="answer.test";
                co_return dns::AddressRaceValue{std::move(answer)};
            }
        };
        dns::AddressRaceProgram<RouteOnly> route_program(context,rules,modes,0);
        auto make=[](dns::ResponseStep step,auto){return std::make_unique<RouteOnly>(step);};
        auto result=co_await route_program.run(make,"answer.test",1,{},std::chrono::steady_clock::now()+2s);
        ok=!result && result.error()==dns::detail::ResolveError::limit;
    } else {
        auto result=co_await program.run(factory,"answer.test",1,{},std::chrono::steady_clock::now()+2s);
        ok=!result && result.error()==dns::detail::ResolveError::limit;
    }
    all.reset();ok=ok && budget.used()==0;
}
static auto execution_failure(io::io_context& context,bool allocation,bool retained,bool& ok) -> capy::task<> {
    State first,second;second.fail=true;second.allocation=allocation;
    ::policy::DnsRule evaluate;evaluate.match_all=true;evaluate.action=::policy::DnsAction::evaluate;evaluate.evaluate_tag="slow";
    ::policy::DnsRule match;match.match_all=true;match.match_response=true;match.match_response_tag="slow";match.action=::policy::DnsAction::respond;
    auto next=evaluate;next.evaluate_tag="second";
    if(retained){next.action=::policy::DnsAction::route;next.evaluate_tag.reset();}
    std::array rules{evaluate,match,next};
    std::array modes{dns::ResponseRaceMode{},dns::ResponseRaceMode{true,false},dns::ResponseRaceMode{false,true}};
    dns::AddressRaceProgram<Operation> program(context,rules,modes,0);
    unsigned starts=0;bool driver_done=!retained;capy::async_event driver_finished;
    auto factory=[&](dns::ResponseStep,std::chrono::steady_clock::time_point) -> std::unique_ptr<Operation> {
        auto& state=++starts==1 ? first : second;
        if(starts==2 && !retained)state.event.set();
        return std::make_unique<Operation>(state);
    };
    auto driver=[&]() -> capy::task<> {
        struct Signal {capy::async_event& event;~Signal(){event.set();}} signal{driver_finished};
        io::steady_timer timer(context);timer.expires_at(std::chrono::steady_clock::now()+10ms);
        auto [first_error]=co_await timer.wait();if(first_error)co_return;
        first.event.set();timer.expires_at(std::chrono::steady_clock::now()+50ms);
        auto [second_error]=co_await timer.wait();if(second_error)co_return;
        driver_done=true;second.event.set();
    };
    if(retained)capy::run_async(context.get_executor())(driver());
    auto result=co_await program.run(factory,"failure.test",1,{},std::chrono::steady_clock::now()+2s);
    if(retained){auto [error]=co_await driver_finished.wait();if(error)co_return;}
    auto expected=allocation ? dns::detail::ResolveError::limit : dns::detail::ResolveError::state;
    ok=!result && result.error()==expected && starts==2 && driver_done && first.destroyed==1 && second.destroyed==1 &&
        (retained || (first.canceled && first.calls==1));
}
auto main(int argc,char** argv) -> int {
    bool uring=argc>1 && std::string_view(argv[1])=="uring";
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    if(uring)return 77;io::io_context context(io::epoll);
#endif
    FailingFrames frames;context.set_frame_allocator(&frames);
    if(!owner_failure(context,frames,0) || !owner_failure(context,frames,1))return 3;
    for(int mode=0;mode<3;++mode) {
        bool done=false,ok=false;
        capy::run_async(context.get_executor(),[&]() noexcept {done=true;},[&](std::exception_ptr) noexcept {done=true;})(partial_failure(context,mode,ok));
        pump(context);if(!done || !ok || frames.live)return 4;
    }
    for(bool retained:{false,true})for(bool allocation:{false,true}) {
        bool done=false,ok=false;
        capy::run_async(context.get_executor(),[&]() noexcept {done=true;},[&](std::exception_ptr) noexcept {done=true;})(execution_failure(context,allocation,retained,ok));
        context.restart();(void)context.run_for(1s);if(!done || !ok || frames.live)return 5;
    }
    for(bool route:{false,true}) {
        bool done=false,ok=false;
        capy::run_async(context.get_executor(),[&]() noexcept {done=true;},[&](std::exception_ptr) noexcept {done=true;})(result_budget(context,route,ok));
        context.restart();(void)context.run_for(1s);if(!done || !ok || frames.live)return 6;
    }
    context.set_frame_allocator(std::pmr::new_delete_resource());
    std::cout<<"startup allocation failure, partial cancellation and drain passed\n";
}
