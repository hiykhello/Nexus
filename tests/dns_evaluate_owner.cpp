import std;
import dns.evaluate_owner;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace capy=nex::capy;
namespace io=nex::corosio;
struct State {capy::async_event event;bool canceled=false;unsigned destroyed=0;};
struct Operation {
    State& state;int value;bool fail=false;
    ~Operation(){++state.destroyed;}
    auto cancel() noexcept -> void {state.canceled=true;state.event.set();}
    auto run() -> capy::task<std::expected<int,std::errc>> {
        if(fail)throw std::runtime_error("injected");
        auto [error]=co_await state.event.wait();
        if(error || state.canceled)co_return std::unexpected(std::errc::operation_canceled);
        co_return value;
    }
};
using Owner=dns::EvaluateOwner<Operation,std::expected<int,std::errc>,2>;
static auto pump(io::io_context& context) -> void {context.restart();(void)context.run_for(std::chrono::milliseconds(20));}
auto main(int argc,char** argv) -> int {
    bool uring=argc>1 && std::string_view(argv[1])=="uring";
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    if(uring)return 77;io::io_context context(io::epoll);
#endif
    State a,b,c;
    Owner owner(context);
    auto first=owner.start(std::make_unique<Operation>(a,1));
    auto second=owner.start(std::make_unique<Operation>(b,2));
    if(!first || !second || owner.active()!=2 || owner.drained() || owner.release(*first))return 1;
    auto overflow=owner.start(std::make_unique<Operation>(c,3));
    if(overflow || overflow.error()!=Owner::StartError::full || c.destroyed!=1)return 2;
    bool notified=false,wait_failed=false;
    capy::run_async(context.get_executor(),[&](capy::results<> result) noexcept {notified=true;wait_failed=bool(std::get<0>(result));},
        [&](std::exception_ptr) noexcept {notified=true;wait_failed=true;})(owner.wait(owner.epoch()));
    pump(context);if(notified)return 13;
    b.event.set();pump(context);if(!notified || wait_failed)return 14;
    auto bview=owner.inspect(*second),aview=owner.inspect(*first);
    if(!bview || !bview->ready || !bview->result || **bview->result!=2 || !aview || aview->ready || owner.active()!=1 || owner.take_result(*first))return 3;
    auto completion=bview->completion;auto taken=owner.take_result(*second);
    if(!taken || !*taken || **taken!=2 || owner.take_result(*second) || owner.inspect(*second)->result)return 18;
    a.event.set();pump(context);aview=owner.inspect(*first);
    if(!aview || !aview->ready || !aview->result || **aview->result!=1 || aview->completion<=completion || !owner.drained())return 4;
    if(!owner.release(*first) || owner.inspect(*first) || a.destroyed!=1)return 5;
    auto throwing=owner.start(std::make_unique<Operation>(a,0,true));
    if(!throwing || *throwing==*first || owner.inspect(*first))return 6;
    pump(context);auto failure=owner.inspect(*throwing);
    if(!failure || !failure->ready || !failure->exception || failure->result || owner.take_result(*throwing) || !owner.release(*throwing))return 7;
    if(!owner.release(*second) || b.destroyed!=1)return 8;
    a.event.clear();a.canceled=false;
    auto pending=owner.start(std::make_unique<Operation>(a,4));if(!pending)return 9;
    pump(context);auto epoch=owner.epoch();owner.stop();
    if(!a.canceled || owner.epoch()==epoch || owner.drained() || owner.start(std::make_unique<Operation>(c,5)))return 10;
    pump(context);auto canceled=owner.inspect(*pending);
    if(!canceled || !canceled->ready || !canceled->result || bool(*canceled->result) || !owner.drained())return 11;
    if(!owner.release(*pending))return 12;
    Owner waiting(context);bool waiter_done=false;
    capy::run_async(context.get_executor(),[&](capy::results<>) noexcept {waiter_done=true;},
        [&](std::exception_ptr) noexcept {waiter_done=true;})(waiting.wait(waiting.epoch()));
    pump(context);if(waiter_done || waiting.drained())return 15;
    waiting.stop();if(waiting.drained())return 16;
    pump(context);if(!waiter_done || !waiting.drained())return 17;
    {
        State lost,kept;Owner selection(context);
        auto loser=selection.start(std::make_unique<Operation>(lost,6));
        auto winner=selection.start(std::make_unique<Operation>(kept,7));
        if(!loser || !winner)return 19;
        pump(context);auto stale=*winner;++stale.generation;
        if(selection.stop_except(stale) || !selection.stop_except(*winner) || selection.stop_except(*winner) ||
           !lost.canceled || kept.canceled || selection.start(std::make_unique<Operation>(c,9)))return 20;
        pump(context);auto lost_result=selection.take_result(*loser);
        if(!lost_result || *lost_result || !selection.release(*loser) || selection.drained())return 21;
        kept.event.set();pump(context);auto kept_result=selection.take_result(*winner);
        if(!kept_result || !*kept_result || **kept_result!=7 || !selection.release(*winner) || !selection.drained())return 22;
    }
    {
        State kept;Owner selection(context);auto winner=selection.start(std::make_unique<Operation>(kept,8));
        if(!winner)return 23;pump(context);
        if(!selection.stop_except(*winner) || kept.canceled)return 24;
        selection.stop();if(!kept.canceled)return 25;
        pump(context);auto result=selection.take_result(*winner);
        if(!result || *result || !selection.release(*winner) || !selection.drained())return 26;
    }
    for(bool pre_stopped:{false,true}) {
        Owner drain(context);std::stop_source parent;
        if(pre_stopped)parent.request_stop();
        bool done=false,failed=false;
        capy::run_async(context.get_executor(),parent.get_token(),
            [&](capy::results<> result) noexcept {done=true;failed=bool(std::get<0>(result));},
            [&](std::exception_ptr) noexcept {done=true;failed=true;})(drain.wait_drain(drain.epoch()));
        pump(context);if(done || drain.drained())return 27;
        parent.request_stop();pump(context);if(done || drain.drained())return 28;
        drain.stop();pump(context);if(!done || failed || !drain.drained())return 29;
        // A stale epoch completes immediately, including under a stopped parent.
        done=false;failed=false;
        capy::run_async(context.get_executor(),parent.get_token(),
            [&](capy::results<> result) noexcept {done=true;failed=bool(std::get<0>(result));},
            [&](std::exception_ptr) noexcept {done=true;failed=true;})(drain.wait_drain(drain.epoch()-1));
        pump(context);if(!done || failed || !drain.drained())return 30;
    }
    std::cout<<"bounded evaluate owner: ordering, generations, exceptions, cancellation and drain passed\n";
}
