import std;
import net.operation_token;
import capy;
import corosio;
namespace io = ::corosio;
using namespace std::chrono_literals;
struct State {
    capy::async_mutex mutex;
    capy::async_event release;
    std::stop_source local,root;
    bool held=false,waiting=false,canceled=false,returned=false;
    unsigned holder_live=0,waiter_live=0;
};
auto holder(State& state)->capy::task<capy::results<>>{
    auto [error,lock]=co_await state.mutex.scoped_lock();if(error)co_return capy::results<>{error};
    struct Guard{State& state;explicit Guard(State& value):state(value){++state.holder_live;}~Guard(){--state.holder_live;}} guard(state);
    state.held=true;auto [stopped]=co_await state.release.wait();co_return capy::results<>{stopped};
}
auto waiter(State& state)->capy::task<capy::results<>>{
    struct Guard{State& state;explicit Guard(State& value):state(value){++state.waiter_live;}~Guard(){--state.waiter_live;}} guard(state);
    auto deadline=std::chrono::steady_clock::now()+5s;state.waiting=true;
    auto operation=io::timeout(state.mutex.scoped_lock(),deadline);
    auto [error,lock]=co_await net::OperationToken(std::move(operation),state.local);
    state.canceled=bool(error)&&state.local.stop_requested();state.release.set();state.returned=true;
    co_return capy::results<>{error};
}
auto anchor(State& state)->capy::task<capy::results<>>{
    auto [error]=co_await io::delay(5s);(void)state;co_return capy::results<>{error};
}
auto run(State& state)->capy::task<>{auto [error,a,b,c]=co_await capy::when_all(holder(state),waiter(state),anchor(state));(void)error;(void)a;(void)b;(void)c;}
auto test(bool uring,unsigned mode)->bool{
    State state;
    {
        auto context=io::make_io_context(uring);
        capy::run_async(context.get_executor(),state.root.get_token(),[]{},[](std::exception_ptr){std::abort();})(run(state));context.run_for(10ms);
        if(!state.held||!state.waiting||state.returned||state.holder_live!=1||state.waiter_live!=1)return false;
        auto begin=std::chrono::steady_clock::now();
        if(mode!=2){if(mode)state.root.request_stop();else state.local.request_stop();context.restart();context.run_for(200ms);if(!state.returned||!state.canceled||std::chrono::steady_clock::now()-begin>100ms)return false;}
    }
    bool passed=!state.holder_live&&!state.waiter_live&&(mode==2?!state.returned:state.returned&&state.canceled);
    std::println("operation-token backend={} mode={} passed={} holder-live={} waiter-live={} returned={} canceled={}",uring,mode,passed,state.holder_live,state.waiter_live,state.returned,state.canceled);return passed;
}
int main(){for(bool uring:{false,true})for(unsigned mode:{0u,1u,2u})if(!test(uring,mode))return 1;return 0;}
