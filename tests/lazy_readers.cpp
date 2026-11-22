#include <boost/capy/ex/abandon.hpp>
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/ex/execution_context.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/ex/frame_allocator.hpp>
#include <algorithm>
#include <cstdio>
#include <deque>
#include <stdexcept>
#include <vector>

#ifdef NEXUS_LAZY_READERS_STANDALONE
#include "lazy_readers_bridge.hpp"
#else
import std;
import net.lazy_readers;
#endif

namespace capy=boost::capy;
struct Context;
struct Executor {
    Context* owner;
    auto context() const noexcept -> Context&;
    auto on_work_started() const noexcept -> void {}
    auto on_work_finished() const noexcept -> void {}
    auto post(capy::continuation& c) const -> void;
    auto dispatch(capy::continuation& c) const -> std::coroutine_handle<> {post(c);return std::noop_coroutine();}
    auto operator==(Executor const&) const -> bool = default;
};
struct Park;
struct Context : capy::execution_context {
    std::deque<capy::continuation> queued;
    std::vector<Park*> parked;
    Context():execution_context(this){}
    auto executor() -> Executor {return {this};}
    auto pump() -> void {
        unsigned budget=10000;
        while(!queued.empty()) {
            if(!budget--)throw std::runtime_error("runaway queue");
            auto c=queued.front();queued.pop_front();capy::safe_resume(c.h);
        }
    }
    ~Context();
};
auto Executor::context() const noexcept -> Context& {return *owner;}
auto Executor::post(capy::continuation& c) const -> void {owner->queued.push_back(c);}
static_assert(capy::Executor<Executor>);
struct Park {
    Context& context;
    capy::continuation continuation;
    bool active=false;
    explicit Park(Context& ctx):context(ctx){}
    Park(Park&& other):context(other.context){}
    ~Park(){if(active)std::erase(context.parked,this);}
    auto await_ready() const noexcept -> bool{return false;}
    auto await_suspend(std::coroutine_handle<> h,capy::await_context const* env) -> void {
        continuation={h,nullptr,env->owner};active=true;context.parked.push_back(this);
    }
    auto await_resume() const noexcept -> void{}
};
Context::~Context() {
    while(!parked.empty()) {
        auto* p=parked.back();parked.pop_back();p->active=false;
        auto c=p->continuation;capy::abandon(c);
    }
    while(!queued.empty()) {auto c=queued.front();queued.pop_front();capy::abandon(c);}
}
struct State {
    net::LazyReaders<32> owner;
    capy::async_event release,readiness,reading;
    std::array<unsigned,32> made{},entered{},destroyed{};
    unsigned live=0,rounds=0;
    bool ready=false,closed=false;
};
struct Live {
    State& state;std::size_t index;
    Live(State& s,std::size_t i):state(s),index(i){++s.live;++s.entered[i];}
    ~Live(){--state.live;++state.destroyed[index];}
};
auto wait_reader(State& s,std::size_t i) -> capy::task<capy::results<>> {
    Live live{s,i};co_return co_await s.release.wait();
}
auto failed_reader(State& s,std::size_t i,bool throwing) -> capy::task<capy::results<>> {
    Live live{s,i};
    if(throwing)throw std::runtime_error("reader error");
    co_return capy::results<>{std::make_error_code(std::errc::io_error)};
}
auto parked_reader(State& s,std::size_t i,Context& ctx) -> capy::task<capy::results<>> {
    Live live{s,i};co_await Park{ctx};co_return capy::results<>{};
}
auto rotated_reader(State& s,std::size_t i) -> capy::task<capy::results<>> {
    Live live{s,i};
    while(!s.closed && !s.owner.stopped()) {
        while(!s.closed && !s.owner.stopped() && !s.ready) {
            auto [error]=co_await s.readiness.wait();if(error)co_return capy::results<>{error};
        }
        if(s.closed || s.owner.stopped())break;
        ++s.rounds;auto [error]=co_await s.reading.wait();
        if(error)co_return capy::results<>{error};
    }
    co_return capy::results<>{};
}
struct Result {bool done=false,error=false;};
template<class Task>
auto launch(Context& ctx,Result& result,Task task,std::stop_token stop={}) -> void {
    capy::run_async(ctx.executor(),stop,[&](capy::results<> value){result.done=true;result.error=bool(std::get<0>(value));},
        [&](std::exception_ptr){result.done=true;result.error=true;})(std::move(task));
}
auto zero_and_precanceled() -> bool {
    for(unsigned mode=0;mode<3;++mode) {
        State s;Context ctx;Result r;std::stop_source stop;
        if(mode==1)s.owner.stop();
        if(mode==2){(void)s.owner.request(2);stop.request_stop();}
        launch(ctx,r,s.owner.run([&](std::size_t i){++s.made[i];return wait_reader(s,i);}),stop.get_token());
        ctx.pump();
        if(mode==0){if(r.done)return false;s.owner.stop();ctx.pump();}
        if(!r.done || s.live || std::ranges::any_of(s.made,[](auto n){return n!=0;}))return false;
    }
    return true;
}
auto requested_and_stable_factory() -> bool {
    State s;Context ctx;Result r;
    if(!s.owner.request(7) || !s.owner.request(7) || s.owner.request(32))return false;
    // Temporary closure is destroyed after run() has copied it into its frame.
    launch(ctx,r,s.owner.run([ptr=&s](std::size_t i){++ptr->made[i];return wait_reader(*ptr,i);}));
    ctx.pump();
    if(s.live!=1 || s.made[7]!=1 || r.done)return false;
    for(std::size_t i=0;i<32;++i)if(!s.owner.request(i))return false;
    ctx.pump();
    if(s.live!=32 || std::ranges::any_of(s.made,[](auto n){return n!=1;}))return false;
    s.owner.stop();ctx.pump();
    if(r.done || s.live!=32)return false; // stop() does not cancel business I/O.
    s.release.set();ctx.pump();
    return r.done && !r.error && !s.live && std::ranges::all_of(s.destroyed,[](auto n){return n==1;});
}
auto failure(unsigned mode) -> bool {
    State s;Context ctx;Result r;
    (void)s.owner.request(0);
    launch(ctx,r,s.owner.run([&](std::size_t i)->capy::task<capy::results<>> {
        ++s.made[i];
        if(i==1 && mode==2)throw std::bad_alloc();
        if(i==1)return failed_reader(s,i,mode==1);
        return wait_reader(s,i);
    }));
    ctx.pump();if(s.live!=1)return false;
    (void)s.owner.request(1);ctx.pump();
    return r.done && r.error && !s.live && s.destroyed[0]==1 && s.made[1]==1;
}
auto external_cancel() -> bool {
    State s;Context ctx;Result r;std::stop_source stop;
    (void)s.owner.request(0);
    launch(ctx,r,s.owner.run([&](std::size_t i){++s.made[i];return wait_reader(s,i);}),stop.get_token());
    ctx.pump();if(s.live!=1)return false;
    stop.request_stop();(void)s.owner.request(1);ctx.pump();
    return r.done && r.error && !s.live && !s.made[1];
}
auto rotation() -> bool {
    State s;Context ctx;Result r;s.ready=true;
    (void)s.owner.request(3);
    launch(ctx,r,s.owner.run([&](std::size_t i){++s.made[i];return rotated_reader(s,i);}));
    ctx.pump();if(s.rounds!=1)return false;
    s.ready=false;s.readiness.clear();s.reading.set();ctx.pump();
    s.reading.clear();s.ready=true;(void)s.owner.request(3);s.readiness.set();ctx.pump();
    if(s.rounds!=2 || s.made[3]!=1)return false;
    s.ready=false;s.readiness.clear();s.reading.set();ctx.pump();
    s.owner.stop();s.readiness.set();ctx.pump(); // owner stop precedes session close.
    s.closed=true;
    return r.done && !r.error && s.destroyed[3]==1 && !s.live;
}
auto abandonment() -> bool {
    State s;Result r;
    {
        Context ctx;(void)s.owner.request(0);(void)s.owner.request(1);
        launch(ctx,r,s.owner.run([&](std::size_t i){++s.made[i];return parked_reader(s,i,ctx);}));
        ctx.pump();if(s.live!=2 || r.done)return false;
    }
    return !r.done && !s.live && s.destroyed[0]==1 && s.destroyed[1]==1;
}
auto main() -> int {
    if(!zero_and_precanceled())return 1;
    if(!requested_and_stable_factory())return 2;
    for(unsigned i=0;i<3;++i)if(!failure(i))return 3+i;
    if(!external_cancel())return 6;
    if(!rotation())return 7;
    if(!abandonment())return 8;
    std::puts("lazy readers: zero/one/32 demand, early/repeated requests, temporary factory, reader errors/factory failure, external stop, same-slot rotation and context abandonment passed");
}
