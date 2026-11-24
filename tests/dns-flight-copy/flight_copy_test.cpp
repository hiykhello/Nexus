// Candidate only. Compile as a dedicated fault-test program: this translation
// unit replaces allocation and must not be linked into ordinary executables.
import std;
import dns.message;
import dns.cache;
import dns.corosio_cached;
import capy;
import corosio;
import dns.group_singleflight;

namespace hp=dns_hp_experiment;
namespace d=dns;
namespace io = ::corosio;
using Error=d::detail::ResolveError;
using Clock=std::chrono::steady_clock;
using namespace std::chrono_literals;
namespace {
struct Gate {
    std::mutex mutex;
    std::condition_variable condition;
    bool entered=false,released=false,timed_out=false,fail=false;
    auto pause() -> void {
        std::unique_lock lock(mutex);entered=true;condition.notify_one();
        timed_out=!condition.wait_for(lock,2s,[&]{return released;});
        if(fail)throw std::bad_alloc();
    }
    auto await_entry() -> bool {
        std::unique_lock lock(mutex);return condition.wait_for(lock,2s,[&]{return entered;});
    }
    auto release() -> void {
        {std::lock_guard lock(mutex);released=true;}condition.notify_one();
    }
};
thread_local Gate* allocation_gate=nullptr;
}
auto operator new(std::size_t size) -> void* {
    if(auto* gate=std::exchange(allocation_gate,nullptr))gate->pause();
    if(auto* value=std::malloc(size ? size : 1))return value;
    throw std::bad_alloc();
}
auto operator delete(void* pointer) noexcept -> void {std::free(pointer);}
auto operator delete(void* pointer,std::size_t) noexcept -> void {std::free(pointer);}
namespace {
auto key(std::string name) -> hp::FlightGroup::Key {
    return {{1,std::move(name),1},{io::ipv4_address::loopback(),53},false,false,true};
}
auto address_answer(std::optional<std::uint32_t> ttl=30) -> d::AddressAnswer {
    std::string name="retained-result-copy.example.test";
    return {name,{name},{d::Address{{127,0,0,17},4}},ttl};
}
#ifdef NEXUS_DNS_RESPONSE
auto raw_answer() -> d::Response {
    d::Response response{};response.wire.resize(600,17);
    response.records.push_back({"retained-result-copy.example.test",1,1,30,d::Section::answer,12,4,{}});
    return response;
}
#endif
// While the result copy is stopped in allocation, the owner's completion and
// another waiter may drain, and an unrelated query must acquire the mutex.
// This fails by the gate's bounded timeout with the original locked copy.
template<bool Raw> auto copy_does_not_lock(bool fail,bool expire_during_copy) -> bool {
    hp::FlightGroup group(2,3);hp::FlightGroup::Waiter copying,peer,unrelated;
    auto request=key("retained-result-copy.example.test");
#ifdef NEXUS_DNS_RESPONSE
    request.raw_response=Raw;
#endif
    auto first=group.join(request,copying);
    auto follower=group.join(std::move(request),peer);
    if(!first || !follower)std::terminate();
    auto completed=Clock::now();
    auto expiry=completed+(expire_during_copy ? 500ms : 10s);
#ifdef NEXUS_DNS_RESPONSE
    if constexpr(Raw)group.complete_raw(first->flight,raw_answer(),completed,expiry);
    else
#endif
        group.complete(first->flight,address_answer(),completed,{},expiry);
    Gate gate;gate.fail=fail;bool copied=false,caught=false,expired=false,unexpected=false;
    std::jthread worker([&] {
        allocation_gate=&gate;
        try {
#ifdef NEXUS_DNS_RESPONSE
            if constexpr(Raw) {
                auto result=group.result_raw(copying);
                copied=result && result->answer && result->answer->wire.size()==600 && result->answer->wire[0]==17;
                // Raw aging/expiry stays in ResponseOperationTraits after copy.
                expired=result && result->expires && Clock::now()>=*result->expires;
            } else
#endif
            {
                auto result=group.result(copying,completed);
                copied=result && !result->expired && result->answer && result->answer->canonical_name=="retained-result-copy.example.test";
                expired=result && result->expired;
            }
        } catch(std::bad_alloc const&) {caught=true;}
        catch(...) {unexpected=true;}
        allocation_gate=nullptr;
    });
    bool ok=gate.await_entry();
    group.finish(first->flight);group.leave(peer);
    ok&=group.counts()==std::pair<std::size_t,std::size_t>{1,1};
    auto joined=group.join(key("unrelated-while-copying.example.test"),unrelated);
    ok&=bool(joined);
    if(joined) {
        group.complete(joined->flight,std::unexpected(Error::canceled));
        group.finish(joined->flight);group.leave(unrelated);
    }
    if(expire_during_copy)std::this_thread::sleep_until(expiry+5ms);
    gate.release();worker.join();
    ok&=!gate.timed_out && !unexpected && caught==fail;
    if(!fail)ok&=expire_during_copy ? expired : copied;
    // A failed or delayed copy never mutates the immutable stored result.
#ifdef NEXUS_DNS_RESPONSE
    if constexpr(Raw) {
        auto retry=group.result_raw(copying);
        ok&=retry && retry->answer && retry->answer->wire.size()==600 && retry->answer->wire[0]==17;
    } else
#endif
    if(!expire_during_copy) {
        auto retry=group.result(copying,completed);
        ok&=retry && !retry->expired && retry->answer && retry->answer->addresses[0].bytes[3]==17;
    }
    group.leave(copying);
    ok&=group.counts()==std::pair<std::size_t,std::size_t>{0,0};
    return ok;
}
auto ttl_and_retirement() -> bool {
    bool ok=true;
    for(auto ttl:{std::optional<std::uint32_t>{},std::optional<std::uint32_t>{0}}) {
        hp::FlightGroup group(2,2);hp::FlightGroup::Waiter initial,later;
        auto first=group.join(key("zero-ttl.example.test"),initial);if(!first)std::terminate();
        auto time=Clock::now();group.complete(first->flight,address_answer(ttl),time);
        auto result=group.result(initial,time+1h);
        ok&=result && !result->expired && result->answer && result->answer->ttl==ttl;
        auto next=group.join(key("zero-ttl.example.test"),later);
        ok&=next && next->leader && next->flight!=first->flight;
        group.finish(first->flight);group.leave(initial);
        if(next){group.complete(next->flight,std::unexpected(Error::canceled));group.leave(later);group.finish(next->flight);}
        ok&=group.counts()==std::pair<std::size_t,std::size_t>{0,0};
    }
    {
        hp::FlightGroup group(1,1);hp::FlightGroup::Waiter waiter;
        auto first=group.join(key("negative-ttl.example.test"),waiter);if(!first)std::terminate();
        auto time=Clock::now()+1s;group.complete(first->flight,std::unexpected(Error::name_not_found),time,2);
        auto before=group.result(waiter,time+1999ms),after=group.result(waiter,time+2s);
        ok&=before && !before->expired && !before->answer && before->answer.error()==Error::name_not_found && after && after->expired;
        group.finish(first->flight);group.leave(waiter);
    }
    {
        hp::FlightGroup group(1,1);hp::FlightGroup::Waiter waiter,late;
        auto first=group.join(key("retiring.example.test"),waiter);if(!first)std::terminate();
        group.leave(waiter);auto rejected=group.join(key("retiring.example.test"),late);
        ok&=!rejected && rejected.error()==Error::limit && group.counts()==std::pair<std::size_t,std::size_t>{1,0};
        group.complete(first->flight,std::unexpected(Error::canceled));group.finish(first->flight);
        ok&=group.counts()==std::pair<std::size_t,std::size_t>{0,0};
    }
    return ok;
}
}
auto main() -> int {
    for(bool fail:{false,true})if(!copy_does_not_lock<false>(fail,false))return 1;
    if(!copy_does_not_lock<false>(false,true) || !ttl_and_retirement())return 2;
#ifdef NEXUS_DNS_RESPONSE
    for(bool fail:{false,true})if(!copy_does_not_lock<true>(fail,false))return 3;
    if(!copy_does_not_lock<true>(false,true))return 4;
#endif
    std::println("DNS immutable flight copy leaves the mutex available and retains waiter ownership, TTL and capacity");
}
