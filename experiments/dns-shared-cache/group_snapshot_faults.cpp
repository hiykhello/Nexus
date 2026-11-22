#include <cstdlib>
#include <new>
import std;
import dns.message;
import dns.cache;
#include "../../src/dns-shared/group_snapshot.hpp"
#include "../../src/dns-shared/group_cache_binding.hpp"

namespace {
thread_local int fail_after=-1;
thread_local bool pause_failure=false;
std::atomic<bool> failure_entered=false,failure_release=false;
auto should_fail() -> bool {
    if (fail_after<0 || fail_after--!=0) return false;
    if (pause_failure) { failure_entered=true; failure_entered.notify_one(); failure_release.wait(false); }
    return true;
}
}
auto operator new(std::size_t size) -> void* {
    if (should_fail()) throw std::bad_alloc();
    if (auto* pointer=std::malloc(size ? size : 1)) return pointer;
    throw std::bad_alloc();
}
void operator delete(void* pointer) noexcept { std::free(pointer); }
void operator delete(void* pointer,std::size_t) noexcept { std::free(pointer); }
auto operator new(std::size_t size,std::align_val_t alignment) -> void* {
    if (should_fail()) throw std::bad_alloc();
    void* pointer=nullptr;
    if (posix_memalign(&pointer,static_cast<std::size_t>(alignment),size ? size : 1)==0) return pointer;
    throw std::bad_alloc();
}
void operator delete(void* pointer,std::align_val_t) noexcept { std::free(pointer); }
void operator delete(void* pointer,std::size_t,std::align_val_t) noexcept { std::free(pointer); }

namespace d=dns;
using Cache=dns_hp_experiment::GroupSnapshot;
auto key(std::string_view name) -> d::CacheKey { return {1,std::string(name),1}; }
auto answer(d::CacheKey const& key,unsigned value) -> d::AddressAnswer {
    d::Address address{}; address.size=4; address.bytes[0]=static_cast<std::uint8_t>(value);
    return {key.name,{key.name},{address},60};
}
auto lookup(Cache& cache,std::size_t group,d::CacheKey const& key,Cache::Reader& reader) -> bool {
    auto result=cache.lookup(group,key,1000,reader);
    return result && result->has_value();
}
auto publish_failure_positions() -> int {
    auto old=key("old-group-snapshot.test"),fresh=key("fresh-group-snapshot.test");
    int failures=0;
    for (int position=0;position<256;++position) {
        std::array<std::size_t,2> capacities{2,2}; Cache cache(capacities,2);
        auto first=cache.reader(0),second=cache.reader(1);
        auto initial=cache.begin_query(0,old);
        if (!initial || !cache.publish(0,old,answer(old,1),1000,*initial)) return -1;
        if (!lookup(cache,1,old,second)) return -2;
        auto token=cache.begin_query(0,fresh); if (!token) return -3;
        bool threw=false,success=false; fail_after=position;
        try { success=cache.publish(0,fresh,answer(fresh,2),1000,*token).has_value(); }
        catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (threw) {
            ++failures;
            if (!lookup(cache,0,old,first) || !lookup(cache,1,old,second) || lookup(cache,0,fresh,first) ||
                cache.size(0)!=1 || cache.size(1)!=1 || Cache::live_nodes()!=1) return -4;
            success=cache.publish(0,fresh,answer(fresh,2),1000,*token).has_value();
        }
        if (!success || !lookup(cache,0,fresh,first) || Cache::live_nodes()!=2) return -5;
        if (!threw) break;
    }
    return failures ? 0 : -6;
}
auto shared_update_failure_positions() -> int {
    auto item=key("shared-update-group-snapshot.test"); int failures=0;
    for (int position=0;position<256;++position) {
        std::array<std::size_t,2> capacities{2,2}; Cache cache(capacities,2);
        auto first=cache.reader(0),second=cache.reader(1);
        auto token=cache.begin_query(0,item);
        if (!token || !cache.publish(0,item,answer(item,1),1000,*token) || !lookup(cache,1,item,second)) return -1;
        auto update=cache.begin_query(1,item); if (!update) return -2;
        bool threw=false,success=false; fail_after=position;
        try { success=cache.publish(1,item,answer(item,9),1000,*update).has_value(); }
        catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (threw) {
            ++failures;
            auto old=cache.lookup(0,item,1000,first),other=cache.lookup(1,item,1000,second);
            if (!old || !*old || (**old).addresses[0].bytes[0]!=1 || !other || !*other ||
                (**other).addresses[0].bytes[0]!=1 || Cache::live_nodes()!=1) return -3;
            success=cache.publish(1,item,answer(item,9),1000,*update).has_value();
        }
        if (!success) return -4;
        auto result=cache.lookup(0,item,1000,first);
        if (!result || !*result || (**result).addresses[0].bytes[0]!=9) return -5;
        if (!threw) break;
    }
    return failures ? 0 : -6;
}
auto multi_group_failure_positions() -> int {
    auto item=key("multi-group-snapshot.test"),victim=key("victim-group-snapshot.test"); int failures=0;
    for (int position=0;position<256;++position) {
        std::array<std::size_t,3> capacities{1,1,1}; Cache cache(capacities,3);
        auto first=cache.reader(0),second=cache.reader(1),third=cache.reader(2);
        auto token=cache.begin_query(0,item),other=cache.begin_query(2,victim);
        if (!token || !other || !cache.publish(0,item,answer(item,1),1000,*token) ||
            !cache.publish(2,victim,answer(victim,3),1000,*other) || !lookup(cache,1,item,second)) return -1;
        auto update=cache.begin_query(2,item); if (!update) return -2;
        auto prepared=answer(item,9); bool threw=false,success=false; fail_after=position;
        try { success=cache.publish(2,item,std::move(prepared),1000,*update).has_value(); }
        catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (threw) {
            ++failures;
            auto a=cache.lookup(0,item,1000,first),b=cache.lookup(1,item,1000,second),c=cache.lookup(2,victim,1000,third);
            if (!a || !*a || (**a).addresses[0].bytes[0]!=1 || !b || !*b || (**b).addresses[0].bytes[0]!=1 ||
                !c || !*c || (**c).addresses[0].bytes[0]!=3 || cache.size(2)!=1 || Cache::live_nodes()!=2) return -3;
            success=cache.publish(2,item,answer(item,9),1000,*update).has_value();
        }
        if (!success) return -4;
        for (unsigned group=0;group<3;++group) {
            auto& reader=group==0 ? first : group==1 ? second : third;
            auto result=cache.lookup(group,item,1000,reader);
            if (!result || !*result || (**result).addresses[0].bytes[0]!=9) return -5;
        }
        if (Cache::live_nodes()!=1) return -6;
        if (!threw) break;
    }
    return failures ? 0 : -7;
}
auto negative_and_invalidation_faults() -> int {
    auto item=key("negative-group-snapshot.test");
    for (bool invalidate:{false,true}) {
        int failures=0;
        for (int position=0;position<256;++position) {
            std::array<std::size_t,2> capacities{2,2}; Cache cache(capacities,2,5000);
            auto first=cache.reader(0),second=cache.reader(1);
            auto initial=cache.begin_query(0,item);
            if (!initial || !cache.publish(0,item,answer(item,1),1000,*initial) || !lookup(cache,1,item,second)) return -1;
            auto token=cache.begin_query(1,item); if (!token) return -2;
            auto input=item; bool threw=false,success=false; fail_after=position;
            try {
                success=invalidate ? cache.invalidate(1,std::move(input),1000,*token).has_value()
                                   : cache.publish_negative(1,std::move(input),d::NegativeKind::name_not_found,30,1000,*token).has_value();
            } catch (std::bad_alloc const&) { threw=true; }
            fail_after=-1;
            if (threw) {
                ++failures;
                if (!lookup(cache,0,item,first) || !lookup(cache,1,item,second) || Cache::live_nodes()!=1) return -3;
                success=invalidate ? cache.invalidate(1,item,1000,*token).has_value()
                                   : cache.publish_negative(1,item,d::NegativeKind::name_not_found,30,1000,*token).has_value();
            }
            if (!success || lookup(cache,0,item,first) || lookup(cache,1,item,second)) return -4;
            auto a=cache.lookup_negative(0,item,1000,first),b=cache.lookup_negative(1,item,1000,second);
            if (!a || !b || a->has_value()==invalidate || b->has_value()==invalidate || Cache::live_nodes()!=(invalidate ? 0U : 1U)) return -5;
            if (!threw) break;
        }
        if (!failures) return -6;
    }
    return 0;
}
auto stale_admission_faults() -> int {
    auto item=key("stale-admission-group-snapshot.test"); int failures=0;
    for (int position=0;position<256;++position) {
        std::array<std::size_t,2> capacities{1,1}; Cache cache(capacities,2,5000);
        auto first=cache.reader(0),second=cache.reader(1);
        auto token=cache.begin_query(0,item); auto original=answer(item,1); original.ttl=1;
        if (!token || !cache.publish(0,item,std::move(original),1000,*token)) return -1;
        auto advance=cache.lookup_stale(0,item,2000,first);
        if (!advance || !*advance) return -2;
        auto input=item; bool threw=false,success=false; fail_after=position;
        try { auto result=cache.lookup_stale(1,std::move(input),2000,second); success=result && result->has_value(); }
        catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (threw) {
            ++failures;
            if (cache.size(0)!=1 || cache.size(1)!=0 || Cache::live_nodes()!=1) return -3;
            auto retry=cache.lookup_stale(1,item,2000,second); success=retry && retry->has_value();
        }
        if (!success || cache.size(1)!=1 || Cache::live_nodes()!=1) return -4;
        if (!threw) break;
    }
    return failures ? 0 : -5;
}
auto admission_failure_positions() -> int {
    auto item=key("admission-group-snapshot.test"); int failures=0;
    for (int position=0;position<256;++position) {
        std::array<std::size_t,2> capacities{1,1}; Cache cache(capacities,2);
        auto first=cache.reader(0),second=cache.reader(1);
        auto token=cache.begin_query(0,item);
        if (!token || !cache.publish(0,item,answer(item,1),1000,*token)) return -1;
        fail_after=position; bool threw=false,success=false;
        try { success=lookup(cache,1,item,second); }
        catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (threw) {
            ++failures;
            if (cache.size(0)!=1 || cache.size(1)!=0 || !lookup(cache,0,item,first) || Cache::live_nodes()!=1) return -2;
            success=lookup(cache,1,item,second);
        }
        if (!success || cache.size(1)!=1 || !lookup(cache,1,item,second)) return -3;
        if (!threw) break;
    }
    return failures ? 0 : -4;
}
auto clear_without_allocation() -> int {
    std::array<std::size_t,2> capacities{2,2}; Cache cache(capacities,1);
    auto item=key("clear-group-snapshot.test"); auto token=cache.begin_query(0,item);
    if (!token || !cache.publish(0,item,answer(item,1),1000,*token)) return 1;
    fail_after=0; auto result=cache.clear(1000); auto remaining=fail_after; fail_after=-1;
    return !result || remaining!=0 || cache.size(0)!=0 || cache.size(1)!=0 ? 2 : 0;
}
auto construction_failure_positions() -> int {
    int failures=0;
    for (int position=0;position<64;++position) {
        bool threw=false; std::array<std::size_t,17> capacities; capacities.fill(256); fail_after=position;
        try { Cache cache(capacities,257); }
        catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (threw) ++failures; else break;
    }
    return failures ? 0 : -1;
}
auto fail_closed_allocation_faults() -> int {
    auto item=key("budget-fault-group-snapshot.test");
    for (bool registration:{false,true}) {
        int failures=0;
        for (int position=0;position<256;++position) {
            std::array<std::size_t,1> capacities{1}; Cache cache(capacities,1,5000,1024*1024);
            auto reader=cache.reader(0);
            auto initial=cache.begin_query(0,item);
            if (!initial || !cache.publish(0,item,answer(item,1),1000,*initial)) return -1;
            auto next=cache.begin_query(0,item); if (!next) return -2;
            auto input=item; auto prepared=answer(item,2);
            bool threw=false,success=false; fail_after=position;
            try {
                if (registration) success=cache.begin_query(0,std::move(input)).has_value();
                else success=cache.publish(0,std::move(input),std::move(prepared),1000,*next).has_value();
            } catch (std::bad_alloc const&) { threw=true; }
            fail_after=-1;
            if (threw) {
                ++failures;
                auto missing=cache.lookup(0,item,1000,reader); auto denied=cache.begin_query(0,item);
                if (!missing || *missing || denied || denied.error()!=d::CacheError::disabled) return -3;
                if (!cache.clear(1000)) return -4;
                auto fresh=cache.begin_query(0,item);
                if (!fresh || !cache.publish(0,item,answer(item,3),1000,*fresh) || !lookup(cache,0,item,reader)) return -5;
            } else if (!success) return -6;
            if (!threw) break;
        }
        if (!failures) return -7;
    }
    return 0;
}
auto caller_key_allocation_faults() -> int {
    auto item=key("long-foreground-registration-and-publication.example.test");
    for (unsigned operation=0;operation<6;++operation) {
        std::array<std::size_t,2> capacities{2,2}; Cache cache(capacities,1,5000,1024*1024);
        auto reader=cache.reader(0);
        auto initial=cache.begin_query(0,item);
        if (!initial || !cache.publish(0,item,answer(item,1),1000,*initial) || !lookup(cache,1,item,reader)) return 1;
        auto token=cache.begin_query(0,item); if (!token) return 2;
        auto prepared=answer(item,2);
        bool threw=false; fail_after=0;
        try {
            if (operation==0) (void)cache.begin_query(0,item);
            if (operation==1) (void)cache.begin_query(0,item.view,std::string_view(item.name),item.type);
            if (operation==2) (void)cache.publish_view(0,item.view,item.name,item.type,std::move(prepared),1000,*token);
            if (operation==3) (void)cache.publish_negative_view(0,item.view,item.name,item.type,d::NegativeKind::no_data,30,1000,*token);
            if (operation==4) (void)cache.invalidate_view(0,item.view,item.name,item.type,1000,*token);
            if (operation==5) (void)cache.publish_copy_view(0,item.view,item.name,item.type,prepared,1000,*token);
        } catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (!threw || lookup(cache,0,item,reader) || lookup(cache,1,item,reader)) return 3;
        auto denied=cache.begin_query(0,item);
        if (denied || denied.error()!=d::CacheError::disabled || !cache.clear(1000)) return 4;
        auto fresh=cache.begin_query(0,item.view,item.name,item.type);
        if (!fresh || !cache.publish_view(0,item.view,item.name,item.type,answer(item,3),1000,*fresh) ||
            !lookup(cache,1,item,reader)) return 5;
        auto invalid=cache.begin_query(0,item.view,std::string(255,'a'),item.type);
        if (invalid || invalid.error()!=d::CacheError::invalid_key || !lookup(cache,0,item,reader)) return 6;
    }
    return 0;
}
auto stale_key_allocation_faults() -> int {
    auto item=key("old-token-must-not-disable-current-generation.test");
    std::array<std::size_t,2> capacities{2,2}; Cache cache(capacities,1,5000,1024*1024);
    auto reader=cache.reader(0);
    auto old=cache.begin_query(0,item);
    if (!old || !cache.clear(1000)) return 1;
    auto initial=cache.begin_query(0,item);
    if (!initial || !cache.publish(0,item,answer(item,1),1000,*initial)) return 2;
    auto superseded=cache.begin_query(0,item),newer=cache.begin_query(0,item);
    if (!superseded || !newer || !cache.publish(0,item,answer(item,2),1000,*newer)) return 3;
    auto wrong_group=cache.begin_query(0,item); if (!wrong_group) return 4;
    std::string different="different-long-domain.example.test";
    for (unsigned mode=0;mode<5;++mode) {
        auto selected=mode==0 ? *old : mode==1 ? *superseded : *wrong_group;
        auto group=mode==2 ? 1 : 0;
        auto prepared=answer(item,3); auto name=mode==4 ? std::string_view(different) : std::string_view(item.name);
        bool threw=false; fail_after=0;
        try { (void)cache.publish_view(group,item.view+(mode==3),name,
                                       item.type,std::move(prepared),1000,selected); }
        catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (!threw || !lookup(cache,0,item,reader)) return 5;
        auto usable=cache.begin_query(0,item); if (!usable || !cache.cancel_query(*usable)) return 6;
    }
    if (!cache.cancel_query(*wrong_group)) return 7;
    return 0;
}
auto allocation_clear_race() -> int {
    auto item=key("registration-copy-concurrent-with-clear.example.test");
    for (bool publication:{false,true}) {
        std::array<std::size_t,1> capacities{1}; Cache cache(capacities,1,5000,1024*1024);
        auto reader=cache.reader(0); auto old=cache.begin_query(0,item);
        if (!old || !cache.publish(0,item,answer(item,1),1000,*old)) return 1;
        auto token=cache.begin_query(0,item); if (!token) return 2;
        auto prepared=answer(item,2);
        failure_entered=false; failure_release=false; std::atomic<bool> threw=false;
        std::thread worker([&] {
            fail_after=0; pause_failure=true;
            try {
                if (publication) (void)cache.publish_view(0,item.view,item.name,item.type,std::move(prepared),1000,*token);
                else (void)cache.begin_query(0,item.view,item.name,item.type);
            } catch (std::bad_alloc const&) { threw=true; }
            fail_after=-1; pause_failure=false;
        });
        while (!failure_entered.load()) failure_entered.wait(false);
        bool ok=cache.clear(1000).has_value();
        auto current=cache.begin_query(0,item);
        ok=ok && current && cache.publish(0,item,answer(item,3),1000,*current).has_value();
        failure_release=true; failure_release.notify_one(); worker.join();
        if (!ok || !threw || !lookup(cache,0,item,reader)) return 3;
        auto next=cache.begin_query(0,item);
        if (!next || !cache.cancel_query(*next)) return 4;
    }
    return 0;
}
auto recovery_without_allocation() -> int {
    auto item=key("a.test"); std::array<std::size_t,1> capacities{1}; std::size_t limit=0;
    {
        Cache measure(capacities,1); auto token=measure.begin_query(0,item);
        if (!token || !measure.publish(0,item,answer(item,1),1000,*token)) return 1;
        limit=measure.charged_bytes();
    }
    Cache cache(capacities,1,0,limit,5); auto reader=cache.reader(0);
    auto token=cache.begin_query(0,item);
    if (!token || !cache.publish(0,item,answer(item,1),1000,*token)) return 2;
    bool failed=false;
    auto old=cache.lookup_with_hook(0,item,1000,reader,[&] {
        auto update=cache.begin_query(0,item); if (!update) return;
        auto result=cache.publish(0,item,answer(item,2),1000,*update);
        failed=!result && result.error()==d::CacheError::disabled;
    });
    if (!failed || !old || *old) return 3;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    bool threw=false,success=false; fail_after=0;
    try { success=cache.begin_query(0,item.view,item.name,item.type).has_value(); }
    catch (std::bad_alloc const&) { threw=true; }
    fail_after=-1;
    return threw || !success ? 4 : 0;
}
auto binding_foreground_allocation_faults() -> int {
    using Binding=dns_hp_experiment::GroupBinding;
    auto item=key("binding-foreground-allocation.example.test");
    std::array<std::size_t,1> capacities{2};
    for (unsigned mode=0;mode<5;++mode) {
        unsigned failures=0;
        for (int position=0;position<128;++position) {
            Cache cache(capacities,1,5000,1024*1024); Binding binding(cache,0); auto reader=cache.reader(0);
            auto seed=binding.begin_query(item);
            if (!seed || !binding.publish(item,answer(item,1),1000,*seed)) return 1;
            auto token=binding.begin_query(item); if (!token) return 2;
            auto prepared=answer(item,2);
            auto invoke=[&]() -> std::expected<void,d::CacheError> {
                if (mode==0) {
                    auto result=binding.begin_query(item);
                    return result ? std::expected<void,d::CacheError>{} : std::unexpected(result.error());
                }
                if (mode==1) return binding.publish(item,std::move(prepared),1000,*token);
                if (mode==2) return binding.publish(item,std::as_const(prepared),1000,*token);
                if (mode==3) return binding.publish_negative(item,d::NegativeKind::no_data,30,1000,*token);
                return binding.invalidate(item,1000,*token);
            };
            bool threw=false; std::expected<void,d::CacheError> result; fail_after=position;
            try { result=invoke(); } catch (std::bad_alloc const&) { threw=true; }
            fail_after=-1;
            if (threw) return 3;
            if (result) break;
            if (result.error()!=d::CacheError::disabled) return 4;
            ++failures;
            auto old=cache.lookup(0,item,1000,reader);
            auto disabled=binding.begin_query(item);
            if (!old || *old || disabled || disabled.error()!=d::CacheError::disabled || !cache.clear(1000)) return 5;
            auto recovered=binding.begin_query(item);
            if (!recovered || !binding.publish(item,answer(item,3),1000,*recovered) || !lookup(cache,0,item,reader)) return 6;
        }
        if (!failures) return 7;
    }
    // Without a finite budget the underlying snapshot deliberately keeps its
    // prior state on allocation failure; the adapter must not mask the error.
    for (bool publication:{false,true}) {
        Cache cache(capacities,1); Binding binding(cache,0); auto reader=cache.reader(0);
        auto seed=binding.begin_query(item);
        if (!seed || !binding.publish(item,answer(item,1),1000,*seed)) return 8;
        auto token=binding.begin_query(item); if (!token) return 9;
        auto prepared=answer(item,2); bool threw=false; fail_after=0;
        try {
            if (publication) (void)binding.publish(item,std::move(prepared),1000,*token);
            else (void)binding.begin_query(item);
        } catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (!threw || !lookup(cache,0,item,reader) || !binding.cancel_query(*token)) return 10;
    }
    return 0;
}
int main() {
    if (auto result=publish_failure_positions()) { std::cerr<<"publish fault "<<result<<'\n'; return 1; }
    if (auto result=shared_update_failure_positions()) { std::cerr<<"update fault "<<result<<'\n'; return 2; }
    if (auto result=multi_group_failure_positions()) { std::cerr<<"multi-group fault "<<result<<'\n'; return 3; }
    if (auto result=negative_and_invalidation_faults()) { std::cerr<<"negative fault "<<result<<'\n'; return 4; }
    if (auto result=stale_admission_faults()) { std::cerr<<"stale fault "<<result<<'\n'; return 5; }
    if (auto result=admission_failure_positions()) { std::cerr<<"admission fault "<<result<<'\n'; return 6; }
    if (auto result=clear_without_allocation()) { std::cerr<<"clear fault "<<result<<'\n'; return 7; }
    if (auto result=construction_failure_positions()) { std::cerr<<"construction fault "<<result<<'\n'; return 8; }
    if (auto result=fail_closed_allocation_faults()) { std::cerr<<"fail-closed fault "<<result<<'\n'; return 9; }
    if (auto result=caller_key_allocation_faults()) { std::cerr<<"caller key fault "<<result<<'\n'; return 11; }
    if (auto result=stale_key_allocation_faults()) { std::cerr<<"stale key fault "<<result<<'\n'; return 12; }
    if (auto result=allocation_clear_race()) { std::cerr<<"allocation clear race "<<result<<'\n'; return 13; }
    if (auto result=recovery_without_allocation()) { std::cerr<<"recovery allocation "<<result<<'\n'; return 14; }
    if (auto result=binding_foreground_allocation_faults()) { std::cerr<<"binding allocation "<<result<<'\n'; return 15; }
    if (Cache::live_nodes()) { std::cerr<<"fault nodes leaked\n"; return 10; }
    std::puts("group snapshot allocation faults and rollback passed");
}
