#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
import std;
import dns.message;
import dns.corosio_query;
import dns.cache;
import dns.corosio_cached;
namespace capy=boost::capy;
namespace io = ::corosio;
using namespace std::chrono_literals;
struct Fixture {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
    dns::AddressCache cache{4};
    int result=0;
    int race_done=0, race_errors=0;
    std::unique_ptr<dns::detail::CachedAddressResolver> operation;
};
auto run(Fixture& f, std::uint16_t port) -> capy::task<> {
    auto upstream=io::endpoint(io::ipv4_address::loopback(),port);
    auto deadline=std::chrono::steady_clock::now()+4s;
    for (int i=0;i<6;++i) {
        dns::detail::CachedAddressResolver operation(f.context,f.cache);
        auto name=i>=4 ? "missing.test" : "a.test";
        auto value=co_await operation.resolve(upstream,i==2 ? 2 : 1,{name,1},deadline);
        if (i>=4) {
            if (value || value.error()!=dns::detail::ResolveError::name_not_found) { f.result=10+i; co_return; }
        } else if (!value || value->addresses.size()!=1 || value->addresses[0].bytes[3]!=1 || !value->ttl || !*value->ttl) {
            f.result=20+i; co_return;
        }
        if (i==2) {
            auto now=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
            if (!f.cache.clear(static_cast<std::uint64_t>(now))) { f.result=30; co_return; }
        }
    }
    f.result=1;
}
auto cancel_run(Fixture& f, std::uint16_t port) -> capy::task<> {
    f.operation=std::make_unique<dns::detail::CachedAddressResolver>(f.context,f.cache);
    auto value=co_await f.operation->resolve(io::endpoint(io::ipv4_address::loopback(),port),1,{"a.test",1},
                                             std::chrono::steady_clock::now()+2s);
    f.result=!value && value.error()==dns::detail::ResolveError::canceled ? 1 : 4;
}
auto race_query(Fixture& f, std::uint16_t port, std::optional<dns::detail::ResolveError> expected) -> capy::task<> {
    dns::detail::CachedAddressResolver operation(f.context,f.cache);
    auto value=co_await operation.resolve(io::endpoint(io::ipv4_address::loopback(),port),1,{"race.test",1},
                                          std::chrono::steady_clock::now()+4s);
    if (expected ? (value || value.error()!=*expected) : (!value || value->addresses.size()!=1)) ++f.race_errors;
    ++f.race_done;
    if (expected) { std::println("negative processed"); std::fflush(stdout); }
}
auto negative_run(Fixture& f, std::uint16_t port, std::string_view mode) -> capy::task<> {
    auto upstream=io::endpoint(io::ipv4_address::loopback(),port);
    auto expected=mode.starts_with("invalid-") ? dns::detail::ResolveError::protocol :
        mode.find("nodata")!=mode.npos ? dns::detail::ResolveError::no_data : dns::detail::ResolveError::name_not_found;
    for (int i=0;i<3;++i) {
        dns::detail::CachedAddressResolver operation(f.context,f.cache,false,mode=="disabled");
        auto value=co_await operation.resolve(upstream,i==2 ? 2 : 1,{"negative.test",1},
                                               std::chrono::steady_clock::now()+4s);
        if (value || value.error()!=expected) { f.result=20+i; co_return; }
    }
    if ((mode.starts_with("alias-") || mode.starts_with("inline-")) && !mode.ends_with("zero")) {
        auto now=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
        auto expired=f.cache.lookup_negative({1,"negative.test",1},static_cast<std::uint64_t>(now)+5000);
        if (!expired || *expired) { f.result=30; co_return; }
    }
    f.result=1;
}
auto main(int argc,char** argv) -> int {
    if (argc<2 || argc>3) return 2;
    Fixture f;
    if (argc==3 && std::string_view(argv[2]).starts_with("negative-")) {
        capy::run_async(f.context.get_executor())(negative_run(f,static_cast<std::uint16_t>(std::stoi(argv[1])),
                                                                std::string_view(argv[2]).substr(9)));
        f.context.restart(); (void)f.context.run_for(5s);
        return f.result==1 ? 0 : f.result ? f.result : 3;
    }
    if (argc==3 && std::string_view(argv[2]).starts_with("race-")) {
        auto port=static_cast<std::uint16_t>(std::stoi(argv[1]));
        auto mode=std::string_view(argv[2]);
        auto error=mode=="race-nodata" ? dns::detail::ResolveError::no_data :
                   mode=="race-servfail" ? dns::detail::ResolveError::server_failure : dns::detail::ResolveError::name_not_found;
        bool transient=mode=="race-servfail";
        capy::run_async(f.context.get_executor())(race_query(f,port,std::nullopt));
        capy::run_async(f.context.get_executor())(race_query(f,port,error));
        f.context.restart(); (void)f.context.run_for(4s);
        if (f.race_done!=2 || f.race_errors || f.cache.size()!=(transient ? 1u : 0u)) return 8;
        capy::run_async(f.context.get_executor())(race_query(f,port,std::nullopt));
        f.context.restart(); (void)f.context.run_for(4s);
        return f.race_done==3 && !f.race_errors && f.cache.size()==1 ? 0 : 9;
    }
    if (argc==3) {
        capy::run_async(f.context.get_executor())(cancel_run(f,static_cast<std::uint16_t>(std::stoi(argv[1]))));
        f.context.restart(); (void)f.context.run_for(100ms);
        if (!f.operation) return 5;
        f.operation->cancel();
        f.context.restart(); (void)f.context.run_for(1s);
        if (f.result!=1 || f.cache.size()) return 6;
        // A leaked registration would reduce the available bounded capacity.
        for (int i=0;i<4096;++i) if (!f.cache.begin_query({1,"a.test",1})) return 7;
        return 0;
    }
    capy::run_async(f.context.get_executor())(run(f,static_cast<std::uint16_t>(std::stoi(argv[1]))));
    f.context.restart(); (void)f.context.run_for(5s);
    return f.result==1 ? 0 : f.result ? f.result : 3;
}
