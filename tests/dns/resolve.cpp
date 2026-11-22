#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
import std;
import dns.message;
import dns.corosio_query;
import dns.corosio_resolver;
namespace capy=boost::capy;
namespace io=nex::corosio;
namespace dns=dns;
using namespace std::chrono_literals;
struct Fixture {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
    dns::detail::AddressResolver resolver{context};
    unsigned ids=0;
    std::optional<std::expected<dns::AddressAnswer,dns::detail::ResolveError>> result;
};
auto run(Fixture& f, std::uint16_t port, bool fail_random, bool use_system) -> capy::task<> {
    auto generator=[&]() -> std::expected<std::uint16_t,dns::detail::ResolveError> {
        if (fail_random) return std::unexpected(dns::detail::ResolveError::random);
        return static_cast<std::uint16_t>(0x1000+ ++f.ids);
    };
    if (use_system) {
        f.result=co_await f.resolver.resolve_random(io::endpoint(io::ipv4_address::loopback(),port),
                                                   {"a.test",1},std::chrono::steady_clock::now()+2s);
        co_return;
    }
    f.result=co_await f.resolver.resolve(io::endpoint(io::ipv4_address::loopback(),port),{"a.test",1},
                                         std::chrono::steady_clock::now()+2s,generator);
}
auto main(int argc,char** argv) -> int {
    if (argc!=3) return 2;
    Fixture f;
    auto mode=std::string_view(argv[2]);
    capy::run_async(f.context.get_executor())(run(f,static_cast<std::uint16_t>(std::stoi(argv[1])),mode=="random",mode=="system"));
    f.context.restart(); (void)f.context.run_for(mode=="cancel" ? 100ms : 3s);
    if (mode=="cancel") { f.resolver.cancel(); f.context.restart(); (void)f.context.run_for(1s); }
    if (!f.result) return 3;
    if (mode=="ok" || mode=="system") {
        if (!*f.result || (mode=="ok" && f.ids!=2)) return 4;
        auto const& a=**f.result;
        return a.canonical_name=="b.test" && a.chain.size()==2 && a.addresses.size()==1 &&
               a.addresses[0].bytes[0]==192 && a.ttl && *a.ttl<=19 ? 0 : 5;
    }
    if (*f.result) return 6;
    auto expected=mode=="loop" ? dns::detail::ResolveError::alias_loop :
                  mode=="cancel" ? dns::detail::ResolveError::canceled :
                  mode=="nxdomain" ? dns::detail::ResolveError::name_not_found :
                  mode=="nodata" ? dns::detail::ResolveError::no_data :
                  mode=="referral" ? dns::detail::ResolveError::referral :
                  mode=="empty" || mode=="wrong-zone" ? dns::detail::ResolveError::indeterminate :
                  mode=="servfail" ? dns::detail::ResolveError::server_failure :
                  mode=="refused" ? dns::detail::ResolveError::refused :
                  mode=="edns" || mode=="cross-family-conflict" ? dns::detail::ResolveError::protocol : dns::detail::ResolveError::random;
    return f.result->error()==expected ? 0 : 7;
}
