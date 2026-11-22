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
namespace io=nex::corosio;
using namespace std::chrono_literals;
struct Fixture {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
    dns::AddressCache cache{8};
    dns::detail::DualAddressResolver resolver{context,cache};
    std::optional<std::expected<std::vector<dns::Address>,dns::detail::ResolveError>> result;
};
auto run(Fixture& f, std::uint16_t port, bool reuse) -> capy::task<> {
    auto upstream=io::endpoint(io::ipv4_address::loopback(),port);
    auto deadline=std::chrono::steady_clock::now()+2s;
    f.result=co_await f.resolver.resolve(upstream,1,"a.test",deadline);
    if (reuse && *f.result) {
        dns::detail::DualAddressResolver second(f.context,f.cache);
        f.result=co_await second.resolve(upstream,1,"a.test",deadline);
    }
}
auto main(int argc, char** argv) -> int {
    if (argc!=3) return 1;
    Fixture f;
    std::string_view mode=argv[2];
    capy::run_async(f.context.get_executor())(run(f,static_cast<std::uint16_t>(std::stoi(argv[1])),mode=="cache"));
    bool cancel=mode=="cancel" || mode=="cancel-v6";
    f.context.restart(); (void)f.context.run_for(cancel ? 100ms : 3s);
    if (cancel) { f.resolver.cancel(); f.context.restart(); (void)f.context.run_for(1s); }
    if (!f.result) return 2;
    if (mode=="both" || mode=="cache" || mode=="v4" || mode=="v6") {
        if (!*f.result) return 3;
        auto const& addresses=**f.result;
        if (mode=="both" || mode=="cache") return addresses.size()==2 && addresses[0].size==4 && addresses[1].size==16 ? 0 : 4;
        return addresses.size()==1 && addresses[0].size==(mode=="v4" ? 4 : 16) ? 0 : 5;
    }
    if (*f.result) return 6;
    auto expected=cancel ? dns::detail::ResolveError::canceled :
                  mode=="limit" ? dns::detail::ResolveError::limit :
                  mode=="nodata" ? dns::detail::ResolveError::no_data :
                  mode=="nxdomain" ? dns::detail::ResolveError::name_not_found :
                  mode=="servfail" ? dns::detail::ResolveError::server_failure : dns::detail::ResolveError::protocol;
    return f.result->error()==expected ? 0 : 7;
}
