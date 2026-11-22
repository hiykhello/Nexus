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
using namespace std::chrono_literals;
struct Fixture {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
    dns::detail::AddressResolver resolver{context};
    std::optional<std::expected<dns::AddressAnswer,dns::detail::ResolveError>> result;
};
auto resolve(Fixture& f, std::uint16_t port, dns::Question question) -> capy::task<> {
    f.result=co_await f.resolver.resolve_random(io::endpoint(io::ipv4_address::loopback(),port),
                                               std::move(question),std::chrono::steady_clock::now()+3s);
}
auto main(int argc,char** argv) -> int {
    if (argc!=3) return 2;
    Fixture f;
    auto kind=std::string_view(argv[2]);
    dns::Question question{kind=="alias" ? "alias.nexus.test" : kind=="missing" ? "missing.nexus.test" :
        kind=="bind-nodata" ? "v4.nexus.test" : kind=="bind-alias-nodata" ? "v4alias.nexus.test" :
        kind=="bind-alias-missing" ? "missingalias.nexus.test" : "target.nexus.test",
        static_cast<std::uint16_t>(kind=="v6" || kind=="bind-nodata" || kind=="bind-alias-nodata" ? 28 : 1)};
    capy::run_async(f.context.get_executor())(resolve(f,static_cast<std::uint16_t>(std::stoi(argv[1])),question));
    f.context.restart(); (void)f.context.run_for(4s);
    if (!f.result) return 3;
    if (kind=="missing") return !*f.result && f.result->error()==dns::detail::ResolveError::name_not_found ? 0 : 9;
    if (kind.starts_with("bind-")) {
        auto expected=kind=="bind-alias-missing" ? dns::detail::ResolveError::name_not_found : dns::detail::ResolveError::no_data;
        auto ttl=f.resolver.negative_cache_ttl();
        auto max_ttl=kind=="bind-nodata" ? 90u : 30u;
        return !*f.result && f.result->error()==expected && ttl && *ttl>0 && *ttl<=max_ttl ? 0 : 10;
    }
    if (!*f.result) return 3;
    auto const& answer=**f.result;
    if (answer.addresses.size()!=1 || !answer.ttl || *answer.ttl==0 || *answer.ttl>60) return 4;
    if (answer.canonical_name!="target.nexus.test") return 5;
    auto const& address=answer.addresses[0];
    if (kind=="alias" && answer.chain.size()!=2) return 6;
    return kind=="v6" ? (address.size==16 && address.bytes[0]==0x20 && address.bytes[15]==1 ? 0 : 7) :
                        (address.size==4 && address.bytes[0]==192 && address.bytes[3]==1 ? 0 : 8);
}
