#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
import std;
import dns.message;
import dns.corosio_query;
import dns.cache;
import dns.local_config;
import dns.corosio_local;
namespace capy=boost::capy; namespace io = ::corosio;
using namespace std::chrono_literals;
struct Fixture {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
    dns::LocalConfig config;
    std::vector<dns::LocalHost> hosts;
    std::unique_ptr<dns::detail::LocalAddressResolver> resolver;
    std::optional<std::expected<std::vector<dns::Address>,dns::detail::ResolveError>> result;
};
auto run(Fixture& f, std::string name) -> capy::task<> {
    f.result=co_await f.resolver->resolve(std::move(name),std::chrono::steady_clock::now()+4s);
}
int main(int argc,char** argv) {
    if (argc!=4) return 1;
    Fixture f; std::string_view mode=argv[1];
    auto server=dns::parse_local_address("127.0.0.1"); if (!server) return 2;
    server->port=static_cast<std::uint16_t>(std::stoi(argv[2])); f.config.servers.push_back(*server);
    if (std::stoi(argv[3])) { server->port=static_cast<std::uint16_t>(std::stoi(argv[3])); f.config.servers.push_back(*server); }
    f.config.attempts=1; f.config.timeout_seconds=1; f.config.use_tcp=mode=="tcp"; f.config.rotate=mode=="rotate";
    if (mode.starts_with("search") || mode=="ndots" || mode=="absolute") {
        f.config.search={"first.test","second.test"};
        if (mode=="ndots") f.config.ndots=2;
        if (mode=="search-zero") f.config.ndots=0;
        if (mode=="search-root") f.config.search={"","first.test"};
    }
    auto hosts=dns::parse_local_hosts("127.0.0.9 HOST.test\n::1 host.test\n"); if (!hosts) return 3; f.hosts=std::move(*hosts);
    auto strategy=mode=="hosts-v6" ? dns::detail::AddressStrategy::ipv6_only : dns::detail::AddressStrategy::ipv4_only;
    f.resolver=std::make_unique<dns::detail::LocalAddressResolver>(f.context,f.config,f.hosts,strategy,1);
    std::string name=mode=="hosts-v6" || mode=="hosts" ? "HOST.test." : mode=="literal" ? "192.0.2.7" :
        mode=="absolute" ? "remote.test." : mode=="search-absolute-first" ? "remote.test" : mode.starts_with("search") ? "remote" : "remote.test";
    capy::run_async(f.context.get_executor())(run(f,std::move(name)));
    f.context.restart(); (void)f.context.run_for(mode=="cancel" || mode=="search-cancel" ? 100ms : 4s);
    if (mode=="cancel" || mode=="search-cancel") { f.resolver->cancel(); f.context.restart(); (void)f.context.run_for(1s); }
    if (!f.result) return 4;
    if (mode=="cancel" || mode=="search-cancel") return !*f.result && f.result->error()==dns::detail::ResolveError::canceled ? 0 : 5;
    if (mode=="search-failure") return !*f.result && f.result->error()==dns::detail::ResolveError::server_failure ? 0 : 9;
    if (mode=="search-timeout") return !*f.result && f.result->error()==dns::detail::ResolveError::timeout ? 0 : 10;
    if (!*f.result || (**f.result).size()!=1) return 6;
    auto const& address=(**f.result)[0];
    if (mode=="hosts-v6") return address.size==16 && address.bytes[15]==1 ? 0 : 7;
    auto last=mode=="hosts" ? 9 : mode=="literal" ? 7 : 42;
    return address.size==4 && address.bytes[3]==last ? 0 : 8;
}
