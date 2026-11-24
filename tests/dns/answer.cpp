import std;
import dns.corosio_local;
import capy;
import corosio;

namespace io = ::corosio;
using Clock=std::chrono::steady_clock;
using Error=dns::detail::ResolveError;

struct Fixture {
    io::io_context context;
    dns::AddressCache cache{8};
    dns::LocalConfig config;
    std::vector<dns::LocalHost> hosts;
    std::optional<dns::detail::DualAddressResolver> dual;
    std::optional<dns::detail::LocalAddressResolver> local;
    std::optional<std::expected<dns::AddressAnswer,Error>> result;
    explicit Fixture(bool uring) : context(io::make_io_context(uring)) {}
};

auto run(Fixture& fixture,std::uint16_t port,std::string_view mode) -> capy::task<> {
    auto deadline=Clock::now()+std::chrono::seconds(2);
    if (mode=="local" || mode=="hosts") {
        auto server=dns::parse_local_address("127.0.0.1");
        if (!server) throw std::runtime_error("invalid test nameserver");
        server->port=port; fixture.config.servers.push_back(*server);
        fixture.config.attempts=1; fixture.config.search={"rules.test"};
        auto hosts=dns::parse_local_hosts("127.0.0.1 Host.rules.test\n::1 Host.rules.test\n");
        if (!hosts) throw std::runtime_error("invalid test hosts");
        fixture.hosts=std::move(*hosts);
        fixture.local.emplace(fixture.context,fixture.config,fixture.hosts,dns::detail::AddressStrategy::prefer_ipv4);
        fixture.result=co_await fixture.local->resolve_answer(mode=="hosts" ? "HOST.rules.test." : "search",deadline);
        co_return;
    }
    auto options=mode=="options" ? std::optional<dns::detail::FamilyCachePolicy>{dns::detail::FamilyCachePolicy{true,false}} : std::nullopt;
    fixture.dual.emplace(fixture.context,fixture.cache,false,dns::detail::AddressStrategy::prefer_ipv4,false,false,nullptr,nullptr,options);
    auto endpoint=io::endpoint(io::ipv4_address::loopback(),port);
    std::string name=mode=="cancel" ? "pending.rules.test" : mode=="cache" || mode=="options" ? "alias.rules.test" : std::string(mode)+".rules.test";
    fixture.result=co_await fixture.dual->resolve_answer(endpoint,1,name,deadline);
    if ((mode=="cache" || mode=="options") && *fixture.result) {
        dns::detail::DualAddressResolver second(fixture.context,fixture.cache,false,dns::detail::AddressStrategy::prefer_ipv4,false,false,nullptr,nullptr,options);
        fixture.result=co_await second.resolve_answer(endpoint,1,name,deadline);
    }
}

auto main(int argc,char** argv) -> int {
    if (argc!=4) return 1;
    bool uring=std::string_view(argv[3])=="uring";
    if (uring && !io::has_uring) return 77;
    Fixture fixture(uring);
    std::string_view mode=argv[2];
    std::exception_ptr failure;
    capy::run_async(fixture.context.get_executor(),[] {},[&](std::exception_ptr error) { failure=error; })
        (run(fixture,static_cast<std::uint16_t>(std::stoi(argv[1])),mode));
    fixture.context.restart();
    (void)fixture.context.run_for(mode=="cancel" ? std::chrono::milliseconds(80) : std::chrono::seconds(3));
    if (mode=="cancel") {
        fixture.dual->cancel();
        fixture.context.restart(); (void)fixture.context.run_for(std::chrono::seconds(1));
    }
    if (failure || !fixture.result) return 2;
    auto const& result=*fixture.result;
    if (mode=="mismatch" || mode=="conflict" || mode=="many" || mode=="cancel") {
        auto expected=mode=="many" ? Error::limit : mode=="cancel" ? Error::canceled : Error::protocol;
        return !result && result.error()==expected ? 0 : 3;
    }
    if (!result || result->addresses.size()!=2) return 4;
    auto canonical=mode=="hosts" ? "host.rules.test" : mode=="local" ? "search.rules.test" : "canonical.test";
    if (result->canonical_name!=canonical || result->chain.empty() || result->chain.back()!=canonical ||
        result->addresses[0].size!=4 || result->addresses[1].size!=16) return 5;
    if (mode=="hosts") return result->ttl ? 6 : 0;
    if (!result->ttl || !*result->ttl || *result->ttl>60) return 7;
    if (mode!="local" && result->chain.size()!=2) return 8;
    std::println("native answer canonical={}, addresses={}, ttl={}",result->canonical_name,result->addresses.size(),*result->ttl);
}
