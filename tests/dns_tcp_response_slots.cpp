import std;
import proxy;
import proxy.dns_state;
import dns.shared_coordinator;
import dns.response_cache;
import dns.local_response;
import dns.local_config;
import dns.corosio_resolver;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace dns=dns;
namespace proxy=proxy;
namespace io=nex::corosio;
namespace capy=nex::capy;
using Clock=std::chrono::steady_clock;
auto run(proxy::Session& session,io::io_context& context,proxy::DnsSlot& slot,std::size_t index,
    std::string name,bool& done,bool& ok,bool expect_cancel,bool disabled=true) -> capy::task<> {
    auto result=co_await proxy::resolve_response_owned(session,context,slot,index,std::move(name),1,Clock::now()+std::chrono::seconds(3),{},disabled);
    ok=expect_cancel ? !result && result.error()==dns::detail::ResolveError::canceled : bool(result);
    done=true;
}
auto main(int argc,char** argv) -> int {
    if(argc!=4 && argc!=5)return 2;
    auto port=[](char const* text) {return static_cast<std::uint16_t>(std::strtoul(text,nullptr,10));};
    bool uring=std::string_view(argv[3])=="uring";
    bool coalesce=argc==5 && std::string_view(argv[4])=="coalesce";
    if(argc==5 && !coalesce)return 2;
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    if(uring)return 77;io::io_context context(io::epoll);
#endif
    std::array<std::size_t,1> capacities{1};
    dns_hp_experiment::GroupSnapshot group(capacities,dns_hp_experiment::GroupSnapshot::SharedCapacity{32},1);
    dns_hp_experiment::Coordinator coordinator(16,64);
    dns_hp_experiment::ViewRegistry views(4,65536,32);
    dns::ResponseCache responses(32);
    proxy::DnsRouting routing;proxy::DnsServer first;first.address[0]=127;first.address[3]=1;first.port=port(argv[1]);
    auto second=first;second.port=port(argv[2]);routing.servers={first,second};
    auto a=views.register_profile(routing,0),b=views.register_profile(routing,1);if(!a || !b)return 3;
    views.seal();std::array profiles{*a,*b};
    proxy::DnsState state(std::move(routing),group,0,0);
    state.views.emplace(views,profiles);state.coordinator.emplace(context,state.cache,coordinator);
    state.response_coordinator.emplace(context,responses,coordinator);
    proxy::Session session(context);session.dns=&state;
    proxy::DnsSlot slow,fast,pre_canceled;pre_canceled.cancel();
    bool slow_done=false,slow_ok=false,fast_done=false,fast_ok=false,pending=false,pre_done=false,pre_ok=false,duplicate_rejected=false;
    capy::run_async(context.get_executor())(run(session,context,slow,0,coalesce ? "shared.test" : "slow.test",slow_done,slow_ok,true,!coalesce));
    capy::run_async(context.get_executor())(run(session,context,fast,coalesce ? 0 : 1,coalesce ? "shared.test" : "fast.test",fast_done,fast_ok,false,!coalesce));
    capy::run_async(context.get_executor())(run(session,context,pre_canceled,0,"never.test",pre_done,pre_ok,true));
    auto stop=[&]() -> capy::task<> {
        io::steady_timer timer(context);timer.expires_at(Clock::now()+std::chrono::milliseconds(150));auto [error]=co_await timer.wait();
        if(!error) {
            auto duplicate=co_await proxy::resolve_response_owned(session,context,slow,0,"duplicate.test",1,Clock::now()+std::chrono::seconds(1),{},true);
            duplicate_rejected=!duplicate && duplicate.error()==dns::detail::ResolveError::state;
            pending=!fast_done;slow.cancel();
        }
    };
    capy::run_async(context.get_executor())(stop());
    (void)context.run_for(std::chrono::seconds(4));
    if(!slow_done || !slow_ok || !fast_done || !fast_ok || !pending || !pre_done || !pre_ok || !duplicate_rejected || slow.operation || fast.operation || session.dns_operation) {
        slow.cancel();fast.cancel();context.restart();(void)context.run();return 4;
    }
    {
        auto local=std::make_shared<dns::LocalSnapshot>();dns::LocalServer address;address.address[0]=127;address.address[3]=1;
        local->hosts.push_back({"local.test",address});
        state.routing.servers.push_back(proxy::DnsServer{});
        dns_hp_experiment::LocalViewRegistry registry;state.local_views.emplace(registry);
        proxy::DnsSlot slot;bool done=false,ok=false;
        auto local_task=[&]() -> capy::task<> {
            auto result=co_await proxy::resolve_response_owned(session,context,slot,2,"local.test",1,Clock::now()+std::chrono::seconds(2),local,true);
            ok=result && result->local && !result->upstream.port() && result->question=="local.test";
            done=true;
        };
        capy::run_async(context.get_executor())(local_task());context.restart();(void)context.run_for(std::chrono::seconds(1));
        if(!done || !ok || slot.operation)return 6;
    }
    state.response_coordinator->stop();state.coordinator->stop();context.restart();(void)context.run_for(std::chrono::seconds(2));
    if(!state.response_coordinator->drained() || !state.coordinator->drained())return 5;
    return 0;
}
