module;
#include <boost/corosio/backend.hpp>
module proxy;
import std;
import proxy.dns_state;
import proxy.dns_backend;
import dns.corosio_cached;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

// Compiled only by the lifetime feature; no test code is textually included
// into the data-plane dialer or linked into ordinary server graphs.
namespace proxy {
    auto dns_slot_task(Session& session, nex::corosio::io_context& context, DnsSlot& slot, std::string name, bool& done)
        -> nex::capy::task<> {
        (void)co_await resolve_bootstrap_owned(session,context,slot,0,std::move(name),80,Clock::now()+std::chrono::seconds(10));
        done=true;
    }
    struct DnsLifetimeState {
        Session* session = nullptr;
        bool destroyed = false, unregistered = false, returned = false, threw = false, cache_released = false;
    };

    struct DnsLifetimeGuard {
        Session& session;
        DnsLifetimeState& state;
        ~DnsLifetimeGuard() {
            state.unregistered = !session.cancel_dns && !session.dns_operation;
            try {
                if (!session.dns) throw 1;
                // A leaked pending token leaves fewer than 4096 slots.
                unsigned registered=0;
                for (; registered<4096; ++registered)
                    if (!session.dns->cache.begin_query({1,"probe.test",1})) break;
                state.cache_released=registered==4096;
            } catch (...) { state.cache_released=false; }
            state.session = nullptr;
            state.destroyed = true;
        }
    };

    auto dns_lifetime_parent(std::unique_ptr<Session> owned, nex::corosio::io_context& context, DnsLifetimeState& state)
        -> nex::capy::task<> {
        auto& session=*owned;
        DnsLifetimeGuard guard{session,state};
        state.session=&session;
        try {
            (void)co_await resolve_bootstrap(session,context,0,"pending.test",80,session.started+std::chrono::seconds(10));
            state.returned=true;
        } catch (...) { state.threw=true; }
    }
    auto dns_question_parent(std::unique_ptr<Session> owned,nex::corosio::io_context& context,DnsLifetimeState& state)
        -> nex::capy::task<> {
        auto& session=*owned;
        DnsLifetimeGuard guard{session,state};
        state.session=&session;
        try {
            (void)co_await resolve_destination(session,context,"pending.test",80,session.started+std::chrono::seconds(10));
            state.returned=true;
        } catch (...) { state.threw=true; }
    }

}

extern "C" int nexus_test_dns_independent_slots(unsigned backend, std::uint16_t port) {
    using namespace proxy;
    using namespace std::chrono_literals;
#if BOOST_COROSIO_HAVE_LIBURING
    nex::corosio::io_context context = backend ? nex::corosio::io_context(nex::corosio::uring) : nex::corosio::io_context(nex::corosio::epoll);
#else
    if (backend) return 77;
    nex::corosio::io_context context(nex::corosio::epoll);
#endif
    DnsRouting routing; DnsServer upstream; upstream.address[0]=127; upstream.address[3]=1; upstream.port=port;
    routing.servers.push_back(upstream); routing.strategy=DnsStrategy::ipv4_only;
    DnsState dns(std::move(routing)); Session session(context); session.dns=&dns;
    DnsSlot first,second; bool first_done=false,second_done=false;
    nex::capy::run_async(context.get_executor())(dns_slot_task(session,context,first,"first.test",first_done));
    nex::capy::run_async(context.get_executor())(dns_slot_task(session,context,second,"second.test",second_done));
    context.restart(); (void)context.run_for(100ms);
    if (!first.operation || !second.operation || first.operation==second.operation || first_done || second_done) return 1;
    first.cancel(); context.restart(); (void)context.run_for(100ms);
    if (!first_done || first.operation || !second.operation || second_done) return 2;
    second.cancel(); context.restart(); (void)context.run_for(100ms);
    if (!second_done || second.operation || session.dns_operation || session.cancel_dns) return 3;
    DnsSlot canceled; canceled.cancel(); bool canceled_done=false;
    nex::capy::run_async(context.get_executor())(dns_slot_task(session,context,canceled,"never.test",canceled_done));
    context.restart(); (void)context.run_for(100ms);
    if (!canceled_done || canceled.operation) return 4;
    return 0;
}

extern "C" bool nexus_test_dns_reply();
extern "C" int nexus_test_dns_lifetime(unsigned backend, unsigned mode, std::uint16_t port) {
    using namespace proxy;
    using namespace std::chrono_literals;
    DnsLifetimeState state;
    std::vector<Session*> registry;
    DnsRouting routing;
    DnsServer server;
    server.address[0]=127; server.address[3]=1; server.port=port;
    routing.servers.push_back(server);
    routing.strategy=DnsStrategy::ipv4_only;
    DnsState dns(std::move(routing));
    {
#if BOOST_COROSIO_HAVE_LIBURING
        nex::corosio::io_context context = backend ? nex::corosio::io_context(nex::corosio::uring) : nex::corosio::io_context(nex::corosio::epoll);
#else
        if (backend) return 77;
        nex::corosio::io_context context(nex::corosio::epoll);
#endif
        auto session=std::make_unique<Session>(context);
        session->dns=&dns;
        registry.push_back(session.get());
        session->registry=&registry;
        nex::capy::run_async(context.get_executor())(dns_lifetime_parent(std::move(session),context,state));
        context.restart();
        (void)context.run_for(50ms);
        if (mode == 2) return state.destroyed && state.unregistered && state.threw && state.cache_released && registry.empty() && !state.returned ? 0 : 1;
        if (!state.session || !state.session->cancel_dns || !state.session->dns_operation || state.destroyed) return 2;
        if (mode == 3) {
            if (!nexus_test_dns_reply()) return 5;
            context.restart();
            (void)context.run_for(1s);
            return state.destroyed && state.unregistered && state.threw && state.cache_released && registry.empty() && !state.returned ? 0 : 6;
        }
        if (mode == 1) {
            state.session->close();
            context.restart();
            (void)context.run_for(1s);
            if (!state.destroyed || !state.returned || state.threw) return 3;
        }
    }
    return state.destroyed && state.unregistered && state.cache_released && registry.empty() && (mode == 1 ? state.returned : !state.returned) ? 0 : 4;
}

extern "C" bool nexus_test_dns_first_reply();
extern "C" int nexus_test_dns_question_lifetime(unsigned backend,unsigned mode,std::uint16_t first,std::uint16_t second) {
    using namespace proxy;
    using namespace std::chrono_literals;
    DnsLifetimeState state;
    std::vector<Session*> registry;
    DnsServer a; a.address[0]=127; a.address[3]=1; a.port=first;
    auto b=a; b.port=second;
    DnsRouting routing{{a,b},{{"",false,0,1},{"",false,1,28}},0};
    DnsState dns(std::move(routing));
    {
#if BOOST_COROSIO_HAVE_LIBURING
        nex::corosio::io_context context=backend ? nex::corosio::io_context(nex::corosio::uring) : nex::corosio::io_context(nex::corosio::epoll);
#else
        if (backend) return 77;
        nex::corosio::io_context context(nex::corosio::epoll);
#endif
        auto session=std::make_unique<Session>(context);
        session->dns=&dns; registry.push_back(session.get()); session->registry=&registry;
        nex::capy::run_async(context.get_executor())(dns_question_parent(std::move(session),context,state));
        context.restart(); (void)context.run_for(50ms);
        if (!state.session || !state.session->cancel_dns || state.destroyed || !nexus_test_dns_first_reply()) return 1;
        context.restart(); (void)context.run_for(50ms);
        if (mode==2) return state.destroyed && state.unregistered && state.threw && state.cache_released && registry.empty() && !state.returned ? 0 : 2;
        if (!state.session || !state.session->cancel_dns || !state.session->dns_operation || state.destroyed) return 3;
        if (mode==3) {
            if (!nexus_test_dns_reply()) return 4;
            context.restart(); (void)context.run_for(1s);
            return state.destroyed && state.unregistered && state.threw && state.cache_released && registry.empty() && !state.returned ? 0 : 5;
        }
        if (mode==1) {
            state.session->close(); context.restart(); (void)context.run_for(1s);
            if (!state.destroyed || !state.returned || state.threw) return 6;
        }
    }
    return state.destroyed && state.unregistered && state.cache_released && registry.empty() &&
        (mode==1 ? state.returned : !state.returned) ? 0 : 7;
}
