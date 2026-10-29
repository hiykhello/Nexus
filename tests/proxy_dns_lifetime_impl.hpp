// Included in the test-only proxy module implementation to exercise the real
// query_server registration and resolver, without exporting private types.
namespace nexus::proxy {
    struct DnsLifetimeState {
        Session* session = nullptr;
        bool destroyed = false, unregistered = false, returned = false, threw = false, cache_released = false;
    };

    auto dns_lifetime_parent(io::io_context& context, DnsLifetimeState& state, std::uint16_t port)
        -> capy::task<> {
        Session session(context);
        struct Guard {
            Session& session;
            DnsLifetimeState& state;
            ~Guard() {
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
        } guard{session,state};
        DnsRouting routing;
        DnsServer server;
        server.address[0]=127; server.address[3]=1; server.port=port;
        routing.servers.push_back(server);
        routing.strategy=DnsStrategy::ipv4_only;
        session.dns=std::make_shared<DnsState>(std::move(routing));
        state.session=&session;
        try {
            (void)co_await resolve_bootstrap(session,context,0,"pending.test",80);
            state.returned=true;
        } catch (...) { state.threw=true; }
    }
}

extern "C" bool nexus_test_dns_reply();
extern "C" int nexus_test_dns_lifetime(unsigned backend, unsigned mode, std::uint16_t port) {
    using namespace nexus::proxy;
    using namespace std::chrono_literals;
    DnsLifetimeState state;
    {
#if BOOST_COROSIO_HAVE_LIBURING
        io::io_context context = backend ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
        if (backend) return 77;
        io::io_context context(io::epoll);
#endif
        capy::run_async(context.get_executor())(dns_lifetime_parent(context,state,port));
        context.restart();
        (void)context.run_for(50ms);
        if (mode == 2) return state.destroyed && state.unregistered && state.threw && state.cache_released && !state.returned ? 0 : 1;
        if (!state.session || !state.session->cancel_dns || !state.session->dns_operation || state.destroyed) return 2;
        if (mode == 3) {
            if (!nexus_test_dns_reply()) return 5;
            context.restart();
            (void)context.run_for(1s);
            return state.destroyed && state.unregistered && state.threw && state.cache_released && !state.returned ? 0 : 6;
        }
        if (mode == 1) {
            state.session->close();
            context.restart();
            (void)context.run_for(1s);
            if (!state.destroyed || !state.returned || state.threw) return 3;
        }
    }
    return state.destroyed && state.unregistered && state.cache_released && (mode == 1 ? state.returned : !state.returned) ? 0 : 4;
}
