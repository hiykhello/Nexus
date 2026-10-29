module;
#include <boost/capy/buffers.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/local_connect_pair.hpp>
#include <boost/corosio/local_stream_socket.hpp>
module nexus.proxy;
import std;
import nexus.dns.fakeip_shared;
import nexus.dns.fakeip_registry;
import nexus.dns.fakeip_response;
import nexus.dns.message;

namespace nexus::proxy {
    namespace {
        constexpr std::uint32_t base=0xc6120000;
        struct LifetimeState {
            std::shared_ptr<dns::FakeIpShared> pool;
            std::vector<std::uint8_t> other;
            std::array<bool,2> entered{}, destroyed{}, pinned_on_destroy{};
            bool parent_destroyed=false, children_first=false, returned=false;
            auto pinned() -> bool {
                auto result=pool->respond(base,other,7);
                return !result && result.error()==std::variant<dns::FakeIpRegistryError,dns::FakeIpDnsError>{dns::FakeIpDnsError::full};
            }
        };
        auto child(io::local_stream_socket& socket, LifetimeState& state, unsigned index)
            -> capy::task<capy::results<>> {
            struct Guard {
                LifetimeState& state; unsigned index;
                ~Guard() { state.pinned_on_destroy[index]=state.pinned(); state.destroyed[index]=true; }
            } guard{state,index};
            state.entered[index]=true;
            std::array<char,1> bytes{};
            auto [error,count]=co_await socket.read_some(capy::mutable_buffer(bytes.data(),bytes.size()));
            (void)count;
            co_return capy::results<>{error};
        }
        auto parent(std::unique_ptr<Session> session, io::io_context& context, LifetimeState& state)
            -> capy::task<> {
            struct Guard {
                LifetimeState& state;
                ~Guard() { state.children_first=state.destroyed[0] && state.destroyed[1]; state.parent_destroyed=true; }
            } guard{state};
            io::local_stream_socket first(context),second(context);
            if (io::connect_pair(first,second)) co_return;
            (void)co_await capy::when_all(child(first,state,0),child(second,state,1));
            state.returned=true;
        }
    }
}

extern "C" int nexus_test_fakeip_lifetime(unsigned backend) {
    using namespace nexus::proxy;
    using namespace std::chrono_literals;
    LifetimeState state;
    state.pool=std::make_shared<nexus::dns::FakeIpShared>(1);
    auto old=Clock::now()-10s;
    auto query=nexus::dns::make_query(1,{"old.test",1});
    auto other=nexus::dns::make_query(2,{"other.test",1});
    if (!query || !other || !state.pool->add(base,base+3,base+1,base+1,1s,0s) || !state.pool->seal()) return 1;
    state.other=std::move(*other);
    auto response=state.pool->respond(base,*query,7,old);
    if (!response || !(*response)->finish(true,old)) return 2;
    auto target=state.pool->acquire(base+1,7,old);
    if (!target || !*target) return 3;
    std::vector<Session*> registry;
    {
#if BOOST_COROSIO_HAVE_LIBURING
        io::io_context context = backend ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
        if (backend) return 77;
        io::io_context context(io::epoll);
#endif
        auto session=std::make_unique<Session>(context);
        session->fakeip=state.pool;
        session->fakeip_target=std::move(*target);
        registry.push_back(session.get());
        session->registry=&registry;
        capy::run_async(context.get_executor())(parent(std::move(session),context,state));
        context.restart(); (void)context.run_for(30ms);
        if (!state.entered[0] || !state.entered[1] || state.parent_destroyed || !state.pinned()) return 4;
    }
    if (!registry.empty() || !state.parent_destroyed || !state.children_first || state.returned ||
        !state.pinned_on_destroy[0] || !state.pinned_on_destroy[1]) return 5;
    auto recovered=state.pool->respond(base,state.other,7);
    if (!recovered || !(*recovered)->finish(false)) return 6;
    return 0;
}
