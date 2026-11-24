import std;
import relay;
import relay.session_quota;

namespace p = relay;
using namespace std::chrono_literals;
using Owners=std::vector<std::unique_ptr<p::Session>>;

static_assert(!std::is_move_constructible_v<p::Session>);
static_assert(!std::is_copy_constructible_v<p::Session>);

auto attach(p::Server& server,Owners& owners,std::size_t count) -> bool {
    for (std::size_t i=0;i<count;++i) {
        auto lease=server.acquire_session();
        if (!lease) return false;
        auto session=std::make_unique<p::Session>(server.executor_context());
        server.attach_session(*session,std::move(*lease));
        owners.push_back(std::move(session));
    }
    return true;
}

auto consistent(Owners const& owners,std::vector<p::Session*> const& registry) -> bool {
    if (std::ranges::count_if(owners,[](auto const& owner) {return bool(owner);})!=
        static_cast<std::ptrdiff_t>(registry.size())) return false;
    for (std::size_t i=0;i<registry.size();++i) {
        auto* session=registry[i];
        if (session->registry!=&registry || session->registry_index!=i ||
            std::ranges::count_if(owners,[session](auto const& owner) {return owner.get()==session;})!=1) return false;
    }
    return true;
}

auto removals() -> bool {
    p::Server server;
    Owners owners;
    if (!attach(server,owners,64) || server.acquire_session()) return false;
    auto* registry=owners.front()->registry;
    if (!consistent(owners,*registry)) return false;
    // An odd stride visits every original slot, mixing tail, middle and first.
    for (std::size_t i=0;i<64;++i) {
        owners[(i*37+13)%64].reset();
        if (!consistent(owners,*registry)) return false;
    }
    if (!registry->empty()) return false;
    std::vector<p::SessionQuota::Lease> recovered;
    for (std::size_t i=0;i<64;++i) {
        auto lease=server.acquire_session(); if (!lease) return false;
        recovered.push_back(std::move(*lease));
    }
    return !server.acquire_session();
}

struct CancelOthers {
    Owners* owners=nullptr;
    std::array<std::size_t,2> victims{};
    std::size_t count=0,calls=0;
    static auto cancel(void* raw) noexcept -> void {
        auto& self=*static_cast<CancelOthers*>(raw); ++self.calls;
        for (std::size_t i=0;i<self.count;++i) (*self.owners)[self.victims[i]].reset();
    }
};

auto reentrant_close(bool stopping) -> bool {
    p::Server server;
    // Keep callback state alive until every Session has been destroyed.
    CancelOthers first,second;
    Owners owners;
    if (!attach(server,owners,8)) return false;
    auto* registry=owners.front()->registry;
    for (auto& session:owners) session->handshake_deadline=std::chrono::steady_clock::now()-1s;
    first={&owners,{1,5},2,0}; second={&owners,{0,0},1,0};
    owners[7]->dns_operation=&first; owners[7]->cancel_dns=&CancelOthers::cancel;
    owners[6]->dns_operation=&second; owners[6]->cancel_dns=&CancelOthers::cancel;
    // The current Session remains alive throughout close(); its callback can
    // synchronously release other tasks/sessions and swap the registry's tail.
    if (stopping) server.stop(); else server.poll(0ms);
    // A previously visited tail may move below the cursor. Repeating close is
    // intentional: keep the production cancellation contract, but bound the
    // total callbacks by the registry size at the beginning of this walk.
    if (!first.calls || !second.calls || first.calls+second.calls>8 || !consistent(owners,*registry)) return false;
    if (!std::ranges::all_of(owners,[](auto const& session) {return !session || session->closed;})) return false;
    owners.clear();
    if (!registry->empty()) return false;
    auto port=server.start(0); if (!port) return false;
    server.stop();
    return true;
}

auto main() -> int {
    if (!removals()) return 1;
    if (!reentrant_close(false)) return 2;
    if (!reentrant_close(true)) return 3;
    std::println("session registry: arbitrary removal, quota recovery and reentrant timeout/stop traversal passed");
}
