export module proxy.vless_mux;
import std;
import xudp;
import xudp.server_io;
import xudp.server_direct;
import xudp.server_sessions;
import proxy;
import proxy.session_quota;
import proxy.principal_limits;
import net.udp_socket;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace proxy::vless_mux {
    class FlowAccounting {
        struct Flow {
            xudp::ServerToken token;
            std::optional<SessionQuota::Lease> principal;
            std::optional<SessionQuota::Lease> quota;
            TrafficRegistration traffic;
        };
        Session& owner_;
        std::vector<Flow> flows_;
    public:
        explicit FlowAccounting(Session& owner) : owner_(owner) {}
        auto opened(xudp::ServerToken token,xudp::Address const& target) -> bool {
            auto* parent=owner_.quota ? &owner_ : owner_.transport_owner;
            auto lease=parent && parent->quota ? parent->quota->try_acquire() : std::nullopt;
            if (parent && parent->quota && !lease) return false;
            auto principal=owner_.principal ? owner_.principal->acquire(PrincipalResource::stream) : std::nullopt;
            if (owner_.principal && !principal) return false;
            if (!lease && !principal) return true;
            auto traffic=owner_.track_child_traffic(TrafficProtocol::xudp,ConnectPath::datagrams,target.port,true);
            flows_.push_back({token,std::move(principal),std::move(lease),std::move(traffic)});
            return true;
        }
        auto close_requested() const noexcept -> std::optional<xudp::ServerToken> {
            auto flow=std::ranges::find_if(flows_,[](auto const& item) {return item.traffic.close_requested();});
            if (flow==flows_.end()) return {};
            return flow->token;
        }
        auto retired(xudp::ServerToken token) noexcept -> void {
            std::erase_if(flows_,[&](Flow const& flow) {return flow.token==token;});
        }
        auto delivered(xudp::ServerToken token,bool upstream,std::size_t size) noexcept -> void {
            auto flow=std::ranges::find(flows_,token,&Flow::token);
            if (flow!=flows_.end()) flow->traffic.count(upstream,size);
        }
        auto reserve(bool upstream,std::size_t size) {
            return owner_.reserve_principal_datagram(upstream,size);
        }
        auto close() noexcept -> void {flows_.clear();}
    };
    template<class Stream,class Resolver>
    using Server=xudp::ServerIo<Stream,Resolver,xudp::ServerDirect,FlowAccounting>;

    // ResolveFunction is a compile-time callable borrowing the existing DNS
    // environment. Session and context references have the original layout.
    template<class Session,class ResolveFunction>
    struct Resolver {
        Session& session;nex::corosio::io_context& context;
        bool resolving=false,timed_out=false;std::chrono::steady_clock::time_point deadline{};
        [[no_unique_address]] ResolveFunction lookup;
        auto resolve(xudp::Address const& address) -> nex::capy::task<std::expected<std::vector<net::UdpEndpoint>,int>> {
            using namespace std::chrono_literals;using Clock=std::chrono::steady_clock;
            resolving=true;timed_out=false;deadline=Clock::now()+10s;
            auto endpoints=co_await lookup(session,context,
                std::string(reinterpret_cast<char const*>(address.bytes.data()),address.length),address.port,deadline);
            resolving=false;
            if (!endpoints || timed_out || session.closed) co_return std::unexpected(1);
            std::vector<net::UdpEndpoint> peers;peers.reserve(endpoints->size());
            for (auto const& endpoint:*endpoints) {
                if (endpoint.address().is_v6() && endpoint.address().to_v6().scope_id()) continue;
                net::UdpEndpoint peer{endpoint.address().is_v4() ? std::uint8_t{4} : std::uint8_t{6},{},endpoint.port()};
                if (peer.family==4) {auto bytes=endpoint.address().to_v4().to_bytes();std::ranges::copy(bytes,peer.address.begin());}
                else {auto bytes=endpoint.address().to_v6().to_bytes();std::ranges::copy(bytes,peer.address.begin());}
                peers.push_back(peer);
            }
            co_return peers;
        }
        auto cancel() noexcept -> void {if (session.cancel_dns) session.cancel_dns(session.dns_operation);}
    };
    template<class Session,class Server>
    auto read(Session& session,Server& mux) -> nex::capy::task<nex::capy::results<>> {
        try {while (!session.closed) if (!co_await mux.read_one()) break;}
        catch (...) {mux.cancel();throw;}
        mux.cancel();co_return nex::capy::results<>{};
    }
    template<class Session,class Server>
    auto poll(Session& session,Server& mux) -> nex::capy::task<nex::capy::results<>> {
        using namespace std::chrono_literals;using Clock=std::chrono::steady_clock;
        auto next_expiry=Clock::now()+1s;
        try {
            while (!session.closed) {
                auto now=Clock::now();
                if (now>=next_expiry) {
                    auto expired=co_await mux.expire_one(now,300s);if (!expired) break;
                    next_expiry=now+(*expired ? 5ms : 1s);
                }
                auto result=co_await mux.poll_one();if (!result) break;
                auto [error]=co_await nex::corosio::delay(*result ? 1ms : 5ms);if (error) break;
            }
        } catch (...) {mux.cancel();throw;}
        mux.cancel();co_return nex::capy::results<>{};
    }
    template<class Session,class Server,class Resolver>
    auto timeout(Session& session,Server& mux,Resolver& resolver) -> nex::capy::task<nex::capy::results<>> {
        using namespace std::chrono_literals;using Clock=std::chrono::steady_clock;
        while (!session.closed) {
            if (resolver.resolving && !resolver.timed_out && Clock::now()>=resolver.deadline) {resolver.timed_out=true;resolver.cancel();}
            auto [error]=co_await nex::corosio::delay(5ms);if (error) break;
        }
        mux.cancel();co_return nex::capy::results<>{};
    }
}
