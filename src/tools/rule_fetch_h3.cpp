module cli.rule_fetch_h3;
import std;
import cli.rule_fetch_response;
import http.header;
import masque.client_session;
import net.packet_stream_socket;
import proxy;
import quic.ech_config;
import hysteria2.transport_options;
import platform.socket_options;
import tls.profiles;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace cli::rule_fetch {
    namespace {
        using Clock=std::chrono::steady_clock;
        struct Attempt {
            TransferResult result;
            bool retry=false;
        };

        template<class Socket>
        struct Carrier {
            std::unique_ptr<Http3Tunnel> tunnel;
            masque::ClientProfile profile;
            masque::Client<Socket> client;

            Carrier(Http3Dial const& dial,std::string_view authority,hysteria2::TransportOptions options,
                std::shared_ptr<masque::HttpTicketCache> tickets,std::unique_ptr<Http3Tunnel> route={})
                :tunnel(std::move(route)),
                 profile(masque::ClientProfile::for_http(dial.tls.profile(),authority,options,dial.tls.fingerprint(),
                     std::move(tickets))),
                 client(dial.context,profile) {}
        };
        using Direct=Carrier<nex::corosio::udp_socket>;
        using Routed=Carrier<net::PacketStreamSocket<proxy::PacketTunnel>>;

        class Connection {
            std::variant<std::unique_ptr<Direct>,std::unique_ptr<Routed>> carrier_;
            nex::capy::async_event idle_changed_;
            Clock::time_point idle_since_=Clock::now();
            std::uint16_t port_;
            std::size_t active_=0;
            bool stopped_=false,driver_done_=false,finished_=false;

            template<class Operation>
            auto visit(Operation&& apply) const -> decltype(auto) {
                return std::visit([&](auto const& carrier) -> decltype(auto) {return apply(carrier->client);},carrier_);
            }

            auto finish_if_ready() noexcept -> void {
                if (driver_done_ && !active_ && !std::exchange(finished_,true))
                    visit([](auto& client) noexcept {client.finish();});
            }
            auto leave() noexcept -> void {
                if (--active_) return;
                idle_since_=Clock::now();
                idle_changed_.set();
                finish_if_ready();
            }
            struct Registration {
                Connection& connection;
                explicit Registration(Connection& owner):connection(owner) {
                    if (!connection.active_++) connection.idle_changed_.set();
                }
                ~Registration(){connection.leave();}
            };

            auto drive() -> nex::capy::task<nex::capy::results<>> {
                struct Stop {
                    Connection& owner;
                    ~Stop(){owner.stop();}
                } stop{*this};
                co_return co_await visit([](auto& client) {return client.run();});
            }
            auto reap_idle() -> nex::capy::task<nex::capy::results<>> {
                while (!stopped_) {
                    auto deadline=idle_since_+std::chrono::seconds(15);
                    if (!active_ && Clock::now()>=deadline) {
                        stop();
                        break;
                    }
                    idle_changed_.clear();
                    auto wait=idle_changed_.wait();
                    auto [error]=active_ ? co_await std::move(wait) :
                        co_await nex::corosio::timeout(std::move(wait),deadline);
                    if (error && !nex::capy::is_timeout(error)) stop();
                }
                co_return nex::capy::results<>{};
            }
            auto run() -> nex::capy::task<> {
                (void)co_await nex::capy::when_all(drive(),reap_idle());
            }

        public:
            template<class Lower>
            Connection(std::uint16_t port,std::unique_ptr<Lower> carrier)
                :carrier_(std::move(carrier)),port_(port) {}

            ~Connection() {
                // No driver or caller retains this owner when it is destroyed.
                if (!std::exchange(finished_,true)) visit([](auto& client) noexcept {client.finish();});
            }

            auto launch(nex::corosio::io_context& io,std::shared_ptr<Connection> owner) -> void {
                auto done=[owner] noexcept {
                    owner->driver_done_=true;
                    owner->stop();
                    owner->finish_if_ready();
                };
                nex::capy::run_async(io.get_executor(),done,[done](std::exception_ptr) noexcept {done();})(run());
            }
            auto stop() noexcept -> void {
                if (!std::exchange(stopped_,true)) {
                    idle_changed_.set();
                    visit([](auto& client) noexcept {client.request_stop();});
                }
            }
            [[nodiscard]] auto idle() const noexcept -> bool {return !active_;}
            [[nodiscard]] auto obsolete() const noexcept -> bool {
                return idle() && (stopped_ || !visit([](auto const& client){return client.reusable_http();}));
            }
            [[nodiscard]] auto accepts(std::uint16_t port) const noexcept -> bool {
                return port==port_ && !stopped_ && active_<4 &&
                    visit([](auto const& client){return client.can_submit_http();});
            }
            auto ready(Clock::time_point deadline) -> nex::capy::task<bool> {
                if (stopped_) co_return false;
                Registration use(*this);
                co_return co_await visit([deadline](auto& client){return client.wait_http_ready(deadline);});
            }
            [[nodiscard]] auto retryable(Clock::time_point deadline) const noexcept -> bool {
                return visit([deadline](auto const& client){return client.retryable_http_handshake(deadline);});
            }
            auto request(Transfer transfer) -> nex::capy::task<TransferResult> {
                if (stopped_) co_return std::unexpected("HTTP/3 connection closed");
                Registration use(*this);
                auto observe=transfer.headers ? std::optional<masque::HttpHeaderSink>{*transfer.headers} : std::nullopt;
                auto response=co_await visit([&](auto& client) {
                    return client.get_response(transfer.target,transfer.maximum,transfer.deadline,transfer.extra_fields,
                        transfer.policy.conditional,transfer.policy.redirect,masque::HttpBodySink{transfer.sink},observe);
                });
                auto stop=co_await nex::capy::this_coro::stop_token;
                if (!response || stop.stop_requested() || Clock::now()>=transfer.deadline)
                    co_return std::unexpected("HTTP/3 response is incomplete, unsupported or exceeds its limit");
                co_return response->status;
            }
        };
    }

    struct Http3Pool::Impl {
        std::array<std::shared_ptr<Connection>,2> connections;
        std::shared_ptr<masque::HttpTicketCache> tickets;

        Impl() {
            if constexpr (masque::http_ticket_recovery) tickets=std::make_shared<masque::HttpTicketCache>();
        }

        auto stop() noexcept -> void {
            for (auto& owner:connections) {
                if (!owner) continue;
                owner->stop();
                owner.reset();
            }
        }
        auto find(std::uint16_t port) -> std::shared_ptr<Connection> {
            for (auto& owner:connections) {
                if (owner && owner->obsolete()) {
                    owner->stop();
                    owner.reset();
                }
            }
            auto match=std::ranges::find_if(connections,[port](auto const& owner) {
                return owner && owner->accepts(port);
            });
            return match==connections.end() ? nullptr : *match;
        }

        auto exchange(std::shared_ptr<Connection> owner,Http3Dial dial,Clock::time_point connect_by,Transfer transfer)
            -> nex::capy::task<Attempt> {
            owner->launch(dial.context,owner);
            struct Guard {
                Connection& connection;
                bool retained=false;
                ~Guard(){if (!retained) connection.stop();}
            } guard{*owner};
            if (!co_await owner->ready(connect_by)) {
                auto stop=co_await nex::capy::this_coro::stop_token;
                co_return Attempt{std::unexpected("HTTP/3 handshake failed"),
                    !stop.stop_requested() && owner->retryable(connect_by)};
            }
            auto slot=std::ranges::find_if(connections,[](auto const& entry){return !entry || entry->idle();});
            if (slot==connections.end())
                co_return Attempt{std::unexpected("HTTP/3 connection pool is full")};
            if (*slot) (*slot)->stop();
            *slot=owner;
            guard.retained=true;
            co_return Attempt{co_await owner->request(transfer)};
        }

        auto through_proxy(hysteria2::TransportOptions options,Http3Dial dial,std::unique_ptr<Http3Tunnel> route,
            nex::corosio::endpoint peer,quic::EchConfig const* ech,Clock::time_point connect_by,Transfer transfer)
            -> nex::capy::task<Attempt> {
            auto& tunnel=*route->tunnel;
            auto stop=co_await nex::capy::this_coro::stop_token;
            auto until=tunnel.connection_deadline(connect_by);
            auto carrier=std::make_unique<Routed>(dial,transfer.authority,options,tickets,std::move(route));
            {
                std::stop_callback cancellation(stop,[&tunnel] noexcept {tunnel.cancel();});
                if (stop.stop_requested()) co_return Attempt{std::unexpected("HTTP/3 outbound canceled")};
                auto connected=co_await tunnel.connect_until(net::packet_peer_address(peer),until);
                if (connected!=proxy::PacketConnectResult::connected)
                    co_return Attempt{std::unexpected("HTTP/3 outbound packet connection failed"),
                        connected==proxy::PacketConnectResult::retryable || connected==proxy::PacketConnectResult::timeout};
                if (!carrier->client.socket().attach(tunnel,tunnel.transport(),peer))
                    co_return Attempt{std::unexpected("HTTP/3 outbound packet peer is invalid")};
                if (!co_await carrier->client.socket().prepare(until))
                    co_return Attempt{std::unexpected("HTTP/3 outbound packet setup failed")};
            }
            if (stop.stop_requested()) co_return Attempt{std::unexpected("HTTP/3 outbound canceled")};
            auto started=carrier->client.start(peer,nullptr,ech,{},connect_by);
            if (!started) co_return Attempt{std::unexpected(std::move(started.error())),Clock::now()>=connect_by};
            co_return co_await exchange(std::make_shared<Connection>(dial.port,std::move(carrier)),dial,connect_by,transfer);
        }

        auto request(Http3Resolver resolver,Http3Dial dial,Http3TunnelFactory make_tunnel,Transfer transfer)
            -> nex::capy::task<TransferResult> {
            if (auto owner=find(dial.port)) co_return co_await owner->request(transfer);
            auto initial_tunnel=make_tunnel ? make_tunnel() : nullptr;
            if (make_tunnel && !initial_tunnel)
                co_return std::unexpected("HTTP/3 outbound does not support datagrams");
            std::optional<quic::EchConfig> ech;
            if (!dial.ech_file.empty()) {
                auto parsed=quic::read_ech_config(dial.ech_file);
                if (!parsed) co_return std::unexpected(std::move(parsed.error()));
                if (parsed->public_name==dial.tls.profile().server_name)
                    co_return std::unexpected("ECH public name matches the origin");
                ech.emplace(std::move(*parsed));
            }
            auto endpoints=co_await resolver(dial.connect_deadline);
            if (!endpoints || Clock::now()>=dial.connect_deadline) co_return std::unexpected("HTTP/3 resolution failed");
            auto stop=co_await nex::capy::this_coro::stop_token;
            TransferResult last=std::unexpected("HTTP/3 connection could not start");
            for (std::size_t index=0;index<endpoints->size();++index) {
                using namespace std::chrono_literals;
                auto now=Clock::now();
                if (stop.stop_requested() || now>=dial.connect_deadline) break;
                auto connect_by=dial.connect_deadline;
                if (index+1<endpoints->size() && connect_by-now>200ms)
                    connect_by=now+std::min((connect_by-now)/2,Clock::duration(500ms));
                hysteria2::TransportOptions options{
                    .handshake_timeout=std::chrono::ceil<std::chrono::milliseconds>(connect_by-now),
                    .idle_timeout=std::max(30000ms,std::chrono::ceil<std::chrono::milliseconds>(transfer.deadline-now)),
                    .max_udp_payload_size=dial.max_udp_payload,.disable_path_mtu_discovery=dial.disable_pmtu
                };
                auto* ech_config=ech ? &*ech : nullptr;
                auto const& endpoint=(*endpoints)[index];
                if (make_tunnel) {
                    auto tunnel=index==0 ? std::move(initial_tunnel) : make_tunnel();
                    if (!tunnel) co_return std::unexpected("HTTP/3 outbound does not support datagrams");
                    auto attempt=co_await through_proxy(options,dial,std::move(tunnel),endpoint,ech_config,connect_by,transfer);
                    last=std::move(attempt.result);
                    if (!attempt.retry) break;
                    continue;
                }
                auto interfaces=dial.binding.network ? (*dial.binding.network)(endpoint.is_v6()) :
                    platform::network::InterfaceCandidates{};
                if (!dial.binding.network) interfaces.indices.push_back(dial.binding.interface_index);
                if (interfaces.indices.empty()) {
                    last=std::unexpected("no eligible network interface for HTTP/3 egress");
                    continue;
                }
                auto selected=dial.binding;
                selected.network.reset();
                for (std::size_t path=0;path<interfaces.indices.size();++path) {
                    auto now=Clock::now();
                    if (stop.stop_requested() || now>=connect_by) break;
                    auto path_deadline=path+1<interfaces.indices.size() ?
                        std::min(connect_by,now+interfaces.fallback_delay) : connect_by;
                    selected.interface_index=interfaces.indices[path];
                    auto carrier=std::make_unique<Direct>(dial,transfer.authority,options,tickets);
                    std::error_code socket_error;
                    auto started=carrier->client.start(endpoint,&selected,ech_config,{},path_deadline,&socket_error);
                    if (!started) {
                        last=std::unexpected(std::move(started.error()));
                        if (dial.binding.network && !platform::network::retry_interface_error(socket_error)) co_return last;
                        continue;
                    }
                    auto owner=std::make_shared<Connection>(dial.port,std::move(carrier));
                    auto attempt=co_await exchange(std::move(owner),dial,path_deadline,transfer);
                    last=std::move(attempt.result);
                    if (!attempt.retry) co_return last;
                }
            }
            co_return last;
        }
    };

    Http3Pool::Http3Pool()=default;
    Http3Pool::~Http3Pool(){stop();}
    auto Http3Pool::stop() noexcept -> void {if (impl_) impl_->stop();}
    auto Http3Pool::request(Http3Resolver resolver,Http3Dial dial,Http3TunnelFactory tunnel,Transfer transfer)
        -> nex::capy::task<TransferResult> {
        if (!impl_) impl_=std::make_unique<Impl>();
        co_return co_await impl_->request(std::move(resolver),dial,std::move(tunnel),transfer);
    }
}
