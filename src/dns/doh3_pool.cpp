module dns.doh3_pool;
import std;
import dns.corosio_query;
import dns.doh_exchange;
import dns.input_budget;
import dns.quic_query;
import dns.response_match;
import hysteria2.transport_options;
import masque.client_session;
import platform.socket_options;
import capy;
import corosio;
import tls.profiles;

namespace dns {
    namespace {
        namespace doh=doh_detail;
        using doh::Clock;
        using doh::Error;
        using doh::Io;
        using doh::Endpoint;
        namespace capy=doh::capy;

        class RoutedSocket {
            Io& io_;
            dns::QuicDnsDatagram lower_;
        public:
            explicit RoutedSocket(Io& io):io_(io) {}
            auto context() noexcept -> Io& {return io_;}
            auto open(dns::QuicDnsDatagramFactory const& factory,Endpoint peer,Clock::time_point deadline)
                -> capy::task<bool> {
                lower_=factory(io_);
                if (!lower_) co_return false;
                co_return co_await lower_->prepare(peer,deadline);
            }
            auto local_endpoint() const noexcept -> Endpoint {return lower_->local_endpoint();}
            auto close() noexcept -> void {if (lower_) lower_->close();}
            auto send_to(capy::const_buffer buffer,Endpoint peer) {return lower_->send_to(buffer,peer);}
            auto recv_from(capy::mutable_buffer buffer,Endpoint& peer) {return lower_->recv_from(buffer,peer);}
        };

        struct Https3Profile {
            tls::ClientProfile identity;
            std::string path;
            platform::SocketBinding binding;
            std::chrono::milliseconds connect_timeout;
            QuicDnsDatagramFactory route;
        };

        template<class Socket>
        struct Carrier {
            masque::ClientProfile tls;
            masque::Client<Socket> client;

            Carrier(Io& io,Https3Profile const& profile,Endpoint endpoint)
                :tls(masque::ClientProfile::for_http(profile.identity,
                     endpoint.port()==443 ? profile.identity.server_name :
                     profile.identity.server_name+':'+std::to_string(endpoint.port()),
                     hysteria2::TransportOptions{
                         .handshake_timeout=profile.connect_timeout,
                         .max_udp_payload_size=profile.route ? std::optional<std::size_t>{1200} : std::nullopt,
                         .disable_path_mtu_discovery=bool(profile.route)})),
                 client(io,tls) {}
        };

        using Physical=Carrier<corosio::udp_socket>;
        using Routed=Carrier<RoutedSocket>;

        enum class Handshake { ready, try_interface, failed };

        class Https3Connection {
            std::shared_ptr<Https3Profile const> profile_;
            Endpoint peer_;
            std::uint32_t interface_index_;
            std::variant<std::unique_ptr<Physical>,std::unique_ptr<Routed>> carrier_;
            Clock::time_point last_used_=Clock::now();
            std::size_t active_=0;
            bool started_=false,stopped_=false,joined_=false,finished_=false;

            template<class Operation>
            auto apply(Operation&& operation) const -> decltype(auto) {
                return std::visit([&](auto const& carrier) -> decltype(auto) {
                    return operation(carrier->client);
                },carrier_);
            }

            auto finish_if_idle() noexcept -> void {
                if (joined_ && !active_ && !std::exchange(finished_,true))
                    apply([](auto& client) noexcept {client.finish();});
            }

            struct Registration {
                Https3Connection& connection;
                explicit Registration(Https3Connection& owner):connection(owner) {++owner.active_;}
                ~Registration() {
                    --connection.active_;
                    connection.last_used_=Clock::now();
                    connection.finish_if_idle();
                }
            };

        public:
            Https3Connection(Io& io,std::shared_ptr<Https3Profile const> profile,Endpoint peer,std::uint32_t interface_index)
                :profile_(std::move(profile)),peer_(peer),interface_index_(interface_index) {
                if (profile_->route) carrier_=std::make_unique<Routed>(io,*profile_,peer);
                else carrier_=std::make_unique<Physical>(io,*profile_,peer);
            }

            ~Https3Connection() {
                if (!finished_) apply([](auto& client) noexcept {client.finish();});
            }

            auto stop() noexcept -> void {
                if (!std::exchange(stopped_,true)) apply([](auto& client) noexcept {client.request_stop();});
            }

            [[nodiscard]] auto idle() const noexcept -> bool {return !active_;}
            [[nodiscard]] auto evict(Clock::time_point now) const noexcept -> bool {
                return idle() && (stopped_ || now-last_used_>=std::chrono::seconds(15) ||
                    (started_ && !apply([](auto const& client) {return client.reusable_http();})));
            }
            [[nodiscard]] auto accepts(Https3Profile const& profile,Endpoint peer,std::span<std::uint32_t const> interfaces) const noexcept -> bool {
                if (!started_ || stopped_ || &profile!=profile_.get() || peer!=peer_ || active_>=4 ||
                    !std::ranges::contains(interfaces,interface_index_)) return false;
                return apply([](auto const& client) {return client.can_submit_http();});
            }

            auto start(Io& io,std::shared_ptr<Https3Connection> owner,platform::SocketBinding const& binding,
                Clock::time_point until,std::stop_token stop) -> capy::task<Handshake> {
                Registration pending(*this);
                if (profile_->route) {
                    auto& client=std::get<std::unique_ptr<Routed>>(carrier_)->client;
                    auto& socket=client.socket();
                    std::stop_callback cancel(stop,[&socket] noexcept {socket.close();});
                    if (stop.stop_requested() || stopped_) co_return Handshake::failed;
                    auto prepared=co_await socket.open(profile_->route,peer_,until);
                    if (!prepared || stopped_ || stop.stop_requested()) co_return Handshake::failed;
                    if (!client.start(peer_,nullptr,nullptr,{},until)) co_return Handshake::failed;
                } else {
                    auto& client=std::get<std::unique_ptr<Physical>>(carrier_)->client;
                    std::error_code socket_error;
                    if (!client.start(peer_,&binding,nullptr,{},until,&socket_error))
                        co_return platform::network::retry_interface_error(socket_error) ?
                            Handshake::try_interface : Handshake::failed;
                }
                auto joined=[owner] noexcept {
                    owner->joined_=true;
                    owner->stop();
                    owner->finish_if_idle();
                };
                auto run=apply([](auto& client) {return client.run();});
                capy::run_async(io.get_executor(),[joined](auto) noexcept {joined();},
                    [joined](std::exception_ptr) noexcept {joined();})(std::move(run));
                started_=true;
                if (co_await apply([until,stop](auto& client) {return client.wait_http_ready(until,stop);}))
                    co_return Handshake::ready;
                co_return apply([until](auto const& client) {return client.retryable_http_handshake(until);}) ?
                    Handshake::try_interface : Handshake::failed;
            }

            auto request(std::span<std::uint8_t const> message,Clock::time_point deadline,std::stop_token stop)
                -> capy::task<std::expected<masque::HttpResponse,masque::HttpError>> {
                if (stopped_) co_return std::unexpected(masque::HttpError::transport);
                Registration use(*this);
                co_return co_await apply([&](auto& client) {
                    return client.post(profile_->path,{doh::media_type,message},doh::max_message,deadline,stop);
                });
            }
        };

        class Https3Pool final : public capy::execution_context::service {
            static constexpr std::size_t capacity=16;
            std::vector<std::shared_ptr<Https3Connection>> connections_;
            bool stopped_=false;
            auto shutdown() noexcept -> void override {stop();}

        public:
            explicit Https3Pool(capy::execution_context&) {}

            auto stop() noexcept -> void {
                stopped_=true;
                for (auto const& owner:connections_) owner->stop();
                connections_.clear();
            }
            auto resume() noexcept -> void {stopped_=false;}
            [[nodiscard]] auto stopped() const noexcept -> bool {return stopped_;}
            auto reap(Clock::time_point now) noexcept -> void {
                std::erase_if(connections_,[now](auto const& owner) {
                    if (!owner->evict(now)) return false;
                    owner->stop();
                    return true;
                });
            }
            [[nodiscard]] auto find(Https3Profile const& profile,Endpoint peer,std::span<std::uint32_t const> interfaces) const
                -> std::shared_ptr<Https3Connection> {
                auto found=std::ranges::find_if(connections_,[&](auto const& owner) {return owner->accepts(profile,peer,interfaces);});
                return found==connections_.end() ? nullptr : *found;
            }
            auto open(Io& io,std::shared_ptr<Https3Profile const> profile,Endpoint endpoint,std::uint32_t interface_index)
                -> std::shared_ptr<Https3Connection> {
                if (connections_.size()==capacity) {
                    auto idle=std::ranges::find_if(connections_,[](auto const& owner) {return owner->idle();});
                    if (idle==connections_.end()) return {};
                    (*idle)->stop();
                    connections_.erase(idle);
                }
                auto owner=std::make_shared<Https3Connection>(io,std::move(profile),endpoint,interface_index);
                connections_.push_back(owner);
                return owner;
            }
        };

        struct Https3Query {
            std::shared_ptr<Https3Profile const> profile;

            auto connect(Https3Pool& pool,Io& io,Endpoint peer,Clock::time_point deadline,
                platform::network::InterfaceCandidates const& interfaces,std::stop_token stop) const
                -> capy::task<std::expected<std::shared_ptr<Https3Connection>,Error>> {
                auto binding=profile->binding;
                binding.network.reset();
                for (std::size_t index=0;index<interfaces.indices.size();++index) {
                    auto now=Clock::now();
                    if (pool.stopped() || stop.stop_requested()) co_return std::unexpected(Error::canceled);
                    if (now>=deadline) co_return std::unexpected(Error::timeout);
                    auto until=index+1<interfaces.indices.size() ?
                        std::min(deadline,now+interfaces.fallback_delay) : deadline;
                    binding.interface_index=interfaces.indices[index];
                    pool.reap(now);
                    auto connection=pool.open(io,profile,peer,binding.interface_index);
                    if (!connection) co_return std::unexpected(Error::budget_exhausted);
                    struct Guard {
                        Https3Connection& connection;
                        bool ready=false;
                        ~Guard(){if (!ready) connection.stop();}
                    } guard{*connection};
                    auto result=co_await connection->start(io,connection,binding,until,stop);
                    if (pool.stopped() || stop.stop_requested()) co_return std::unexpected(Error::canceled);
                    if (result==Handshake::ready) {
                        guard.ready=true;
                        co_return std::move(connection);
                    }
                    if (result==Handshake::failed) co_return std::unexpected(profile->binding.network && !profile->route ? Error::protocol : Error::transport);
                }
                co_return std::unexpected(Clock::now()>=deadline ? Error::timeout : Error::transport);
            }

            auto operator()(Io& io,Endpoint peer,dns::QueryMessage const& query,std::uint16_t id,Clock::time_point deadline,
                dns::InputBudget& budget,std::stop_token stop) const -> capy::task<std::expected<dns::Response,Error>> {
                auto error=[&] {
                    return stop.stop_requested() ? Error::canceled : Clock::now()>=deadline ? Error::timeout : Error::transport;
                };
                auto now=Clock::now();
                if (now>=deadline || stop.stop_requested()) co_return std::unexpected(error());
                auto request=doh::make_query_wire(query);
                if (!request) co_return std::unexpected(request.error());
                auto lease=budget.acquire(doh::max_message);
                if (!lease) co_return std::unexpected(Error::budget_exhausted);
                auto& pool=io.use_service<Https3Pool>();
                if (pool.stopped()) co_return std::unexpected(Error::canceled);
                pool.reap(now);
                platform::network::InterfaceCandidates interfaces;
                if (!profile->route && profile->binding.network)
                    interfaces=(*profile->binding.network)(peer.is_v6());
                else interfaces.indices.push_back(profile->binding.interface_index);
                auto connection=pool.find(*profile,peer,interfaces.indices);
                if (!connection) {
                    auto connected=co_await connect(pool,io,peer,std::min(deadline,now+profile->connect_timeout),interfaces,stop);
                    if (!connected) co_return std::unexpected(connected.error());
                    connection=std::move(*connected);
                }
                auto result=co_await connection->request(*request,deadline,stop);
                if (stop.stop_requested() || Clock::now()>=deadline) co_return std::unexpected(error());
                if (!result) co_return std::unexpected(
                    result.error()==masque::HttpError::response ? Error::protocol : Error::transport);
                doh::detail::Body metadata(budget);
                for (auto const& [name,value]:result->fields)
                    if (!metadata.field(name,value)) co_return std::unexpected(Error::protocol);
                if (!metadata.content_type || result->body.size()<12 ||
                    (metadata.length && *metadata.length!=result->body.size()))
                    co_return std::unexpected(Error::protocol);
                auto bytes=std::span(reinterpret_cast<std::uint8_t const*>(result->body.data()),result->body.size());
                auto response=dns::parse_response(bytes,0,query.question);
                if (!response)
                    co_return std::unexpected(response.error()==dns::MessageError::truncated ? Error::truncated : Error::protocol);
                if (!dns::age_response(*response,metadata.age.value_or(0),id)) co_return std::unexpected(Error::protocol);
                co_return std::move(*response);
            }
        };
    }

    auto make_https3_query(std::string_view server_name,std::string_view ca_file,std::string_view path,
        platform::SocketBinding binding,std::optional<std::chrono::milliseconds> timeout,QuicDnsDatagramFactory route)
        -> std::expected<detail::ProtectedQuery,std::string> {
        if (!doh::valid_path(path)) return std::unexpected("invalid DoH request path");
        auto profile=tls::ClientProfile::load(server_name,ca_file);
        if (!profile) return std::unexpected(std::move(profile.error()));
        return detail::ProtectedQuery{Https3Query{std::make_shared<Https3Profile const>(
            Https3Profile{std::move(*profile),std::string(path),std::move(binding),
                timeout.value_or(std::chrono::seconds(5)),std::move(route)})}};
    }

    auto stop_https3_queries(Io& context) noexcept -> void {
        if (auto* pool=context.find_service<Https3Pool>()) pool->stop();
    }
    auto resume_https3_queries(Io& context) noexcept -> void {
        if (auto* pool=context.find_service<Https3Pool>()) pool->resume();
    }
    auto reap_idle_https3_queries(Io& context,Clock::time_point now) noexcept -> void {
        if (auto* pool=context.find_service<Https3Pool>()) pool->reap(now);
    }
}
