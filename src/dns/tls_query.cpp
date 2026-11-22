module dns.tls_query;
import std;
import proxy.v4;
import dns.corosio_query;
import dns.input_budget;
import platform.socket_options;
import tls.byte_stream;
import tls.connector;
import tls.profiles;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace dns {
    namespace dot_detail {
        using Clock=std::chrono::steady_clock;
        using Error=detail::UdpError;
        using Io=nex::corosio::io_context;
        using Endpoint=nex::corosio::endpoint;
        namespace capy=nex::capy;
        using namespace std::chrono_literals;

        struct FixedResolver {
            Endpoint endpoint;
            auto cancel() noexcept -> void {}
            auto operator()(Clock::time_point) const -> capy::task<std::optional<std::vector<Endpoint>>> {
                co_return std::vector{endpoint};
            }
        };
        class FastOpenStream {
            using Connector=tls::detail::FastOpenPhysicalConnector<FixedResolver,tls::ClientProfile>;
            Connector connector_;
            std::optional<tls::detail::ByteStream<Connector::Socket>> stream_;
        public:
            FastOpenStream(Io& context,Endpoint endpoint,tls::ClientProfile const& profile,platform::TcpSocketOptions const& options)
                :connector_(context,FixedResolver{endpoint},profile,options) {}

            auto start(Clock::time_point deadline) -> capy::task<bool> {
                if (co_await connector_.start(deadline)!=tls::detail::ConnectResult::connected) co_return false;
                stream_.emplace(*connector_.application());
                co_return true;
            }
            auto read(std::span<std::uint8_t> bytes) -> capy::task<std::size_t> {
                auto result=co_await stream_->read(bytes);
                co_return result.value_or(0);
            }
            auto send(std::span<std::uint8_t const> bytes,Clock::time_point deadline) -> capy::task<bool> {
                return stream_->send(bytes,deadline);
            }
            auto cancel() noexcept -> void {connector_.cancel();}
        };

        struct Physical {
            tls::ClientProfile tls;
            platform::TcpSocketOptions socket;
        };
        struct TlsProfile {
            std::variant<Physical,TlsDnsStreamFactory> transport;
            std::chrono::milliseconds connect_timeout;
        };
        struct Frame {
            Bytes bytes;
            InputBudget::Lease lease;
        };
        struct Request {
            capy::async_event wake;
            Bytes outgoing;
            Clock::time_point deadline;
            std::uint16_t id=0;
            bool submitted=false;
            std::optional<std::expected<Frame,Error>> result;

            Request(Bytes bytes,Clock::time_point until):outgoing(std::move(bytes)),deadline(until) {}
        };

        // One serialized executor owns the connection and request registry.
        // Each transaction ID is used once per connection, including canceled
        // queries, so a delayed response cannot be delivered to a newer query.
        class TlsConnection {
            using Connector=tls::detail::PhysicalConnector<FixedResolver,tls::ClientProfile>;
            using Stream=tls::detail::ByteStream<Connector::Socket>;
            static constexpr std::size_t max_requests=32, max_transactions=4096;

            std::shared_ptr<TlsProfile const> profile_;
            Endpoint endpoint_;
            Io& context_;
            std::optional<Connector> connector_;
            std::optional<Stream> stream_;
            TlsDnsStream routed_;
            std::map<std::uint16_t,std::shared_ptr<Request>> pending_;
            std::deque<std::shared_ptr<Request>> writes_;
            std::bitset<65536> used_;
            std::size_t transactions_=0;
            capy::async_event writer_changed_;
            Clock::time_point idle_since_{};
            bool started_=false, quiescing_=false, closed_=false, served_=false;

            auto fill(std::span<std::uint8_t> bytes) -> capy::task<bool> {
                while (!bytes.empty()) {
                    auto size=std::size_t{0};
                    if (routed_) size=co_await routed_->read(bytes);
                    else if (auto result=co_await stream_->read(bytes)) size=*result;
                    if (!size) co_return false;
                    bytes=bytes.subspan(size);
                }
                co_return true;
            }
            auto read_responses() -> capy::task<capy::results<>> {
                while (!closed_ && !quiescing_ && !pending_.empty()) {
                    std::array<std::uint8_t,2> length;
                    if (!co_await fill(length)) {close(Error::transport); break;}
                    auto size=(std::size_t(length[0])<<8)|length[1];
                    if (size<12) {close(Error::protocol); break;}
                    auto lease=default_upstream_receive_budget().acquire(size);
                    if (!lease) {close(Error::budget_exhausted); break;}
                    Bytes bytes(size);
                    if (!co_await fill(bytes)) {close(Error::transport); break;}
                    auto id=static_cast<std::uint16_t>((unsigned(bytes[0])<<8)|bytes[1]);
                    auto it=pending_.find(id);
                    if (!used_.test(id) || (it!=pending_.end() && !it->second->submitted)) {
                        close(Error::protocol);
                        break;
                    }
                    if (it==pending_.end()) continue;
                    auto request=std::move(it->second);
                    pending_.erase(it);
                    served_=true;
                    if (pending_.empty()) {
                        quiescing_=true;
                        writer_changed_.set();
                    }
                    request->result.emplace(Frame{std::move(bytes),std::move(*lease)});
                    request->wake.set();
                }
                co_return capy::results<>{};
            }
            auto write_requests() -> capy::task<capy::results<>> {
                while (!closed_ && !quiescing_) {
                    if (writes_.empty()) {
                        writer_changed_.clear();
                        auto [error]=co_await writer_changed_.wait();
                        if (error) {close(Error::canceled); break;}
                        continue;
                    }
                    auto request=std::move(writes_.front());
                    writes_.pop_front();
                    if (Clock::now()>=request->deadline) continue;
                    request->submitted=true;
                    auto bytes=std::move(request->outgoing);
                    // Once writing starts, frame integrity belongs to the
                    // connection. A waiter's timeout cannot interrupt it.
                    auto deadline=Clock::now()+5s;
                    auto sent=routed_ ? co_await routed_->send(bytes,deadline) : co_await stream_->send(bytes,deadline);
                    if (!sent) {
                        close(Error::transport);
                        break;
                    }
                }
                co_return capy::results<>{};
            }
            auto run() -> capy::task<> {
                if (closed_) co_return;
                if (!stream_ && !routed_ && !co_await connect(Clock::now()+profile_->connect_timeout)) {
                    close(Error::transport);
                    co_return;
                }
                (void)co_await capy::when_all(read_responses(),write_requests());
            }

            auto connect(Clock::time_point deadline) -> capy::task<bool> {
                if (auto const* factory=std::get_if<TlsDnsStreamFactory>(&profile_->transport)) {
                    routed_=(*factory)(context_,endpoint_);
                    co_return routed_ && co_await routed_->start(deadline) && !closed_;
                }
                auto const& physical=std::get<Physical>(profile_->transport);
                connector_.emplace(context_,FixedResolver{endpoint_},physical.tls,physical.socket);
                if (co_await connector_->start(deadline)!=tls::detail::ConnectResult::connected || closed_)
                    co_return false;
                stream_.emplace(*connector_->application());
                co_return true;
            }

        public:
            TlsConnection(Io& context,std::shared_ptr<TlsProfile const> profile,Endpoint endpoint)
                :profile_(std::move(profile)),endpoint_(endpoint),context_(context) {}

            [[nodiscard]] auto idle() const noexcept -> bool {return !started_;}
            [[nodiscard]] auto reusable() const noexcept -> bool {return served_;}
            [[nodiscard]] auto evict(Clock::time_point now) const noexcept -> bool {
                return idle() && (closed_ || transactions_>=max_transactions || now>=idle_since_+15s);
            }
            [[nodiscard]] auto accepts(TlsProfile const& profile,Endpoint endpoint) const noexcept -> bool {
                return &profile==profile_.get() && endpoint==endpoint_ && !closed_ &&
                    pending_.size()<max_requests && writes_.size()<max_requests && transactions_<max_transactions;
            }
            auto close(Error error) noexcept -> void {
                if (std::exchange(closed_,true)) return;
                if (connector_) connector_->cancel();
                if (routed_) {
                    routed_->cancel();
                    if (!started_) routed_={};
                }
                writes_.clear();
                auto pending=std::move(pending_);
                writer_changed_.set();
                for (auto const& [id,request]:pending) {
                    request->result.emplace(std::unexpected(error));
                    request->wake.set();
                }
            }
            auto leave(std::shared_ptr<Request> const& request) noexcept -> void {
                if (!pending_.erase(request->id)) return;
                std::erase(writes_,request);
                if (pending_.empty()) close(Error::canceled);
            }
            auto submit(std::shared_ptr<Request> const& request,std::uint16_t id) -> void {
                while (used_.test(id)) ++id;
                request->id=id;
                request->outgoing[2]=static_cast<std::uint8_t>(id>>8);
                request->outgoing[3]=static_cast<std::uint8_t>(id);
                writes_.push_back(request);
                try {pending_.emplace(id,request);}
                catch (...) { writes_.pop_back(); throw; }
                used_.set(id);
                ++transactions_;
                writer_changed_.set();
            }
            auto start(Io& context,std::shared_ptr<TlsConnection> self) -> void {
                if (std::exchange(started_,true)) return;
                try {
                    capy::run_async(context.get_executor(),[self,&context] {
                        self->idle_since_=Clock::now();
                        self->quiescing_=false;
                        self->started_=false;
                        if (self->closed_) self->routed_={};
                        else if (!self->pending_.empty()) self->start(context,self);
                    },[self](std::exception_ptr) noexcept {
                        self->started_=false;
                        self->close(Error::transport);
                        self->routed_={};
                    })(run());
                } catch (...) {
                    started_=false;
                    close(Error::transport);
                    throw;
                }
            }
        };

        // Corosio owns the pool and shuts it down while its socket services
        // are still alive. Per-generation profile identities never share TLS
        // connections even when the new endpoint and credentials are equal.
        class TlsPool final : public capy::execution_context::service {
            std::vector<std::shared_ptr<TlsConnection>> connections_;
            bool stopped_=false;
            auto shutdown() noexcept -> void override {stop();}

        public:
            explicit TlsPool(capy::execution_context&) {}
            auto stop() noexcept -> void {
                stopped_=true;
                for (auto const& connection:connections_) connection->close(Error::canceled);
                connections_.clear();
            }
            auto resume() noexcept -> void {stopped_=false;}
            auto reap(Clock::time_point now) noexcept -> void {
                std::erase_if(connections_,[now](auto const& connection) {return connection->evict(now);});
            }
            auto acquire(Io& context,std::shared_ptr<TlsProfile const> const& profile,Endpoint endpoint)
                -> std::shared_ptr<TlsConnection> {
                if (stopped_) return {};
                reap(Clock::now());
                auto existing=std::ranges::find_if(connections_,[&](auto const& connection) {
                    return connection->accepts(*profile,endpoint);
                });
                if (existing!=connections_.end()) return *existing;
                constexpr std::size_t capacity=32;
                if (connections_.size()==capacity) {
                    auto idle=std::ranges::find_if(connections_,[](auto const& connection) {return connection->idle();});
                    if (idle==connections_.end()) return {};
                    connections_.erase(idle);
                }
                auto connection=std::make_shared<TlsConnection>(context,profile,endpoint);
                connections_.push_back(connection);
                return connection;
            }
        };

        struct TlsQuery {
            std::shared_ptr<TlsProfile const> profile;

            auto operator()(Io& context,Endpoint endpoint,QueryMessage const& query,std::uint16_t id,
                Clock::time_point deadline,InputBudget& budget,std::stop_token stop) const
                -> capy::task<std::expected<Response,Error>> {
                auto& pool=context.use_service<TlsPool>();
                for (bool retried=false;;retried=true) {
                    if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
                    if (Clock::now()>=deadline) co_return std::unexpected(Error::timeout);
                    auto encoded=encode_query(query);
                    if (!encoded || encoded->size()>65535) co_return std::unexpected(Error::invalid_query);
                    Bytes frame{static_cast<std::uint8_t>(encoded->size()>>8),static_cast<std::uint8_t>(encoded->size())};
                    frame.insert(frame.end(),encoded->begin(),encoded->end());
                    auto connection=pool.acquire(context,profile,endpoint);
                    if (!connection) co_return std::unexpected(Error::budget_exhausted);
                    bool retryable=connection->reusable();
                    auto request=std::make_shared<Request>(std::move(frame),deadline);
                    connection->submit(request,id);
                    struct Registration {
                        TlsConnection& connection;
                        std::shared_ptr<Request> const& request;
                        ~Registration() {connection.leave(request);}
                    } registration{*connection,request};
                    std::stop_callback cancellation(stop,[&request]() noexcept {request->wake.set();});
                    connection->start(context,connection);
                    auto [error]=co_await nex::corosio::timeout(request->wake.wait(),deadline);
                    if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
                    if (Clock::now()>=deadline || capy::is_timeout(error)) co_return std::unexpected(Error::timeout);
                    if (error) co_return std::unexpected(Error::canceled);
                    if (!request->result) co_return std::unexpected(Error::transport);
                    auto& result=*request->result;
                    if (!result) {
                        if (retryable && !retried && result.error()==Error::transport) continue;
                        co_return std::unexpected(result.error());
                    }
                    std::optional<InputBudget::Lease> lease;
                    if (&budget!=&default_upstream_receive_budget()) {
                        lease=budget.acquire(result->bytes.size());
                        if (!lease) co_return std::unexpected(Error::budget_exhausted);
                    }
                    auto response=parse_owned_response(std::move(result->bytes),request->id,query.question);
                    if (!response)
                        co_return std::unexpected(response.error()==MessageError::truncated ? Error::truncated : Error::protocol);
                    response->wire[0]=static_cast<std::uint8_t>(id>>8);
                    response->wire[1]=static_cast<std::uint8_t>(id);
                    co_return std::move(*response);
                }
            }
        };
    }

    auto stop_tls_queries(nex::corosio::io_context& context) noexcept -> void {
        if (auto* pool=context.find_service<dot_detail::TlsPool>()) pool->stop();
    }
    auto resume_tls_queries(nex::corosio::io_context& context) noexcept -> void {
        if (auto* pool=context.find_service<dot_detail::TlsPool>()) pool->resume();
    }

    auto reap_idle_tls_queries(nex::corosio::io_context& context,std::chrono::steady_clock::time_point now) noexcept -> void {
        if (auto* pool=context.find_service<dot_detail::TlsPool>()) pool->reap(now);
    }

    auto make_tls_query(std::string_view server_name,std::string_view ca_file,platform::TcpSocketOptions options,
        std::chrono::milliseconds connect_timeout)
        -> std::expected<detail::ProtectedQuery,std::string> {
        auto profile=tls::ClientProfile::load(server_name,ca_file,0x001d,false,{});
        if (!profile) return std::unexpected(std::move(profile.error()));
        if (options.tcp_fast_open.value_or(false)) {
            auto factory=[profile=std::move(*profile),options=std::move(options)](dot_detail::Io& context,dot_detail::Endpoint endpoint)
                -> TlsDnsStream {
                return pro::make_proxy<TlsDnsStreamFacade,dot_detail::FastOpenStream>(context,endpoint,profile,options);
            };
            return make_routed_tls_query(std::move(factory),connect_timeout);
        }
        return detail::ProtectedQuery{dot_detail::TlsQuery{std::make_shared<dot_detail::TlsProfile const>(
            dot_detail::TlsProfile{dot_detail::Physical{std::move(*profile),std::move(options)},connect_timeout})}};
    }

    auto make_routed_tls_query(TlsDnsStreamFactory factory,std::chrono::milliseconds connect_timeout)
        -> std::expected<detail::ProtectedQuery,std::string> {
        if (!factory) return std::unexpected("missing routed DoT stream factory");
        return detail::ProtectedQuery{dot_detail::TlsQuery{std::make_shared<dot_detail::TlsProfile const>(
            dot_detail::TlsProfile{std::move(factory),connect_timeout})}};
    }
}
