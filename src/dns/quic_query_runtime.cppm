// QUIC DoQ pooled connection & query driver module.
export module dns.quic_query_runtime;
import std;
import crypto;
import dns.corosio_query;
import dns.input_budget;
import dns.quic_query;
export import dns.quic_query_app;
import net.datagram_driver;
import net.udp_connect;
import platform.socket_options;
import quic.cid_registry;
import quic.connection;
import quic.datagram_port;
import quic.datagram_session;
import quic.transport_memory;
import tls.fingerprint;
import tls.profiles;
import capy;
import corosio;
import ngtcp2;

export namespace dns::doq_detail {
    using Io = corosio::io_context;
    using Endpoint = corosio::endpoint;
    inline constexpr std::array<std::string_view, 1> alpn{"doq"};

    struct InterfaceAttempt {
        std::uint32_t index;
        Clock::time_point until;
    };

    template<class Profile>
    class Socket {
        Io& context_;
        corosio::udp_socket direct_;
        QuicDnsDatagram layered_;

    public:
        explicit Socket(Io& context) : context_(context), direct_(context) {}
        auto context() noexcept -> Io& { return context_; }
        auto prepare(Profile const& profile, Endpoint peer, Clock::time_point deadline,
            std::optional<InterfaceAttempt> path, std::error_code& bind_error) -> capy::task<bool> {
            if (!profile.datagram) {
                auto const* selected = &profile.binding;
                platform::SocketBinding binding;
                if (path) {
                    binding = profile.binding;
                    binding.network.reset();
                    binding.interface_index = path->index;
                    selected = &binding;
                }
                bind_error = net::prepare_udp_socket(direct_, peer, selected, deadline);
                co_return !bind_error;
            }
            layered_ = profile.datagram(context());
            if (!layered_) co_return false;
            co_return co_await layered_->prepare(peer, deadline);
        }
        auto local_endpoint() const -> Endpoint {
            return layered_ ? layered_->local_endpoint() : direct_.local_endpoint();
        }
        auto close() noexcept -> void {
            if (layered_) layered_->close();
            else direct_.close();
        }
        auto release() noexcept -> void { layered_ = {}; }
        auto send_to(capy::const_buffer bytes, Endpoint peer) -> capy::task<capy::results<std::size_t>> {
            if (layered_) co_return co_await layered_->send_to(bytes, peer);
            auto [error, size] = co_await direct_.send_to(bytes, peer);
            co_return capy::results<std::size_t>{error, size};
        }
        auto recv_from(capy::mutable_buffer bytes, Endpoint& peer) -> capy::task<capy::results<std::size_t>> {
            if (layered_) co_return co_await layered_->recv_from(bytes, peer);
            auto [error, size] = co_await direct_.recv_from(bytes, peer);
            co_return capy::results<std::size_t>{error, size};
        }
    };

    template<class Policy>
    class Connection {
        using Profile = typename Policy::Profile;
        using Tls = typename Policy::Tls;
        using TicketCache = typename Policy::TicketCache;
        using App = Application<Tls, Policy::supports_early_data>;
        using Session = quic::DatagramSession<Tls, App>;
        using Registry = quic::CidRegistry<1, 8>;

        struct Factory {
            using Session = Connection::Session;
            std::optional<Session> session;
            int failure = 0;
            auto admit(n::ngtcp2_pkt_hd const&, Endpoint const&, Clock::time_point) const noexcept -> bool { return false; }
            auto create(quic::SessionHandle, Registry&, std::span<std::uint8_t const>, n::ngtcp2_pkt_hd const&,
                Endpoint const&, Clock::time_point) noexcept -> std::expected<Session*, int> {
                return std::unexpected(n::err_callback_failure);
            }
            auto application_drained(quic::SessionHandle, Session const&) const noexcept -> bool { return true; }
            auto failed(quic::SessionHandle, int error) noexcept -> void { failure = error; }
            auto destroy(quic::SessionHandle, Session&) noexcept -> void { session.reset(); }
        };
        using Port = quic::DatagramPort<Factory, 1, 8, 8, true>;
        using Driver = net::DatagramDriver<Port, Socket<Profile>>;

        std::shared_ptr<Profile const> profile_;
        [[no_unique_address]] TicketCache tickets_;
        Endpoint peer_, local_;
        std::optional<InterfaceAttempt> path_;
        std::error_code bind_error_;
        Socket<Profile> socket_;
        quic::NativeTransportMemory<> memory_{4 * 1024 * 1024};
        std::optional<Tls> tls_;
        std::optional<App> app_;
        Factory factory_;
        Port port_{factory_};
        Driver driver_{socket_, port_};
        std::optional<quic::SessionHandle> owner_;
        bool stopping_ = false, finished_ = false, opened_ = false;

        auto lifetime() -> capy::task<capy::results<>> {
            while (!stopping_ && !driver_.drained()) {
                auto idle = app_->idle_deadline();
                auto now = Clock::now();
                if (!port_.active(*owner_) || app_->poisoned() || (idle && now >= *idle)) {
                    stopping_ = true;
                    if (port_.active(*owner_)) {
                        port_.begin_shutdown();
                        driver_.notify();
                        auto until = now + 100ms;
                        while (!port_.quiescent() && Clock::now() < until && driver_.running()) {
                            auto& changed = driver_.changed();
                            changed.clear();
                            if (port_.quiescent()) break;
                            auto [error] = co_await corosio::timeout(changed.wait(), until);
                            if (error) break;
                        }
                    }
                    driver_.finish();
                    break;
                }
                auto& changed = driver_.changed();
                changed.clear();
                auto work = changed.wait();
                auto [error] = idle ? co_await corosio::timeout(std::move(work), *idle) : co_await std::move(work);
                if (error && !capy::is_timeout(error)) {
                    stop();
                    break;
                }
            }
            co_return capy::results<>{};
        }
        auto run(Clock::time_point prepare_by, Clock::time_point connect_by, bool replayable) -> capy::task<> {
            if (stopping_) co_return;
            auto prepared = co_await socket_.prepare(*profile_, peer_, prepare_by, path_, bind_error_);
            if (!prepared || stopping_ || !start_native(connect_by, replayable)) co_return;
            opened_ = true;
            (void)co_await capy::when_all(driver_.run(), lifetime());
        }
        auto finish() noexcept -> void {
            stop();
            socket_.release();
            if (!opened_ && owner_) (void)port_.registry().release(*owner_);
            finished_ = true;
        }

    public:
        Connection(Io& context, std::shared_ptr<Profile const> profile, Endpoint peer, TicketCache tickets,
            std::optional<InterfaceAttempt> path)
            : profile_(std::move(profile)), tickets_(std::move(tickets)), peer_(peer), path_(path), socket_(context) {}
        [[nodiscard]] auto done() const noexcept -> bool { return finished_; }
        [[nodiscard]] auto accepts(Profile const& profile, Endpoint peer) const noexcept -> bool {
            return !stopping_ && !finished_ && &profile == profile_.get() && peer == peer_ && app_->available();
        }
        [[nodiscard]] auto matches(std::optional<InterfaceAttempt> path) const noexcept -> bool {
            return path ? path_ && path_->index == path->index : !path_;
        }
        [[nodiscard]] auto ready_on(std::span<std::uint32_t const> interfaces) const noexcept -> bool {
            return path_ && app_->ready() && std::ranges::contains(interfaces, path_->index);
        }
        [[nodiscard]] auto retry_interface(bool submitted_bytes) const noexcept -> bool {
            if (!path_ || submitted_bytes || app_->ready() || app_->poisoned()) return false;
            if (bind_error_) return platform::network::retry_interface_error(bind_error_);
            if (factory_.failure) return factory_.failure == n::err_handshake_timeout;
            auto const& failure = driver_.failure();
            if (failure) {
                auto* socket = std::get_if<net::DatagramFailure>(&*failure);
                return socket && (platform::network::retry_interface_error(socket->system) ||
                    socket->system == std::errc::connection_refused);
            }
            return Clock::now() >= path_->until;
        }
        auto stop() noexcept -> void {
            stopping_ = true;
            if (app_) app_->request_stop();
            driver_.finish();
        }

    private:
        auto start_native(Clock::time_point connect_by, bool replayable) -> bool {
            local_ = socket_.local_endpoint();
            auto tls_config = tls::make_profile_fingerprint_config(tls::Fingerprint::native, profile_->tls.key_share,
                profile_->tls.hybrid_only, tls::HandshakeTransport::quic);
            auto hello = tls::make_fingerprint_hello(profile_->tls.server_name, alpn, tls_config,
                tls::HandshakeTransport::quic, std::span<std::uint8_t const>{});
            if (!hello) return false;
            if (!Policy::initialize_tls(tls_, std::move(*hello), *profile_, peer_, tickets_, replayable)) return false;
            std::array<std::uint8_t, 8> source{};
            std::array<std::uint8_t, 16> destination{};
            if (!crypto::random_bytes(source) || !crypto::random_bytes(destination)) return false;
            auto now = Clock::now();
            if (now >= connect_by) return false;
            if (!port_.registry().insert(*owner_, source)) return false;
            factory_.session.emplace(*tls_, *app_, local_);
            n::ngtcp2_settings settings{};
            n::ngtcp2_transport_params params{};
            n::ngtcp2_settings_default_versioned(n::settings_version, &settings);
            settings.handshake_timeout = std::chrono::duration_cast<std::chrono::nanoseconds>(connect_by - now).count();
            n::ngtcp2_transport_params_default_versioned(n::transport_params_version, &params);
            params.initial_max_stream_data_bidi_local = 65537;
            params.initial_max_data = max_streams * 65537;
            params.active_connection_id_limit = 4;
            params.max_idle_timeout = std::chrono::duration_cast<std::chrono::nanoseconds>(15s).count();
            params.disable_active_migration = 1;
            n::ngtcp2_cid src{}, dst{};
            n::ngtcp2_cid_init(&src, source.data(), source.size());
            n::ngtcp2_cid_init(&dst, destination.data(), destination.size());
            auto error = factory_.session->start(false, dst, src, peer_, settings, params, memory_.transport(), now);
            if (error || !port_.attach(*owner_, *factory_.session)) {
                factory_.session.reset();
                return false;
            }
            return true;
        }

    public:
        auto start(Io& context, std::shared_ptr<Connection> self, Clock::time_point deadline, bool replayable) -> bool {
            // A waiter may expire while another query still needs the handshake.
            auto connect_by = path_ ? path_->until : Clock::now() + profile_->connect_timeout;
            auto prepare_by = std::min(deadline, connect_by);
            auto reserved = port_.registry().reserve();
            if (!reserved) return false;
            owner_ = *reserved;
            app_.emplace(port_.registry(), *owner_);
            try {
                capy::run_async(context.get_executor(), [self] { self->finish(); },
                    [self](std::exception_ptr) noexcept { self->finish(); })(run(prepare_by, connect_by, replayable));
            } catch (...) {
                finish();
                throw;
            }
            return path_.has_value() || !finished_;
        }
        auto submit(std::shared_ptr<Query> const& query) -> void {
            app_->submit(query);
            driver_.notify();
        }
        auto reject_protocol() noexcept -> void {
            app_->reject_protocol();
            driver_.notify();
        }
        auto leave(std::shared_ptr<Query> const& query) noexcept -> void {
            app_->leave(query);
            if (!opened_ && app_->idle_deadline()) stop();
            driver_.notify();
        }
    };

    template<class Policy>
    class Pool final : public capy::execution_context::service {
        using Profile = typename Policy::Profile;
        using TicketCache = typename Policy::TicketCache;
        using Conn = Connection<Policy>;
        [[no_unique_address]] TicketCache tickets_ = Policy::make_ticket_cache();
        std::vector<std::shared_ptr<Conn>> connections_;
        bool stopped_ = false;
        auto shutdown() noexcept -> void override {
            stopped_ = true;
            for (auto const& connection : connections_) connection->stop();
            connections_.clear();
        }
    public:
        explicit Pool(capy::execution_context&) {}
        auto stop() noexcept -> void { shutdown(); }
        auto resume() noexcept -> void { stopped_ = false; }
        auto find_ready(Profile const& profile, Endpoint peer, std::span<std::uint32_t const> interfaces) const
            -> std::shared_ptr<Conn> {
            auto existing = std::ranges::find_if(connections_, [&](auto const& connection) {
                return connection->accepts(profile, peer) && connection->ready_on(interfaces);
            });
            return existing == connections_.end() ? nullptr : *existing;
        }
        auto acquire(Io& context, std::shared_ptr<Profile const> const& profile, Endpoint peer, Clock::time_point deadline,
            bool replayable, std::optional<InterfaceAttempt> path = {}) -> std::expected<std::shared_ptr<Conn>, Error> {
            if (stopped_) return std::unexpected(Error::canceled);
            std::erase_if(connections_, [](auto const& connection) { return connection->done(); });
            auto existing = std::ranges::find_if(connections_, [&](auto const& connection) {
                return connection->accepts(*profile, peer) && connection->matches(path);
            });
            if (existing != connections_.end()) return *existing;
            if (connections_.size() >= 16) return std::unexpected(Error::budget_exhausted);
            auto connection = std::make_shared<Conn>(context, profile, peer, tickets_, path);
            if (!connection->start(context, connection, deadline, replayable)) return std::unexpected(Error::transport);
            connections_.push_back(connection);
            return connection;
        }
    };

    template<class Policy>
    struct QuicQuery {
        using Profile = typename Policy::Profile;
        using Conn = Connection<Policy>;
        using ConnPool = Pool<Policy>;
        std::shared_ptr<Profile const> profile;
        struct Attempt {
            std::expected<Response, Error> result;
            bool retry_interface = false;
        };
        auto exchange(Conn& connection, Bytes frame, QueryMessage const& query, std::uint16_t id,
            Clock::time_point deadline, InputBudget& budget, std::stop_token stop, bool replayable) const
            -> capy::task<Attempt> {
            if (connection.done()) co_return Attempt{std::unexpected(Error::transport), connection.retry_interface(false)};
            auto request = std::make_shared<Query>(std::move(frame), deadline, replayable);
            connection.submit(request);
            struct Registration {
                Conn& connection;
                std::shared_ptr<Query> const& request;
                ~Registration() { connection.leave(request); }
            } registration{connection, request};
            std::stop_callback cancel(stop, [&request]() noexcept { request->wake.set(); });
            auto [error] = co_await corosio::timeout(request->wake.wait(), deadline);
            if (stop.stop_requested()) co_return Attempt{std::unexpected(Error::canceled)};
            if (Clock::now() >= deadline || capy::is_timeout(error)) co_return Attempt{std::unexpected(Error::timeout)};
            if (error || !request->result) co_return Attempt{std::unexpected(Error::canceled)};
            auto& answer = *request->result;
            if (!answer) co_return Attempt{std::unexpected(answer.error()),
                answer.error() == Error::transport && connection.retry_interface(request->submitted_bytes)};
            std::optional<InputBudget::Lease> input;
            if (&budget != &default_upstream_receive_budget()) {
                input = budget.acquire(answer->bytes.size());
                if (!input) co_return Attempt{std::unexpected(Error::budget_exhausted)};
            }
            auto response = parse_owned_response(std::move(answer->bytes), 0, query.question);
            if (!response) {
                if (response.error() == MessageError::truncated) co_return Attempt{std::unexpected(Error::truncated)};
                connection.reject_protocol();
                co_return Attempt{std::unexpected(Error::protocol)};
            }
            response->wire[0] = static_cast<std::uint8_t>(id >> 8);
            response->wire[1] = static_cast<std::uint8_t>(id);
            co_return Attempt{std::move(*response)};
        }

        auto operator()(Io& context, Endpoint endpoint, QueryMessage const& query, std::uint16_t id,
            Clock::time_point deadline, InputBudget& budget, std::stop_token stop) const
            -> capy::task<std::expected<Response, Error>> {
            if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
            if (Clock::now() >= deadline) co_return std::unexpected(Error::timeout);
            auto encoded = encode_query(query);
            if (!encoded || encoded->size() > 65535) co_return std::unexpected(Error::invalid_query);
            (*encoded)[0] = (*encoded)[1] = 0;
            Bytes frame{static_cast<std::uint8_t>(encoded->size() >> 8), static_cast<std::uint8_t>(encoded->size())};
            frame.insert(frame.end(), encoded->begin(), encoded->end());
            // Keep EDNS data and message types outside ordinary address lookup on 1-RTT.
            bool replayable = Policy::supports_early_data && query.question.klass == 1 &&
                (query.question.type == 1 || query.question.type == 28) && !query.edns;
            auto& pool = context.use_service<ConnPool>();
            if (!profile->binding.network || profile->datagram) {
                auto connection = pool.acquire(context, profile, endpoint, deadline, replayable);
                if (!connection) co_return std::unexpected(connection.error());
                auto attempt = co_await exchange(**connection, std::move(frame), query, id, deadline, budget, stop, replayable);
                co_return std::move(attempt.result);
            }

            auto interfaces = (*profile->binding.network)(endpoint.is_v6());
            if (auto connection = pool.find_ready(*profile, endpoint, interfaces.indices)) {
                auto attempt = co_await exchange(*connection, std::move(frame), query, id, deadline, budget, stop, replayable);
                co_return std::move(attempt.result);
            }
            auto connect_by = std::min(deadline, Clock::now() + profile->connect_timeout);
            for (std::size_t index = 0; index < interfaces.indices.size(); ++index) {
                if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
                auto now = Clock::now();
                if (now >= connect_by) co_return std::unexpected(Error::timeout);
                auto until = index + 1 < interfaces.indices.size() ?
                    std::min(connect_by, now + interfaces.fallback_delay) : connect_by;
                auto connection = pool.acquire(context, profile, endpoint, deadline, replayable,
                    InterfaceAttempt{interfaces.indices[index], until});
                if (!connection) co_return std::unexpected(connection.error());
                auto wire = index + 1 == interfaces.indices.size() ? std::move(frame) : frame;
                auto attempt = co_await exchange(**connection, std::move(wire), query, id, deadline, budget, stop, replayable);
                if (!attempt.retry_interface || index + 1 == interfaces.indices.size())
                    co_return std::move(attempt.result);
            }
            co_return std::unexpected(Error::transport);
        }
    };

    template<class Policy>
    auto stop_quic_queries_with(corosio::io_context& context) noexcept -> void {
        if (auto* pool = context.find_service<Pool<Policy>>()) pool->stop();
    }

    template<class Policy>
    auto resume_quic_queries_with(corosio::io_context& context) noexcept -> void {
        if (auto* pool = context.find_service<Pool<Policy>>()) pool->resume();
    }

    template<class Policy>
    auto make_quic_query_with(std::string_view server_name, std::string_view ca_file, platform::SocketBinding binding,
        std::chrono::milliseconds connect_timeout, bool early_data, QuicDnsDatagramFactory datagram)
        -> std::expected<dns::detail::ProtectedQuery, std::string> {
        auto profile = tls::ClientProfile::load(server_name, ca_file, 0x001d, false, alpn);
        if (!profile) return std::unexpected(std::move(profile.error()));
        auto snapshot = Policy::make_profile(std::move(*profile), std::move(binding), connect_timeout, early_data, std::move(datagram));
        if (!snapshot) return std::unexpected(std::move(snapshot.error()));
        return dns::detail::ProtectedQuery{QuicQuery<Policy>{std::move(*snapshot)}};
    }
}
