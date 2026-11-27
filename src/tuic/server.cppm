export module tuic.server;
import std;
import crypto;
import tuic.wire;
import tuic.stream_input;
import tuic.application;
import tuic.transport_options;
import quic.cid_registry;
import quic.datagram_port;
import quic.datagram_session;
import quic.transport_memory;
import quic.retry_admission;
import quic.retry_token;
import quic.tls_server;
import quic.optional_client_resumption;
import tls.ech_server;
import tls.server_credential;
import net.datagram_driver;
import ngtcp2;
import capy;
import corosio;

export namespace tuic {
    // Multi-session QUIC listener for TUIC v5. Mirrors Masque/Hysteria2 listener
    // architecture: Retry admission + CID registry + typed per-session Application.
    template<class Hooks, std::size_t Sessions = 32, std::size_t Streams = 64, std::size_t Window = 32768>
    class Listener {
        using Clock = std::chrono::steady_clock;
        using Registry = quic::CidRegistry<Sessions, 8>;

        struct SessionHooks {
            Listener& listener;
            Registry& registry;
            quic::SessionHandle owner;
            Hooks& app_hooks;
            std::size_t session_slot = 0;

            auto changed() noexcept -> void { listener.notify(); }
            auto admit_authenticated(std::size_t user) noexcept -> bool
                requires requires {app_hooks.admit_authenticated(owner,user);} {
                return app_hooks.admit_authenticated(owner,user);
            }
            auto authenticated(std::size_t user) -> void { app_hooks.authenticated(owner, user); }
            auto connect_stream(StreamHandle stream, TargetAddress const& target) -> void {
                app_hooks.connect_stream(owner, stream, target);
            }
            auto udp_packet(IncomingUdpPacket pkt) -> void {
                app_hooks.udp_packet(owner, std::move(pkt));
            }
            auto udp_dissociate(std::uint16_t assoc_id) -> void {
                app_hooks.udp_dissociate(owner, assoc_id);
            }
            auto transport_closed() noexcept -> void { app_hooks.transport_closed(owner); }
            auto add_connection_id(ngtcp2::ngtcp2_cid const& id, ngtcp2::ngtcp2_stateless_reset_token const&) noexcept -> int {
                return registry.insert(owner, {id.data, id.datalen}) ? 0 : ngtcp2::err_callback_failure;
            }
            auto remove_connection_id(ngtcp2::ngtcp2_cid const& id) noexcept -> int {
                (void)registry.remove(owner, {id.data, id.datalen});
                return 0;
            }
        };

    public:
#ifdef NEXUS_QUIC_RESUMPTION
        using TicketStore = quic::EarlyDataTicketStore<64>;
        using ServerTls = quic::EarlyDataTlsServer<TicketStore>;
#else
        using ServerTls = quic::TlsServer;
#endif
        using App = Application<ServerTls, SessionHooks, Streams, Window>;
        using NativeSession = quic::DatagramSession<ServerTls, App>;

    private:
        struct Bundle {
#ifdef NEXUS_QUIC_RESUMPTION
            std::unique_ptr<ServerTls> tls;
#else
            quic::TlsServer tls;
#endif
            SessionHooks hooks;
            quic::NativeTransportMemory<> memory;
            App app;
            NativeSession session;
            corosio::endpoint initial_peer;
#ifdef NEXUS_QUIC_RESUMPTION
            Bundle(Listener& parent,Registry& reg,quic::SessionHandle id,corosio::endpoint peer,std::unique_ptr<ServerTls> server_tls)
                : tls(std::move(server_tls)), hooks{parent, reg, id, parent.hooks_, id.slot},
                  memory(parent.options_.native_bytes), app(*tls, hooks, parent.users_, &parent.user_index_),
                  session(*tls,app,parent.local_),initial_peer(peer) {
                app.set_issue_tickets(parent.options_.zero_rtt_handshake);
            }
#else
            Bundle(Listener& parent,Registry& reg,quic::SessionHandle id,corosio::endpoint peer,std::optional<tls::ServerCredential>&& dynamic_credential)
                : tls(std::move(dynamic_credential), parent.credential_, "h3", parent.ech_keys_), hooks{parent, reg, id, parent.hooks_, id.slot},
                  memory(parent.options_.native_bytes), app(tls, hooks, parent.users_, &parent.user_index_),
                  session(tls,app,parent.local_),initial_peer(peer) {}
#endif
        };

        struct Factory {
            using Session = NativeSession;
            using ControlFailure = quic::RetryFailure;
            Listener& listener;
            quic::RetryAdmission<> retry;
            std::optional<quic::RetryClaims> permit;
            bool direct_admit = false;
            std::optional<ControlFailure> error;
            std::array<std::optional<Bundle>, Sessions> bundles;

            explicit Factory(Listener& owner) noexcept : listener(owner) {}

            auto admit(ngtcp2::ngtcp2_pkt_hd const& initial, corosio::endpoint const& peer,
                       Clock::time_point now, std::size_t bytes) noexcept -> bool {
                permit.reset();
                direct_admit = false;
#ifdef NEXUS_QUIC_RESUMPTION
                if (listener.options_.zero_rtt_handshake) {
                    if (bytes < 1200 || initial.version != 1 || initial.type != ngtcp2::NGTCP2_PKT_INITIAL ||
                        initial.dcid.datalen < 8 || initial.dcid.datalen > 20 || initial.scid.datalen > 20 || !peer.port())
                        return false;
                    direct_admit = true;
                    return true;
                }
#endif
                auto res = retry.inspect(initial, peer, now, bytes);
                if (!res) { if (!error) error = res.error(); return false; }
                permit = *res;
                return permit.has_value();
            }
            auto control_failure() const noexcept { return error; }
            auto control_output(std::span<std::uint8_t> out, Clock::time_point now) noexcept
                -> std::expected<std::optional<net::DatagramOutput>, ControlFailure> {
                if (error) return std::unexpected(*error);
                return retry.output(out, now);
            }
            auto control_transmitted(std::uint64_t tok, Clock::time_point now) noexcept { return retry.transmitted(tok, now); }
            auto control_next_expiry() const noexcept { return retry.next_expiry(); }
            auto control_expire(Clock::time_point now) noexcept { return retry.expire(now); }
            auto control_request_stop() noexcept -> void { retry.request_stop(); }
            auto control_stop() noexcept -> void { permit.reset(); direct_admit = false; retry.stop(); }
            auto control_drained() const noexcept -> bool { return retry.drained(); }

            auto create(quic::SessionHandle owner, Registry& reg, std::span<std::uint8_t const> source,
                        ngtcp2::ngtcp2_pkt_hd const& initial, corosio::endpoint const& peer,
                        Clock::time_point now) noexcept -> std::expected<Session*, int> {
                namespace n = ::ngtcp2;
                try {
                    bool const use_direct = std::exchange(direct_admit, false);
                    std::optional<quic::RetryClaims> verified;
                    if (!use_direct) {
                        if (!permit || !std::ranges::equal(permit->retry.bytes(), std::span(initial.dcid.data).first(initial.dcid.datalen)))
                            return std::unexpected(n::err_callback_failure);
                        verified = *permit;
                        permit.reset();
                    }
                    auto& entry = bundles[owner.slot];
                    if (entry) return std::unexpected(n::err_callback_failure);
#ifdef NEXUS_QUIC_RESUMPTION
                    auto server_tls = listener.atomic_credential_
                        ? ServerTls::create(listener.atomic_credential_, "h3", listener.ticket_store_,
                            listener.options_.zero_rtt_handshake, {}, listener.ech_keys_)
                        : (listener.credential_
                            ? ServerTls::create(*listener.credential_, "h3", listener.ticket_store_,
                                listener.options_.zero_rtt_handshake, {}, listener.ech_keys_)
                            : std::unexpected(tls::PskError::invalid_input));
                    if (!server_tls) return std::unexpected(n::err_callback_failure);
                    entry.emplace(listener, reg, owner, peer, std::move(*server_tls));
#else
                    std::optional<tls::ServerCredential> dyn_cred;
                    if (listener.atomic_credential_) {
                        auto cur = listener.atomic_credential_->clone_current();
                        if (!cur) return std::unexpected(n::err_callback_failure);
                        dyn_cred.emplace(std::move(*cur));
                    } else if (!listener.credential_) return std::unexpected(n::err_callback_failure);
                    entry.emplace(listener, reg, owner, peer, std::move(dyn_cred));
#endif
                    n::ngtcp2_settings settings{};
                    n::ngtcp2_transport_params params{};
                    apply_tuic_quic_config(listener.options_, Streams, Window, settings, params);
                    if (verified) {
                        n::ngtcp2_cid_init(&params.original_dcid, verified->original.data.data(), verified->original.size);
                        params.original_dcid_present = 1;
                        params.retry_scid = initial.dcid;
                        params.retry_scid_present = 1;
                        settings.token = initial.token;
                        settings.tokenlen = initial.tokenlen;
                        settings.token_type = n::NGTCP2_TOKEN_TYPE_RETRY;
                    } else {
                        params.original_dcid = initial.dcid;
                        params.original_dcid_present = 1;
                    }
                    n::ngtcp2_cid cid{};
                    n::ngtcp2_cid_init(&cid, source.data(), source.size());
                    auto code = entry->session.start(true, initial.scid, cid, peer, settings, params, entry->memory.transport(), now);
                    if (code) {
                        entry->session.stop();
                        entry->session.drain();
                        entry.reset();
                        return std::unexpected(code);
                    }
                    return &entry->session;
                } catch (...) {
                    bundles[owner.slot].reset();
                    return std::unexpected(n::err_nomem);
                }
            }
            auto application_drained(quic::SessionHandle owner, Session const&) const noexcept -> bool {
                return listener.hooks_.session_drained(owner);
            }
            auto failed(quic::SessionHandle, int) noexcept -> void {}
            auto destroy(quic::SessionHandle owner, Session&) noexcept -> void {
                listener.hooks_.session_destroyed(owner);
                bundles[owner.slot].reset();
            }
        };

    public:
        using Port = quic::DatagramPort<Factory, Sessions, 8, 8, false>;
        using Driver = net::DatagramDriver<Port, corosio::udp_socket>;

    private:
        corosio::udp_socket socket_;
        corosio::endpoint local_;
        tls::ServerCredential const* credential_ = nullptr;
        std::shared_ptr<tls::AtomicServerCredential> atomic_credential_{};
        std::shared_ptr<tls::EchServerKeys const> ech_keys_{};
        std::span<UserCredential const> users_;
        detail::UserIndex user_index_;
        ClientTransportOptions options_;
#ifdef NEXUS_QUIC_RESUMPTION
        TicketStore ticket_store_;
#endif
        Hooks& hooks_;
        Factory factory_{*this};
        Port port_{factory_};
        Driver driver_{socket_, port_};
        bool run_started_ = false;

    public:
        Listener(corosio::io_context& ctx, tls::ServerCredential const* cred,
                 std::shared_ptr<tls::AtomicServerCredential> atomic_cred,
                 std::span<UserCredential const> users, ClientTransportOptions opts, Hooks& hooks,
                 std::shared_ptr<tls::EchServerKeys const> ech_keys = {})
            : socket_(ctx), credential_(cred), atomic_credential_(std::move(atomic_cred)),
              ech_keys_(std::move(ech_keys)), users_(users), user_index_(users), options_(opts), hooks_(hooks) {}
        Listener(corosio::io_context& ctx, tls::ServerCredential const& cred,
                 std::span<UserCredential const> users, ClientTransportOptions opts, Hooks& hooks,
                 std::shared_ptr<tls::EchServerKeys const> ech_keys = {})
            : Listener(ctx, &cred, {}, users, opts, hooks, std::move(ech_keys)) {}
        Listener(corosio::io_context& ctx, std::shared_ptr<tls::AtomicServerCredential> atomic_cred,
                 std::span<UserCredential const> users, ClientTransportOptions opts, Hooks& hooks,
                 std::shared_ptr<tls::EchServerKeys const> ech_keys = {})
            : Listener(ctx, nullptr, std::move(atomic_cred), users, opts, hooks, std::move(ech_keys)) {}

        auto prepare(corosio::endpoint local) -> std::expected<corosio::endpoint, std::error_code> {
            if (!factory_.retry.initialize()) return std::unexpected(std::make_error_code(std::errc::io_error));
            if (auto err = socket_.open(local.address().family())) return std::unexpected(err);
            if (auto err = socket_.bind(local)) { socket_.close(); return std::unexpected(err); }
            local_ = socket_.local_endpoint();
            return local_;
        }

        auto app(quic::SessionHandle h) noexcept -> App* {
            if (h.slot >= Sessions || !factory_.bundles[h.slot]) return nullptr;
            auto& b = *factory_.bundles[h.slot];
            return b.hooks.owner == h ? &b.app : nullptr;
        }
#ifdef NEXUS_QUIC_RESUMPTION
        auto clear_tickets() noexcept -> void { ticket_store_.clear(); }
        [[nodiscard]] auto ticket_count() const noexcept -> std::size_t { return ticket_store_.size(); }
#endif

        auto initial_peer(quic::SessionHandle h) const noexcept -> std::optional<corosio::endpoint> {
            if (h.slot>=Sessions) return {};
            auto const& bundle=factory_.bundles[h.slot];
            if (!bundle || bundle->hooks.owner!=h) return {};
            return bundle->initial_peer;
        }

        auto changed() noexcept -> capy::async_event& { return driver_.changed(); }
        auto notify() noexcept -> void { driver_.notify(); }
        auto running() const noexcept -> bool { return driver_.running(); }
        auto driver_drained() const noexcept -> bool { return !run_started_ || driver_.drained(); }
        auto drained() const noexcept -> bool { return port_.drained(); }
        auto maintain() noexcept -> void { port_.maintain(); }
        auto start() -> void { driver_.notify(); }
        auto run() -> auto { run_started_ = true; return driver_.run(); }
        auto stop() noexcept -> void {
            driver_.finish();
            if (!run_started_) {
                port_.request_stop();
                port_.stop();
                socket_.close();
            }
            notify();
        }
    };
}
