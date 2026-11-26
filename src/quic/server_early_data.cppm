// QUIC TLS 1.3 server 0-RTT early data with single-use anti-replay ticket store.
export module quic.server_early_data;
import std;
import containers.inplace_vector;
import crypto;
import crypto.ecdh;
import quic.packet_keys;
import quic.tls_common;
export import quic.resumption;
import tls.ech_server;
import tls.psk;
import tls.psk_server_policy;
import tls.server_credential;
import tls.server_negotiation;
import tls.server_keys;
import tls.raw_server_flight;
import tls.handshake_policy;
import tls.handshake;
import tls.server_hello;
import tls.key_share;
import tls.hybrid;
import tls.schedule;
import tls.transcript;
import ngtcp2;

export namespace quic {
    // Bounded server ticket store with per-ticket cipher suite tracking and
    // single-use 0-RTT anti-replay detection. Single-executor owned.
    template<std::size_t Capacity = 64>
    class EarlyDataTicketStore {
        tls::ServerTicketStore<Capacity> store_;
        std::deque<std::pair<std::array<std::uint8_t, 32>, std::uint16_t>> suites_;
        std::deque<std::array<std::uint8_t, 32>> used_early_;
        static constexpr std::size_t max_suites = Capacity * 2;
        static constexpr std::size_t max_replay = Capacity * 4;
    public:
        [[nodiscard]] auto size() const noexcept -> std::size_t { return store_.size(); }
        auto clear() noexcept -> void { store_.clear(); suites_.clear(); used_early_.clear(); }
        [[nodiscard]] auto contains(std::span<std::uint8_t const> identity) const noexcept -> bool {
            return store_.contains(identity);
        }
        [[nodiscard]] auto find(std::span<std::uint8_t const> identity, tls::ServerTicketBinding const& binding,
            crypto::Hash hash, std::uint64_t now) -> std::optional<tls::PskOfferView> {
            return store_.find(identity, binding, hash, now);
        }
        [[nodiscard]] auto publish(tls::ServerTicketEntry&& entry, std::uint64_t now) -> bool {
            return store_.publish(std::move(entry), now);
        }
        auto record_suite(std::array<std::uint8_t, 32> const& id, std::uint16_t suite) -> void {
            if (suites_.size() >= max_suites) suites_.pop_front();
            suites_.emplace_back(id, suite);
        }
        [[nodiscard]] auto ticket_suite(std::span<std::uint8_t const> id) const noexcept -> std::optional<std::uint16_t> {
            if (id.size() != 32) return {};
            for (auto it = suites_.rbegin(); it != suites_.rend(); ++it)
                if (std::ranges::equal(it->first, id)) return it->second;
            return {};
        }
        [[nodiscard]] auto try_consume_early(std::span<std::uint8_t const> id) -> bool {
            if (id.size() != 32) return false;
            for (auto const& used : used_early_)
                if (std::ranges::equal(used, id)) return false;
            if (used_early_.size() >= max_replay) used_early_.pop_front();
            std::array<std::uint8_t, 32> copy{};
            std::ranges::copy(id, copy.begin());
            used_early_.push_back(copy);
            return true;
        }
    };

    namespace early_detail {
        struct EarlyFlight {
            crypto::Hash hash;
            tls::Transcript transcript;
            tls::Secret client_hs_traffic;
        };
    }

    template<class Store = EarlyDataTicketStore<64>, class Clock = tls::PskSteadyClock>
    class EarlyDataServerPolicy {
        Store& store_;
        tls::PskServerPolicy<Store, Clock> base_;
        std::optional<tls::Secret> early_traffic_;
        bool early_allowed_ = true;
        bool accepted_early_ = false;
    public:
        static constexpr bool enabled = true;
        static constexpr bool early_data = true;
        static constexpr auto local_error(tls::PskError e) noexcept -> bool { return e == tls::PskError::crypto_error; }

        EarlyDataServerPolicy(Store& store, tls::ServerTicketBinding binding, bool early_allowed) noexcept
            : store_(store), base_(store, std::move(binding)), early_allowed_(early_allowed) {}
        EarlyDataServerPolicy(EarlyDataServerPolicy const&) = delete;
        auto operator=(EarlyDataServerPolicy const&) -> EarlyDataServerPolicy& = delete;
        EarlyDataServerPolicy(EarlyDataServerPolicy&&) noexcept = default;

        auto cancel() noexcept -> void { base_.cancel(); early_traffic_.reset(); accepted_early_ = false; }
        auto disallow_early() noexcept -> void { early_allowed_ = false; }
        [[nodiscard]] auto selected() const noexcept -> bool { return base_.selected(); }
        [[nodiscard]] auto selected_index() const noexcept -> std::optional<std::uint16_t> { return base_.selected_index(); }
        [[nodiscard]] auto binding() const noexcept -> tls::ServerTicketBinding const& { return base_.binding(); }
        [[nodiscard]] auto accepted_early() const noexcept -> bool { return accepted_early_; }
        [[nodiscard]] auto early_traffic() const noexcept -> std::optional<std::span<std::uint8_t const>> {
            return early_traffic_ ? std::optional(early_traffic_->view()) : std::nullopt;
        }
        auto select(tls::ClientHello const& client, std::span<std::uint8_t const> wire, std::uint16_t suite,
            std::span<std::uint8_t const> first = {}, std::span<std::uint8_t const> retry = {})
            -> std::expected<std::optional<std::span<std::uint8_t const>>, tls::PskError> {
            auto psk = base_.select(client, wire, suite, first, retry);
            if (!psk) return psk;
            if (early_allowed_ && first.empty() && *psk && base_.selected_index() == std::uint16_t{0} &&
                client.extension(42) && client.extension(42)->data.empty()) {
                auto* ext41 = client.extension(41);
                auto parsed = ext41 ? tls::parse_client_psks(ext41->data) : std::unexpected(tls::PskError::invalid_offer);
                auto hash = tls::psk_cipher_hash(suite);
                if (parsed && hash && !parsed->entries.empty()) {
                    auto id = parsed->entries.front().identity;
                    if (store_.ticket_suite(id) == suite && store_.try_consume_early(id)) {
                        auto early = tls::early_secret(*hash, **psk);
                        auto ch_hash = crypto::digest(*hash, wire);
                        if (early && ch_hash) {
                            auto traffic = tls::derive_secret(*hash, early->view(), "c e traffic", *ch_hash);
                            if (traffic) {
                                early_traffic_.emplace(std::move(*traffic));
                                accepted_early_ = true;
                            }
                        }
                    }
                }
            }
            return psk;
        }
        auto retain_master(tls::Secret&& master, crypto::Hash hash) -> std::expected<void, tls::PskError> {
            return base_.retain_master(std::move(master), hash);
        }
        auto client_finished(std::span<std::uint8_t const> transcript_hash) -> std::expected<void, tls::PskError> {
            return base_.client_finished(transcript_hash);
        }
        [[nodiscard]] auto take_issuer() -> std::expected<tls::ServerTicketIssuer<Store, Clock>, tls::PskError> {
            return base_.take_issuer();
        }
    };

    template<class Store = EarlyDataTicketStore<64>, class Clock = tls::PskSteadyClock>
    class EarlyDataTlsServer {
        enum class State { hello, retry_hello, finished, completing, complete, failed } state_ = State::hello;
        struct ApplicationReadKey { PacketSuite suite; tls::Secret secret; };
        std::optional<tls::ServerCredential> owned_credential_;
        tls::ServerCredential const* credential_ = nullptr;
        std::string_view alpn_;
        Store& store_;
        EarlyDataServerPolicy<Store, Clock> recovery_;
        tls::EchServerContext ech_;
        std::string negotiated_sni_;
        std::optional<tls::HandshakeDecoder> decoder_;
        std::optional<tls::RawServerFlight> flight_;
        std::optional<early_detail::EarlyFlight> early_flight_;
        std::optional<ApplicationReadKey> application_;
        std::optional<tls::Secret> exporter_;
        crypto::Hash cipher_hash_ = crypto::Hash::sha256;
        std::uint16_t cipher_suite_ = 0;
        crypto::Bytes first_, retry_;
        std::uint8_t last_alert_ = 0;
        bool early_allowed_ = true;

        auto alpn() const noexcept -> std::span<std::uint8_t const> {
            return {reinterpret_cast<std::uint8_t const*>(alpn_.data()), alpn_.size()};
        }
        template<class Connection>
        auto fail(Connection& connection, std::uint8_t alert, int code = ngtcp2::err_crypto) noexcept -> int {
            last_alert_ = alert; connection.tls_alert(alert); cancel(); return code;
        }
        auto make_secrets_for_early(tls::ClientHello const& client, std::span<std::uint8_t const> wire,
            std::span<std::uint16_t const> schemes) -> std::expected<tls::ServerHandshakeSecrets, tls::ServerKeyError> {
            tls::ClientHello stripped = client;
            std::erase_if(stripped.extensions, [](auto const& e) { return e.type == 42; });
            auto sel = tls::negotiate_server<true>(stripped, schemes, tls::PeerSignaturePolicy::require_offered,
                tls_packet_ciphers, tls::HandshakeTransport::quic);
            if (!sel) return std::unexpected(tls::ServerKeyError::negotiation_failed);
            if (!sel->x25519_share && !sel->hybrid_share && !sel->ec_share)
                return std::unexpected(tls::ServerKeyError::retry_required);
            auto psk = recovery_.select(client, wire, sel->cipher_suite, {}, {});
            if (!psk) return std::unexpected(EarlyDataServerPolicy<Store, Clock>::local_error(psk.error())
                ? tls::ServerKeyError::crypto_error : tls::ServerKeyError::invalid_psk);
            if (!*psk && !sel->signature_scheme) return std::unexpected(tls::ServerKeyError::negotiation_failed);
            std::optional<crypto::X25519Private> key;
            if (!sel->ec_share) {
                auto gen = crypto::X25519Private::generate();
                if (!gen) return std::unexpected(tls::ServerKeyError::crypto_error);
                key.emplace(std::move(*gen));
            }
            std::optional<crypto::Secret32> x_sec;
            std::optional<tls::HybridServerResult> hybrid;
            std::optional<crypto::EcSecret> ec_sec;
            crypto::EcPublic ec_pub;
            std::array<std::uint8_t, 32> pub_bytes{};
            std::span<std::uint8_t const> pub_share, shared;
            if (sel->group == 0x001d && sel->x25519_share) {
                auto v = key->agree(*sel->x25519_share);
                if (!v) return std::unexpected(tls::ServerKeyError::invalid_peer);
                x_sec.emplace(std::move(*v)); shared = x_sec->view();
                auto p = key->public_key();
                if (!p) return std::unexpected(tls::ServerKeyError::crypto_error);
                pub_bytes = *p; pub_share = pub_bytes;
            } else if (sel->group == tls::x25519_mlkem768_group && sel->hybrid_share) {
                auto r = tls::hybrid_server_accept(*sel->hybrid_share, std::move(*key));
                if (!r) return std::unexpected(tls::ServerKeyError::invalid_peer);
                hybrid.emplace(std::move(*r)); shared = hybrid->secret.view(); pub_share = hybrid->share;
            } else if (sel->ec_share && crypto::nist_curve(sel->group)) {
                auto ek = crypto::EcPrivate::generate(sel->group);
                if (!ek) return std::unexpected(tls::ServerKeyError::crypto_error);
                auto s = ek->agree(sel->ec_share->view());
                if (!s) return std::unexpected(tls::ServerKeyError::invalid_peer);
                auto p = ek->public_key();
                if (!p) return std::unexpected(tls::ServerKeyError::crypto_error);
                ec_pub = *p; pub_share = ec_pub.view(); ec_sec.emplace(std::move(*s)); shared = ec_sec->view();
            } else return std::unexpected(tls::ServerKeyError::invalid_hello);
            key.reset();
            auto enc_share = tls::KeyShare::encode_server_view({sel->group, pub_share});
            if (!enc_share) return std::unexpected(tls::ServerKeyError::crypto_error);
            tls::ServerHello sh;
            sh.session_id_echo = client.session_id;
            sh.cipher_suite = sel->cipher_suite;
            sh.extensions = {{43, {3, 4}}, {51, std::move(*enc_share)}};
            if (auto idx = recovery_.selected_index())
                sh.extensions.push_back({41, {static_cast<std::uint8_t>(*idx >> 8), static_cast<std::uint8_t>(*idx)}});
            if (!crypto::random_bytes(sh.random) || sh.is_retry()) return std::unexpected(tls::ServerKeyError::crypto_error);
            auto sh_body = sh.encode();
            if (!sh_body) return std::unexpected(tls::ServerKeyError::crypto_error);
            auto sh_wire = tls::HandshakeDecoder::encode(2, *sh_body, 65535);
            if (!sh_wire) return std::unexpected(tls::ServerKeyError::crypto_error);
            if (ech_.accepted()) {
                auto confirmed = tls::apply_ech_accept_confirmation(wire, {}, {}, *sh_wire);
                if (!confirmed) return std::unexpected(tls::ServerKeyError::crypto_error);
                *sh_wire = std::move(*confirmed);
            }
            auto hash = sel->cipher_suite == 0x1302 ? crypto::Hash::sha384 : crypto::Hash::sha256;
            auto transcript = tls::Transcript::create(hash);
            if (!transcript || !transcript->append(wire) || !transcript->append(*sh_wire))
                return std::unexpected(tls::ServerKeyError::crypto_error);
            auto digest = transcript->snapshot();
            auto early = tls::early_secret(hash, *psk);
            if (!digest || !early) return std::unexpected(tls::ServerKeyError::crypto_error);
            auto hs = tls::handshake_secret(hash, early->view(), shared);
            if (!hs) return std::unexpected(tls::ServerKeyError::crypto_error);
            auto ct = tls::derive_secret(hash, hs->view(), "c hs traffic", *digest);
            auto st = tls::derive_secret(hash, hs->view(), "s hs traffic", *digest);
            if (!ct || !st) return std::unexpected(tls::ServerKeyError::crypto_error);
            return tls::ServerHandshakeSecrets{std::move(*sh_wire), sel->signature_scheme,
                tls::HandshakeSecrets{sel->cipher_suite, hash, std::move(*transcript), std::move(*hs), std::move(*ct), std::move(*st)}};
        }
        template<class Connection>
        auto initial_message(Connection& connection, std::uint8_t type, std::span<std::uint8_t const> wire) -> int {
            using namespace ngtcp2;
            if ((state_ != State::hello && state_ != State::retry_hello) || type != 1) return fail(connection, 10);
            if (!credential_) return fail(connection, 80);
            auto step = process_quic_client_hello_ech(ech_, wire, state_ == State::retry_hello);
            if (!step) return fail(connection, step.error());
            auto effective_wire = step->effective_wire(wire);
            negotiated_sni_ = std::move(step->sni);
            if (ech_.rejected_offered()) recovery_.disallow_early();
            auto params = tls::quic_client_parameters<true, true>(step->client, alpn());
            if (!params) return fail(connection, params.error() == tls::HandshakePolicyError::missing_transport_parameters ? 109
                : params.error() == tls::HandshakePolicyError::invalid_alpn ? 120 : 47);
            if (auto f = parameter_block_status(*params)) return fail(connection, 47, f);
            auto schemes = credential_->signature_schemes();
            if (schemes.empty()) return fail(connection, 80);
            bool const ech_ok = ech_.accepted();
            bool has_early_ext = step->client.extension(42) != nullptr;
            auto raw = (state_ == State::hello && has_early_ext)
                ? make_secrets_for_early(step->client, effective_wire, schemes)
                : (state_ == State::hello
                    ? quic_server_handshake_secrets(effective_wire, schemes, ech_ok, recovery_)
                    : quic_server_handshake_secrets_retry(first_, retry_, effective_wire, schemes, ech_ok, recovery_));
            if (!raw) {
                if (state_ != State::hello || raw.error() != tls::ServerKeyError::retry_required || has_early_ext)
                    return fail(connection, raw.error() == tls::ServerKeyError::crypto_error ? 80 : 40);
                auto hrr = quic_server_retry_hello(effective_wire, schemes, ech_ok, recovery_);
                if (!hrr) return fail(connection, 40);
                first_.assign(effective_wire.begin(), effective_wire.end()); retry_ = std::move(*hrr);
                if (auto e = connection.submit_crypto(NGTCP2_ENCRYPTION_LEVEL_INITIAL, retry_)) return fail(connection, 80, e);
                state_ = State::retry_hello; return 0;
            }
            auto suite = tls_packet_suite(raw->secrets.cipher_suite);
            if (!suite) return fail(connection, 47);
            cipher_suite_ = raw->secrets.cipher_suite;
            auto error = connection.remote_transport_parameters(*params);
            if (!error) error = connection.install_secret(NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE, false, *suite, raw->secrets.client_traffic.view());
            if (!error) error = connection.install_secret(NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE, true, *suite, raw->secrets.server_traffic.view());
            if (error) return fail(connection, 80, error);
            auto local = local_quic_parameters(connection);
            if (!local) return fail(connection, 80, local.error());
            error = connection.submit_crypto(NGTCP2_ENCRYPTION_LEVEL_INITIAL, raw->server_hello);
            if (error) return fail(connection, 80, error);
            if (recovery_.accepted_early() && recovery_.early_traffic()) {
                error = connection.install_server_early_data(*suite, *recovery_.early_traffic());
                if (error) return fail(connection, 80, error);
                auto ee = encode_early_encrypted_extensions(alpn(), *local);
                if (!ee || !raw->secrets.transcript.append(*ee)) return fail(connection, 80);
                auto h1 = raw->secrets.transcript.snapshot();
                if (!h1) return fail(connection, 80);
                auto verify = tls::finished_verify_data(raw->secrets.hash, raw->secrets.server_traffic.view(), *h1);
                if (!verify) return fail(connection, 80);
                auto fin = tls::HandshakeDecoder::encode(20, verify->view());
                if (!fin || !raw->secrets.transcript.append(*fin)) return fail(connection, 80);
                auto h2 = raw->secrets.transcript.snapshot();
                if (!h2) return fail(connection, 80);
                auto app = tls::application_traffic_secrets(raw->secrets.cipher_suite, raw->secrets.hash,
                    raw->secrets.handshake_secret.view(), *h2, recovery_);
                if (!app) return fail(connection, 80);
                if ((error = connection.install_secret(NGTCP2_ENCRYPTION_LEVEL_1RTT, true, *suite, app->server.view())) ||
                    (error = connection.submit_crypto(NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE, *ee)) ||
                    (error = connection.submit_crypto(NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE, *fin)))
                    return fail(connection, 80, error);
                application_.emplace(ApplicationReadKey{*suite, std::move(app->client)});
                early_flight_.emplace(early_detail::EarlyFlight{raw->secrets.hash, std::move(raw->secrets.transcript),
                    std::move(raw->secrets.client_traffic)});
                cipher_hash_ = app->hash; exporter_.emplace(std::move(app->exporter));
                crypto::Bytes{}.swap(first_); crypto::Bytes{}.swap(retry_);
                state_ = State::finished; return 0;
            }
            std::array<crypto::Bytes, 4> messages;
            std::optional<tls::TrafficSecrets> app;
            auto flight = tls::RawServerFlight::create_with_ech_retry(std::move(*raw), *credential_, messages, app, alpn(),
                std::span<std::uint8_t const>(*local), ech_.retry_configs(), recovery_);
            if (!flight) return fail(connection, flight.error().alert);
            if (auto e = connection.install_secret(NGTCP2_ENCRYPTION_LEVEL_1RTT, true, *suite, app->server.view()))
                return fail(connection, 80, e);
            for (auto& msg : messages) {
                if (msg.empty()) continue;
                if (auto e = connection.submit_crypto(NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE, msg)) return fail(connection, 80, e);
                crypto::Bytes{}.swap(msg);
            }
            application_.emplace(ApplicationReadKey{*suite, std::move(app->client)});
            flight_.emplace(std::move(*flight));
            cipher_hash_ = app->hash; exporter_.emplace(std::move(app->exporter));
            crypto::Bytes{}.swap(first_); crypto::Bytes{}.swap(retry_);
            state_ = State::finished; return 0;
        }
        template<class Connection>
        auto finished_message(Connection& connection, std::uint8_t type, std::span<std::uint8_t const> wire) -> int {
            using namespace ngtcp2;
            if (state_ != State::finished || type != 20) return fail(connection, 10);
            if (early_flight_) {
                auto body = wire.subspan(4);
                auto sz = early_flight_->hash == crypto::Hash::sha256 ? 32u : 48u;
                if (body.size() != sz) return fail(connection, 50);
                auto h = early_flight_->transcript.snapshot();
                if (!h) return fail(connection, 80);
                auto verify = tls::finished_verify_data(early_flight_->hash, early_flight_->client_hs_traffic.view(), *h);
                if (!verify) return fail(connection, 80);
                if (!crypto::constant_time_equal(verify->view(), body)) return fail(connection, 51);
                if (!early_flight_->transcript.append(wire)) return fail(connection, 80);
                auto done_hash = early_flight_->transcript.snapshot();
                if (!done_hash || !recovery_.client_finished(*done_hash)) return fail(connection, 80);
                early_flight_.reset();
            } else {
                auto verified = flight_->client_finished(wire, recovery_);
                if (!verified) return fail(connection, verified.error().alert);
                flight_.reset();
            }
            if (auto e = connection.install_secret(NGTCP2_ENCRYPTION_LEVEL_1RTT, false, application_->suite, application_->secret.view()))
                return fail(connection, 80, e);
            application_.reset(); state_ = State::completing; return 0;
        }
    public:
        EarlyDataTlsServer(tls::ServerCredential const& credential, std::string_view alpn, Store& store,
            tls::ServerTicketBinding binding, bool early_allowed = true,
            std::shared_ptr<tls::EchServerKeys const> ech_keys = {}) noexcept
            : credential_(&credential), alpn_(alpn), store_(store), recovery_(store, std::move(binding), early_allowed),
              ech_(std::move(ech_keys)), early_allowed_(early_allowed) {}
        EarlyDataTlsServer(tls::ServerCredential&& credential, std::string_view alpn, Store& store,
            tls::ServerTicketBinding binding, bool early_allowed = true,
            std::shared_ptr<tls::EchServerKeys const> ech_keys = {}) noexcept
            : owned_credential_(std::move(credential)), credential_(&*owned_credential_), alpn_(alpn), store_(store),
              recovery_(store, std::move(binding), early_allowed), ech_(std::move(ech_keys)), early_allowed_(early_allowed) {}
        EarlyDataTlsServer(EarlyDataTlsServer const&) = delete;
        auto operator=(EarlyDataTlsServer const&) -> EarlyDataTlsServer& = delete;

        [[nodiscard]] static auto create(tls::ServerCredential const& credential, std::string_view alpn,
            Store& store, bool early_allowed = true, std::span<std::uint8_t const> application_scope = {},
            std::shared_ptr<tls::EchServerKeys const> ech_keys = {})
            -> std::expected<std::unique_ptr<EarlyDataTlsServer>, tls::PskError> {
            if (alpn.empty() || alpn.size() > 255) return std::unexpected(tls::PskError::invalid_input);
            auto scope = detail::resumption_scope(application_scope);
            if (!scope) return std::unexpected(scope.error());
            auto binding = tls::make_server_ticket_binding(credential,
                std::span(reinterpret_cast<std::uint8_t const*>(alpn.data()), alpn.size()), *scope);
            if (!binding) return std::unexpected(binding.error());
            return std::make_unique<EarlyDataTlsServer>(credential, alpn, store, std::move(*binding), early_allowed, std::move(ech_keys));
        }
        [[nodiscard]] static auto create(tls::ServerCredential&& credential, std::string_view alpn,
            Store& store, bool early_allowed = true, std::span<std::uint8_t const> application_scope = {},
            std::shared_ptr<tls::EchServerKeys const> ech_keys = {})
            -> std::expected<std::unique_ptr<EarlyDataTlsServer>, tls::PskError> {
            if (alpn.empty() || alpn.size() > 255) return std::unexpected(tls::PskError::invalid_input);
            auto scope = detail::resumption_scope(application_scope);
            if (!scope) return std::unexpected(scope.error());
            auto binding = tls::make_server_ticket_binding(credential,
                std::span(reinterpret_cast<std::uint8_t const*>(alpn.data()), alpn.size()), *scope);
            if (!binding) return std::unexpected(binding.error());
            return std::make_unique<EarlyDataTlsServer>(std::move(credential), alpn, store, std::move(*binding), early_allowed, std::move(ech_keys));
        }
        [[nodiscard]] static auto create(std::shared_ptr<tls::AtomicServerCredential> const& atomic, std::string_view alpn,
            Store& store, bool early_allowed = true, std::span<std::uint8_t const> application_scope = {},
            std::shared_ptr<tls::EchServerKeys const> ech_keys = {})
            -> std::expected<std::unique_ptr<EarlyDataTlsServer>, tls::PskError> {
            if (!atomic) return std::unexpected(tls::PskError::invalid_input);
            auto cloned = atomic->clone_current();
            if (!cloned) return std::unexpected(tls::PskError::invalid_input);
            return create(std::move(*cloned), alpn, store, early_allowed, application_scope, std::move(ech_keys));
        }

        auto complete() const noexcept -> bool { return state_ == State::complete; }
        auto resumed() const noexcept -> bool { return complete() && recovery_.selected(); }
        auto early_accepted() const noexcept -> bool { return recovery_.accepted_early(); }
        [[nodiscard]] auto ech_accepted() const noexcept -> bool { return ech_.accepted(); }
        [[nodiscard]] auto ech_rejected() const noexcept -> bool { return ech_.rejected_offered(); }
        [[nodiscard]] auto negotiated_sni() const noexcept -> std::string_view { return negotiated_sni_; }
        auto alert() const noexcept -> std::uint8_t { return last_alert_; }
        auto cipher_suite() const noexcept -> std::uint16_t { return cipher_suite_; }
        struct ExporterMaster { crypto::Hash hash; std::span<std::uint8_t const> secret; };
        [[nodiscard]] auto exporter_master() const noexcept -> std::optional<ExporterMaster> {
            return exporter_ ? std::optional(ExporterMaster{cipher_hash_, exporter_->view()}) : std::nullopt;
        }
        auto cancel() noexcept -> void {
            recovery_.cancel(); state_ = State::failed; flight_.reset(); early_flight_.reset();
            application_.reset(); decoder_.reset(); exporter_.reset(); ech_.reset();
            crypto::Bytes{}.swap(first_); crypto::Bytes{}.swap(retry_);
        }
        template<class Connection> auto start(Connection&) -> int { return ngtcp2::err_callback_failure; }
        template<class Connection>
        auto receive(Connection& connection, ngtcp2::ngtcp2_encryption_level level, std::uint64_t,
            std::span<std::uint8_t const> bytes) -> int {
            using namespace ngtcp2;
            try {
                if ((state_ == State::hello || state_ == State::retry_hello) && level == NGTCP2_ENCRYPTION_LEVEL_INITIAL) {
                    if (!decoder_) {
                        auto d = tls::HandshakeDecoder::create(65535);
                        if (!d) return fail(connection, 80);
                        decoder_.emplace(std::move(*d));
                    }
                    auto err = feed_tls_messages(*decoder_, bytes, 1, [&](auto t, auto w) { return initial_message(connection, t, w); });
                    if (err) return state_ == State::failed ? err : fail(connection, 50, err);
                    if (state_ == State::finished) {
                        if (decoder_->pending_bytes()) return fail(connection, 10);
                        auto d = tls::HandshakeDecoder::create(48);
                        if (!d) return fail(connection, 80);
                        decoder_.emplace(std::move(*d));
                    }
                    return 0;
                }
                if (state_ == State::finished && level == NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE) {
                    auto err = feed_tls_messages(*decoder_, bytes, 1, [&](auto t, auto w) { return finished_message(connection, t, w); });
                    if (err) return state_ == State::failed ? err : fail(connection, 50, err);
                    if (state_ == State::completing) {
                        if (decoder_->pending_bytes()) return fail(connection, 10);
                        decoder_.reset(); state_ = State::complete;
                        err = connection.complete_handshake();
                        if (err) return fail(connection, 80, err);
                    }
                    return 0;
                }
                return fail(connection, 10);
            } catch (...) { cancel(); throw; }
        }
        template<class Connection>
        auto issue_early_ticket(Connection& connection, std::uint32_t lifetime = 86400, unsigned count = 1) -> bool {
            if (!complete() || !cipher_suite_ || !count) return false;
            auto issuer = recovery_.take_issuer();
            if (!issuer) return false;
            for (unsigned i = 0; i < count; ++i) {
                auto ticket = issuer->prepare(lifetime);
                if (!ticket) return false;
                auto raw = ticket->body();
                if (raw.size() != 53 || raw[17] != 0 || raw[18] != 32 || raw[51] != 0 || raw[52] != 0) return false;
                std::array<std::uint8_t, 32> id{};
                std::ranges::copy(raw.subspan(19, 32), id.begin());
                crypto::Bytes body(raw.begin(), raw.end());
                if (early_allowed_) {
                    body[51] = 0; body[52] = 8;
                    body.insert(body.end(), {0, 42, 0, 4, 255, 255, 255, 255});
                }
                auto encoded = tls::HandshakeDecoder::encode(4, body);
                if (!encoded) return false;
                if (connection.submit_crypto(ngtcp2::NGTCP2_ENCRYPTION_LEVEL_1RTT, *encoded)) return false;
                if (!ticket->publish(store_, Clock::now())) return false;
                store_.record_suite(id, cipher_suite_);
            }
            return true;
        }
    };
}
