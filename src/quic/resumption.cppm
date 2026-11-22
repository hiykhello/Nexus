export module quic.resumption;
export import quic.tls_client;
export import quic.tls_server;
export import tls.resuming_client;
export import tls.psk_server_policy;
export import tls.server_credential;
export import tls.certificate_trust;
import std;
import nexus.thirdparty.corosio;
import nexus.thirdparty.ngtcp2;
import quic.ech_config;

export namespace quic {
    namespace detail {
        inline auto resumption_scope(std::span<std::uint8_t const> application_scope)
            -> std::expected<std::array<std::uint8_t,32>,tls::PskError> {
            if (application_scope.size()>65535)return std::unexpected(tls::PskError::invalid_input);
            auto digest=crypto::DigestContext::create(crypto::Hash::sha256);if (!digest)return std::unexpected(tls::PskError::crypto_error);
            constexpr std::string_view domain="nexus QUIC 1RTT resumption v1";
            if (!digest->update(std::span(reinterpret_cast<std::uint8_t const*>(domain.data()),domain.size())) || !digest->update(application_scope))
                return std::unexpected(tls::PskError::crypto_error);
            auto hash=digest->snapshot();if (!hash || hash->size()!=32)return std::unexpected(tls::PskError::crypto_error);
            std::array<std::uint8_t,32> result{};std::ranges::copy(*hash,result.begin());return result;
        }
    }
    // The same borrowed immutable PKI snapshot supplies both authentication
    // and ticket binding. Anchors and name bytes outlive the QUIC owner.
    // Includes the IPv6 zone so link-local peers on different interfaces
    // cannot share tickets. Trust, TLS identity and ALPN are bound separately.
    inline auto ticket_peer_scope(nex::corosio::endpoint const& peer) noexcept -> std::array<std::uint8_t,23> {
        std::array<std::uint8_t,23> scope{};
        auto address=peer.address();
        scope[0]=address.is_v4() ? 4 : 6;
        scope[1]=static_cast<std::uint8_t>(peer.port()>>8);
        scope[2]=static_cast<std::uint8_t>(peer.port());
        if (address.is_v4()) std::ranges::copy(address.to_v4().to_bytes(),scope.begin()+3);
        else {
            auto ip=address.to_v6();
            std::ranges::copy(ip.to_bytes(),scope.begin()+3);
            for (unsigned index=0;index<4;++index)
                scope[19+index]=static_cast<std::uint8_t>(ip.scope_id()>>(24-index*8));
        }
        return scope;
    }

    class ResumptionPki {
        std::span<std::span<std::uint8_t const> const> anchors_;
        tls::PeerNameKind kind_;
        std::span<std::uint8_t const> name_;
        std::int64_t verification_time_;
        std::array<std::uint8_t,32> scope_;
    public:
        ResumptionPki(std::span<std::span<std::uint8_t const> const> anchors,tls::PeerNameKind kind,
            std::span<std::uint8_t const> name,std::int64_t time,std::array<std::uint8_t,32> scope) noexcept
            : anchors_(anchors),kind_(kind),name_(name),verification_time_(time),scope_(scope) {}
        auto operator()(std::span<std::span<std::uint8_t const> const> chain) const
            -> std::expected<void,tls::CertificateTrustError> {
            return tls::verify_server_certificate_chain(chain,anchors_,kind_,name_,verification_time_);
        }
        auto resumption_binding(tls::ClientHello const& hello,std::span<std::uint8_t const> alpn) const
            -> std::expected<tls::TicketBinding,tls::PskError> {
            return tls::make_ticket_binding(hello,anchors_,kind_,name_,alpn,scope_);
        }
    };
    template<class Cache,class Clock> class ResumingTlsClient;
    template<class Cache=tls::ResumptionCache<>,class Clock=tls::PskSteadyClock>
    class ClientResumptionSetup {
        friend class ResumingTlsClient<Cache,Clock>;
        using Policy=tls::PskClientPolicy<typename Cache::Ticket,Clock,Cache&>;
        tls::ClientHello hello_;
        std::array<std::uint16_t,2> groups_{};
        std::uint8_t count_;
        ResumptionPki identity_;
        std::string_view alpn_;
        Policy recovery_;
        ClientResumptionSetup(tls::ClientHello&& hello,std::span<std::uint16_t const> groups,ResumptionPki identity,
            std::string_view alpn,Policy&& policy) noexcept
            : hello_(std::move(hello)),count_(static_cast<std::uint8_t>(groups.size())),identity_(identity),alpn_(alpn),recovery_(std::move(policy)) {
            std::ranges::copy(groups,groups_.begin());
        }
    public:
        ClientResumptionSetup(ClientResumptionSetup const&)=delete;
        auto operator=(ClientResumptionSetup const&) -> ClientResumptionSetup& = delete;
        ClientResumptionSetup(ClientResumptionSetup&&) noexcept = default;
        [[nodiscard]] static auto create(tls::ClientHello hello,std::span<std::uint16_t const> groups,
            std::span<std::span<std::uint8_t const> const> anchors,tls::PeerNameKind kind,std::span<std::uint8_t const> name,
            std::int64_t verification_time,std::string_view alpn,Cache& cache,std::span<std::uint8_t const> application_scope={},
                bool early=false)
            -> std::expected<ClientResumptionSetup,tls::PskError> {
            if (groups.size()>2 || alpn.empty() || alpn.size()>255)return std::unexpected(tls::PskError::invalid_input);
            auto scope=detail::resumption_scope(application_scope);if (!scope)return std::unexpected(scope.error());
            ResumptionPki identity(anchors,kind,name,verification_time,*scope);
            auto binding=identity.resumption_binding(hello,std::span(reinterpret_cast<std::uint8_t const*>(alpn.data()),alpn.size()));
            if (!binding)return std::unexpected(binding.error());
            std::inplace_vector<typename Cache::Ticket,8> offers;
            if (auto ticket=cache.take(*binding,hello.cipher_suites,Clock::now()))offers.push_back(std::move(*ticket));
            auto policy=Policy::create(std::move(*binding),std::move(offers),cache);if (!policy)return std::unexpected(policy.error());
            if constexpr(tls::EarlyDataPolicy<Policy>) {
                if (early) policy->permit_early();
            }
            return ClientResumptionSetup(std::move(hello),groups,identity,alpn,std::move(*policy));
        }
    };
    // This enabled owner adds only its necessary material. It inherits the
    // actual shared start/receive algorithm; no forwarding handshake loop.
    template<class Cache=tls::ResumptionCache<>,class Clock=tls::PskSteadyClock>
    class ResumingTlsClient : public TlsClient<ResumptionPki> {
        using Base=TlsClient<ResumptionPki>;
        using Policy=tls::PskClientPolicy<typename Cache::Ticket,Clock,Cache&>;
        Policy recovery_;
    public:
        explicit ResumingTlsClient(ClientResumptionSetup<Cache,Clock>&& setup)
            : Base(std::move(setup.hello_),std::span<std::uint16_t const>(setup.groups_).first(setup.count_),setup.identity_,setup.alpn_),recovery_(std::move(setup.recovery_)) {}
        [[gnu::always_inline]] auto resumption_policy() noexcept -> Policy& {return recovery_;}
        [[nodiscard]] auto resumed() const noexcept -> bool {return Base::complete() && recovery_.complete() && recovery_.selected();}
        auto cancel() noexcept -> void {Base::cancel(recovery_);}
    };
    // Shared by named outbound profiles spanning several worker executors.
    template<class Cache=tls::ResumptionCache<>>
    class SharedResumptionCache {
        std::mutex mutex_;
        Cache cache_;
    public:
        using Ticket=typename Cache::Ticket;

        [[nodiscard]] auto take(tls::TicketBinding const& binding,std::span<std::uint16_t const> suites,
            std::uint64_t now_ms) -> std::optional<Ticket> {
            std::lock_guard lock(mutex_);
            return cache_.take(binding,suites,now_ms);
        }

        template<bool Quic,class... Metadata>
        auto receive(std::span<std::uint8_t const> body,crypto::Hash hash,std::span<std::uint8_t const> master,
            tls::TicketBinding const& binding,std::uint64_t now_ms,Metadata&&... metadata) {
            std::lock_guard lock(mutex_);
            return cache_.template receive<Quic>(body,hash,master,binding,now_ms,std::forward<Metadata>(metadata)...);
        }
    };

    // Select the TLS owner before the first Initial. The ECH dial uses the
    // plain handshake, while eligible dials use the same TLS core with PSK.
    template<class CertificatePolicy,class Cache=tls::ResumptionCache<>>
    class SelectableTlsClient {
        using Plain=TlsClient<CertificatePolicy>;
        using Resuming=ResumingTlsClient<Cache,tls::PskSteadyClock>;
        std::variant<Plain,Resuming> tls_;

    public:
        SelectableTlsClient(tls::ClientHello hello,std::span<std::uint16_t const> groups,CertificatePolicy identity,
            std::string_view alpn)
            :tls_(std::in_place_type<Plain>,std::move(hello),groups,std::move(identity),alpn) {}
        explicit SelectableTlsClient(ClientResumptionSetup<Cache>&& setup)
            :tls_(std::in_place_type<Resuming>,std::move(setup)) {}

        auto enable_ech(this SelectableTlsClient& self,EchConfig const& config) -> bool {
            auto* plain=std::get_if<Plain>(&self.tls_);
            return plain && plain->enable_ech(config);
        }
        [[nodiscard]] auto complete(this SelectableTlsClient const& self) noexcept -> bool {
            return std::visit([](auto const& tls) {return tls.complete();},self.tls_);
        }
        using ExporterMaster=typename Plain::ExporterMaster;
        [[nodiscard]] auto exporter_master(this SelectableTlsClient const& self) noexcept -> std::optional<ExporterMaster> {
            return std::visit([](auto const& tls) -> std::optional<ExporterMaster> {
                auto value=tls.exporter_master();
                if (!value) return std::nullopt;
                return ExporterMaster{value->hash,value->secret};
            },self.tls_);
        }
        auto cancel(this SelectableTlsClient& self) noexcept -> void {
            std::visit([](auto& tls) noexcept {tls.cancel();},self.tls_);
        }
        template<class Connection>
        auto start(this SelectableTlsClient& self,Connection& connection) -> int {
            return std::visit([&](auto& tls) {
                if constexpr (requires {tls.resumption_policy();})
                    return tls.start(connection,tls.resumption_policy());
                else return tls.start(connection);
            },self.tls_);
        }
        template<class Connection>
        auto receive(this SelectableTlsClient& self,Connection& connection,nex::ngtcp2::ngtcp2_encryption_level level,
            std::uint64_t offset,std::span<std::uint8_t const> bytes) -> int {
            return std::visit([&](auto& tls) {
                if constexpr (requires {tls.resumption_policy();})
                    return tls.receive(connection,level,offset,bytes,tls.resumption_policy());
                else return tls.receive(connection,level,offset,bytes);
            },self.tls_);
        }
    };
    template<class Store,class Clock> class ResumingTlsServer;
    template<class Store=tls::ServerTicketStore<>,class Clock=tls::PskSteadyClock>
    class ServerResumptionSetup {
        friend class ResumingTlsServer<Store,Clock>;
        tls::ServerCredential const& credential_;
        std::string_view alpn_;
        tls::PskServerPolicy<Store,Clock> recovery_;
        ServerResumptionSetup(tls::ServerCredential const& credential,std::string_view alpn,tls::PskServerPolicy<Store,Clock>&& recovery) noexcept
            : credential_(credential),alpn_(alpn),recovery_(std::move(recovery)) {}
    public:
        ServerResumptionSetup(ServerResumptionSetup const&)=delete;
        auto operator=(ServerResumptionSetup const&) -> ServerResumptionSetup& = delete;
        ServerResumptionSetup(ServerResumptionSetup&&) noexcept = default;
        [[nodiscard]] static auto create(tls::ServerCredential const& credential,std::string_view alpn,Store& store,
            std::span<std::uint8_t const> application_scope={}) -> std::expected<ServerResumptionSetup,tls::PskError> {
            if (alpn.empty() || alpn.size()>255)return std::unexpected(tls::PskError::invalid_input);
            auto scope=detail::resumption_scope(application_scope);if (!scope)return std::unexpected(scope.error());
            auto binding=tls::make_server_ticket_binding(credential,std::span(reinterpret_cast<std::uint8_t const*>(alpn.data()),alpn.size()),*scope);
            if (!binding)return std::unexpected(binding.error());
            return ServerResumptionSetup(credential,alpn,tls::PskServerPolicy<Store,Clock>(store,std::move(*binding)));
        }
    };
    template<class Store=tls::ServerTicketStore<>,class Clock=tls::PskSteadyClock>
    class ResumingTlsServer : public TlsServer {
        tls::PskServerPolicy<Store,Clock> recovery_;
    public:
        explicit ResumingTlsServer(ServerResumptionSetup<Store,Clock>&& setup)
            : TlsServer(setup.credential_,setup.alpn_),recovery_(std::move(setup.recovery_)) {}
        [[gnu::always_inline]] auto resumption_policy() noexcept -> tls::PskServerPolicy<Store,Clock>& {return recovery_;}
        [[nodiscard]] auto resumed() const noexcept -> bool {return TlsServer::complete() && recovery_.selected();}
        auto cancel() noexcept -> void {TlsServer::cancel(recovery_);}
        [[nodiscard]] auto take_issuer() -> std::expected<tls::ServerTicketIssuer<Store,Clock>,tls::PskError> {
            if (!TlsServer::complete())return std::unexpected(tls::PskError::invalid_state);return recovery_.take_issuer();
        }
    };
}
