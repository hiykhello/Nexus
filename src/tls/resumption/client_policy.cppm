export module tls.psk_client_policy;
export import tls.psk;
import tls.server_hello;
import tls.certificate_trust;
import std;
import nexus.compat;

export namespace tls {
    // Compute once for an immutable trust/profile snapshot. Application scope
    // distinguishes explicit configuration generations or logical services.
    // ALPN is matched separately against the ticket's authenticated selection.
    [[nodiscard]] inline auto make_ticket_binding(ClientHello const& hello,std::span<std::span<std::uint8_t const> const> anchors,
        PeerNameKind kind,std::span<std::uint8_t const> name,std::span<std::uint8_t const> alpn={},
        std::span<std::uint8_t const> application_scope={}) -> std::expected<TicketBinding,PskError> {
        if (anchors.empty() || anchors.size()>1024 || name.empty() || name.size()>253 || alpn.size()>255 || application_scope.size()>65535 ||
            (kind!=PeerNameKind::dns && kind!=PeerNameKind::ip) || (kind==PeerNameKind::ip && name.size()!=4 && name.size()!=16))
            return std::unexpected(PskError::invalid_input);
        auto digest=crypto::DigestContext::create(crypto::Hash::sha256);if (!digest) return std::unexpected(PskError::crypto_error);
        auto add=[&](std::span<std::uint8_t const> bytes) {
            std::array<std::uint8_t,8> size{};auto n=bytes.size();
            for (std::size_t i=0;i<8;++i)size[7-i]=static_cast<std::uint8_t>(n>>(i*8));
            return digest->update(size).has_value() && digest->update(bytes).has_value();
        };
        constexpr std::array<std::uint8_t,20> domain{'n','e','x','u','s',' ','t','l','s',' ','r','e','c','o','v','e','r','y',' ','1'};
        std::array<std::uint8_t,1> encoded_kind{static_cast<std::uint8_t>(kind)};
        auto* sni=hello.extension(0);auto sni_bytes=sni ? std::span<std::uint8_t const>(sni->data) : std::span<std::uint8_t const>{};
        if (!add(domain) || !add(encoded_kind) || !add(name) || !add(sni_bytes) || !add(application_scope)) return std::unexpected(PskError::crypto_error);
        std::size_t total=0;
        for (auto anchor:anchors) {
            if (anchor.empty() || anchor.size()>1048576 || anchor.size()>4194304-total) return std::unexpected(PskError::invalid_input);
            total+=anchor.size();if (!add(anchor)) return std::unexpected(PskError::crypto_error);
        }
        auto hash=digest->snapshot();if (!hash || hash->size()!=32)return std::unexpected(PskError::crypto_error);
        TicketBinding result{std::string(reinterpret_cast<char const*>(name.data()),name.size()),crypto::Bytes(alpn.begin(),alpn.end()),{}};
        std::ranges::copy(*hash,result.authentication_context.begin());result.server_name_extension.assign(sni_bytes.begin(),sni_bytes.end());return result;
    }
    class ResumptionReceiver {
        TicketBinding binding_;
        Secret master_;
        crypto::Hash hash_;
    public:
        ResumptionReceiver(TicketBinding binding,Secret&& master,crypto::Hash hash) noexcept
            : binding_(std::move(binding)),master_(std::move(master)),hash_(hash) {}
        ResumptionReceiver(ResumptionReceiver const&)=delete;
        auto operator=(ResumptionReceiver const&) -> ResumptionReceiver& = delete;
        ResumptionReceiver(ResumptionReceiver&&) noexcept = default;
        auto operator=(ResumptionReceiver&&) noexcept -> ResumptionReceiver& = default;
        template<std::size_t Capacity>
        auto ticket(std::span<std::uint8_t const> body,ResumptionCache<Capacity>& cache,std::uint64_t now_ms)
            -> std::expected<bool,PskError> {
            return cache.receive(body,hash_,master_.view(),binding_,now_ms);
        }
    };
    // Owns only the material required by an enabled recovery attempt. Every
    // algorithm below is passed this concrete policy by reference; ordinary
    // owners contain no pointer, optional, callback or reference to it.
    struct NoTicketCache {};
    template<class Offer=ResumptionTicket,class Clock=PskSteadyClock,class TicketCache=NoTicketCache>
    class PskClientPolicy {
        enum class State { initial,offered,keys,master,derived,complete,taken,failed } state_=State::initial;
        TicketBinding binding_;
        nexus::inplace_vector<Offer,8> offered_;
        std::optional<Secret> master_,resumption_;
        crypto::Hash hash_=crypto::Hash::sha256;
        std::uint64_t offered_ms_=0;
        bool selected_=false;
        struct EarlyState {
            bool enabled=false,offered=false;
            std::uint16_t suite=0;
        };
        static constexpr bool early_capable=requires(Offer const& offer) {
            offer.parameters();
            offer.suite();
        };
        [[no_unique_address]] std::conditional_t<early_capable,EarlyState,NoPsk> early_;
        [[no_unique_address]] TicketCache cache_;
        PskClientPolicy(TicketBinding&& binding,nexus::inplace_vector<Offer,8>&& offers) noexcept
            requires std::same_as<TicketCache,NoTicketCache>
            : binding_(std::move(binding)),offered_(std::move(offers)) {}
        PskClientPolicy(TicketBinding&& binding,nexus::inplace_vector<Offer,8>&& offers,TicketCache cache) noexcept
            requires (!std::same_as<TicketCache,NoTicketCache>)
            : binding_(std::move(binding)),offered_(std::move(offers)),cache_(cache) {}
        auto views() const -> std::expected<nexus::inplace_vector<PskOfferView,8>,PskError> {
            nexus::inplace_vector<PskOfferView,8> result;
            for (auto const& value:offered_) {
                auto view=value.offer(offered_ms_);if (!view) return std::unexpected(view.error());result.push_back(*view);
            }
            return result;
        }
    public:
        static constexpr bool enabled=true;
        static constexpr bool early_data=early_capable;
        static constexpr bool ticket_resumption=Offer::kind==PskKind::resumption;
        static constexpr auto local_error(PskError error) noexcept -> bool {return error==PskError::crypto_error;}
        static constexpr auto transport_error(PskError error) noexcept -> bool {return error==PskError::protocol_violation;}
        PskClientPolicy(PskClientPolicy const&)=delete;
        auto operator=(PskClientPolicy const&) -> PskClientPolicy& = delete;
        PskClientPolicy(PskClientPolicy&& other) noexcept
            : state_(std::exchange(other.state_,State::failed)),binding_(std::move(other.binding_)),offered_(std::move(other.offered_)),master_(std::move(other.master_)),
              resumption_(std::move(other.resumption_)),hash_(other.hash_),offered_ms_(other.offered_ms_),selected_(other.selected_),early_(other.early_),cache_(other.cache_) {}
        auto operator=(PskClientPolicy&& other) noexcept -> PskClientPolicy& requires std::same_as<TicketCache,NoTicketCache> {
            if (this!=&other) {cancel();state_=std::exchange(other.state_,State::failed);binding_=std::move(other.binding_);offered_=std::move(other.offered_);
                master_=std::move(other.master_);resumption_=std::move(other.resumption_);hash_=other.hash_;offered_ms_=other.offered_ms_;selected_=other.selected_;}
            return *this;
        }
        template<class... CacheArgument>
        [[nodiscard]] static auto create(TicketBinding binding,nexus::inplace_vector<Offer,8> offers={},CacheArgument&... cache) -> std::expected<PskClientPolicy,PskError> {
            if (binding.server_name.empty() || binding.server_name.size()>253 || binding.alpn.size()>255) return std::unexpected(PskError::invalid_input);
            for (auto const& offer:offers) if (offer.binding()!=binding) return std::unexpected(PskError::identity_mismatch);
            return PskClientPolicy(std::move(binding),std::move(offers),cache...);
        }
        auto cancel() noexcept -> void {offered_.clear();master_.reset();resumption_.reset();state_=State::failed;selected_=false;}
        auto permit_early() noexcept -> void requires early_capable { early_.enabled=true; }
        [[nodiscard]] auto offered_early() const noexcept -> bool requires early_capable { return early_.offered; }
        [[nodiscard]] auto early_suite() const noexcept -> std::uint16_t requires early_capable { return early_.suite; }
        [[nodiscard]] auto early_parameters() const noexcept -> std::span<std::uint8_t const> requires early_capable {
            return offered_.front().parameters();
        }
        [[nodiscard]] auto early_traffic(std::span<std::uint8_t const> wire) const
            -> std::expected<Secret,PskError> requires early_capable {
            auto const& ticket=offered_.front();
            auto value=ticket.offer(offered_ms_);
            if (!value) return std::unexpected(value.error());
            auto transcript=crypto::digest(ticket.hash(),wire);
            auto secret=early_secret(ticket.hash(),value->secret);
            if (!transcript || !secret) return std::unexpected(PskError::crypto_error);
            auto traffic=derive_secret(ticket.hash(),secret->view(),"c e traffic",*transcript);
            if (!traffic) return std::unexpected(PskError::crypto_error);
            return std::move(*traffic);
        }
        [[nodiscard]] auto selected() const noexcept -> bool {return selected_;}
        [[nodiscard]] auto binding() const noexcept -> TicketBinding const& {return binding_;}
        [[nodiscard]] auto complete() const noexcept -> bool {return state_==State::complete;}
        auto prepare(ClientHello& hello) -> std::expected<void,PskError> {
            if (state_!=State::initial) return std::unexpected(PskError::invalid_state);
            offered_ms_=Clock::now();
            nexus::erase_if(offered_,[&](auto const& value) {return !value.usable(offered_ms_) ||
                !std::ranges::any_of(hello.cipher_suites,[&](auto suite){return psk_cipher_hash(suite)==value.hash();});});
            auto values=views();if (!values) return std::unexpected(values.error());
            bool early=false;
            if constexpr(early_capable) {
                if (early_.enabled && offered_.size()==1) {
                    auto const& ticket=offered_.front();
                    early=ticket.max_early_data()==0xffffffffu && !ticket.parameters().empty() &&
                        std::ranges::contains(hello.cipher_suites,ticket.suite());
                    if (early) {
                        early_.offered=true;
                        early_.suite=ticket.suite();
                    }
                }
            }
            auto result=prepare_psk_hello(hello,*values,early);
            if (result) state_=State::offered;
            return result;
        }
        auto retry(ClientHello& hello,std::uint16_t suite) -> std::expected<void,PskError> {
            if (state_!=State::offered) return std::unexpected(PskError::invalid_state);
            auto hash=psk_cipher_hash(suite);if (!hash) return std::unexpected(PskError::invalid_selection);
            offered_ms_=Clock::now();
            nexus::erase_if(offered_,[&](auto const& value) {return value.hash()!=*hash || !value.usable(offered_ms_);});
            std::erase_if(hello.extensions,[](auto const& extension) {return extension.type==41;});
            auto values=views();if (!values) return std::unexpected(values.error());return prepare_psk_hello(hello,*values);
        }
        auto seal(ClientHello& hello,crypto::Bytes& wire,std::span<std::uint8_t const> first={},std::span<std::uint8_t const> retry={})
            -> std::expected<void,PskError> {
            if (state_!=State::offered) return std::unexpected(PskError::invalid_state);
            auto values=views();if (!values) return std::unexpected(values.error());return seal_psk_binders(hello,wire,*values,first,retry);
        }
        auto select(ClientHello const& client,ServerHello const& server) -> std::expected<std::optional<std::span<std::uint8_t const>>,PskError> {
            if (state_!=State::offered) return std::unexpected(PskError::invalid_state);
            auto hash=psk_cipher_hash(server.cipher_suite);if (!hash) return std::unexpected(PskError::invalid_selection);hash_=*hash;
            auto selected=std::ranges::find(server.extensions,std::uint16_t{41},&Extension::type);
            if (selected==server.extensions.end()) {selected_=false;state_=State::keys;return std::optional<std::span<std::uint8_t const>>{};}
            auto* extension=client.extension(41);
            if (!extension || client.extensions.back().type!=41 || selected->data.size()!=2) return std::unexpected(PskError::invalid_selection);
            auto index=(std::size_t{selected->data[0]}<<8)|selected->data[1];auto encoded=parse_client_psks(extension->data);auto values=views();
            if (!encoded || !values || encoded->entries.size()!=values->size() || index>=values->size()) return std::unexpected(PskError::invalid_selection);
            for (std::size_t i=0;i<values->size();++i) {
                auto const& offer=(*values)[i];auto const& wire=encoded->entries[i];
                if (!std::ranges::equal(wire.identity,offer.identity) || wire.obfuscated_age!=offer.obfuscated_age || wire.binder.size()!=psk_hash_size(offer.hash))
                    return std::unexpected(PskError::invalid_offer);
            }
            auto const& offer=(*values)[index];if (offer.hash!=*hash) return std::unexpected(PskError::invalid_selection);
            selected_=true;state_=State::keys;return std::optional<std::span<std::uint8_t const>>(offer.secret);
        }
        auto offer_consumed() noexcept -> void {offered_.clear();}
        auto extensions(std::span<std::uint8_t const> alpn) -> std::expected<void,PskError> {
            if (state_!=State::keys || (selected_ && !std::ranges::equal(alpn,binding_.alpn))) return std::unexpected(PskError::identity_mismatch);
            if (!selected_) binding_.alpn.assign(alpn.begin(),alpn.end());return {};
        }
        auto retain_master(Secret&& master,crypto::Hash hash) -> std::expected<void,PskError> {
            if (state_!=State::keys || hash!=hash_ || master.view().size()!=psk_hash_size(hash)) return std::unexpected(PskError::invalid_state);
            master_.emplace(std::move(master));state_=State::master;return {};
        }
        auto client_finished(std::span<std::uint8_t const> transcript_hash) -> std::expected<void,PskError> {
            if (state_!=State::master || !master_ || transcript_hash.size()!=psk_hash_size(hash_)) return std::unexpected(PskError::invalid_state);
            auto secret=derive_secret(hash_,master_->view(),"res master",transcript_hash);master_.reset();
            if (!secret) {cancel();return std::unexpected(PskError::crypto_error);}
            resumption_.emplace(std::move(*secret));state_=State::derived;return {};
        }
        auto finished_sent() -> std::expected<void,PskError> {
            if (state_!=State::derived || !resumption_) return std::unexpected(PskError::invalid_state);state_=State::complete;return {};
        }
        template<class... Metadata>
        auto ticket(std::span<std::uint8_t const> body,Metadata&&... metadata) -> std::expected<bool,PskError>
            requires (!std::same_as<TicketCache,NoTicketCache>) {
            if (state_!=State::complete || !resumption_) return std::unexpected(PskError::invalid_state);
            return cache_.template receive<true>(body,hash_,resumption_->view(),binding_,Clock::now(),std::forward<Metadata>(metadata)...);
        }
        [[nodiscard]] auto take_receiver() -> std::expected<ResumptionReceiver,PskError> {
            if (state_!=State::complete || !resumption_) return std::unexpected(PskError::invalid_state);
            ResumptionReceiver result(std::move(binding_),std::move(*resumption_),hash_);resumption_.reset();state_=State::taken;return result;
        }
    };
}
