export module tls.psk;
export import tls.schedule;
export import tls.resumption_policy;
import tls.hello;
import tls.transcript;
import tls.post_handshake;
import std;
import containers.inplace_vector;

export namespace tls {
    enum class PskError { invalid_state,invalid_input,invalid_offer,invalid_selection,expired,identity_mismatch,crypto_error,protocol_violation };
    enum class PskKind : std::uint8_t { resumption,external };
    struct PskOfferView {
        std::span<std::uint8_t const> identity,secret;
        crypto::Hash hash=crypto::Hash::sha256;
        PskKind kind=PskKind::resumption;
        std::uint32_t obfuscated_age=0;
    };
    struct ClientPskWireOffer {
        std::span<std::uint8_t const> identity,binder;
        std::uint32_t obfuscated_age=0;
    };
    struct ClientPskWireOffers {
        containers::inplace_vector<ClientPskWireOffer,8> entries;
        std::size_t prefix_size=0;
    };
    // All spans borrow one complete pre_shared_key extension. This parser is
    // shared by binder sealing and authenticated identity selection.
    [[nodiscard]] auto parse_client_psks(std::span<std::uint8_t const> extension)
        -> std::expected<ClientPskWireOffers,PskError>;
    struct TicketBinding {
        std::string server_name;
        crypto::Bytes alpn;
        std::array<std::uint8_t,32> authentication_context{};
        crypto::Bytes server_name_extension;
        auto operator==(TicketBinding const&) const -> bool = default;
    };
    [[nodiscard]] auto psk_hash_size(crypto::Hash hash) noexcept -> std::size_t;
    [[nodiscard]] auto psk_cipher_hash(std::uint16_t suite) noexcept -> std::optional<crypto::Hash>;
    // The caller supplies a complete framed Hello whose binder bytes have
    // their final lengths. first/retry are both present only for Hello2.
    [[nodiscard]] auto psk_binder(PskOfferView offer,std::span<std::uint8_t const> truncated_hello,
        std::span<std::uint8_t const> first={},std::span<std::uint8_t const> retry={}) -> std::expected<Secret,PskError>;
    [[nodiscard]] auto prepare_psk_hello(ClientHello& hello,std::span<PskOfferView const> offers,bool early_data=false)
        -> std::expected<void,PskError>;
    [[nodiscard]] auto seal_psk_binders(ClientHello& hello,crypto::Bytes& framed_hello,std::span<PskOfferView const> offers,
        std::span<std::uint8_t const> first={},std::span<std::uint8_t const> retry={}) -> std::expected<void,PskError>;
    // Owning secret material exists only for a caller that enables recovery.
    class ResumptionTicket {
        Secret secret_;
        crypto::Bytes identity_;
        TicketBinding binding_;
        crypto::Hash hash_;
        std::uint64_t received_ms_;
        std::uint32_t lifetime_,age_add_,max_early_data_;
        ResumptionTicket(Secret&&,crypto::Bytes&&,TicketBinding&&,crypto::Hash,std::uint64_t,std::uint32_t,std::uint32_t,std::uint32_t) noexcept;
    public:
        static constexpr auto kind=PskKind::resumption;
        ResumptionTicket(ResumptionTicket const&)=delete;
        auto operator=(ResumptionTicket const&) -> ResumptionTicket& = delete;
        ResumptionTicket(ResumptionTicket&&) noexcept = default;
        auto operator=(ResumptionTicket&&) noexcept -> ResumptionTicket& = default;
        template<bool Quic=false>
        [[nodiscard]] static auto from_message(std::span<std::uint8_t const> body,crypto::Hash hash,std::span<std::uint8_t const> master,
        TicketBinding binding,std::uint64_t now) -> std::expected<ResumptionTicket,PskError> {
        auto size=psk_hash_size(hash);auto parsed=parse_new_session_ticket(body);
        if (!parsed || !size || master.size()!=size || binding.server_name.empty() || binding.server_name.size()>253 || binding.alpn.size()>255)
            return std::unexpected(PskError::invalid_input);
        if constexpr(Quic) if (parsed->early_data && parsed->max_early_data!=0xffffffffu)return std::unexpected(PskError::protocol_violation);
        if (!parsed->lifetime) return std::unexpected(PskError::expired);
        auto secret=expand_label(hash,master,"resumption",parsed->nonce,size);
        if (!secret) return std::unexpected(PskError::crypto_error);
        return ResumptionTicket(std::move(*secret),crypto::Bytes(parsed->ticket.begin(),parsed->ticket.end()),std::move(binding),hash,now,
            std::min(parsed->lifetime,std::uint32_t{604800}),parsed->age_add,parsed->max_early_data);
    }
        [[nodiscard]] auto binding() const noexcept -> TicketBinding const& { return binding_; }
        [[nodiscard]] auto hash() const noexcept -> crypto::Hash { return hash_; }
        [[nodiscard]] auto usable(std::uint64_t now_ms) const noexcept -> bool;
        [[nodiscard]] auto offer(std::uint64_t now_ms) const noexcept -> std::expected<PskOfferView,PskError>;
        [[nodiscard]] auto max_early_data() const noexcept -> std::uint32_t { return max_early_data_; }
    };
    class ExternalPsk {
        Secret secret_;
        crypto::Bytes identity_;
        TicketBinding binding_;
        crypto::Hash hash_;
        ExternalPsk(Secret&& secret,crypto::Bytes&& identity,TicketBinding&& binding,crypto::Hash hash) noexcept
            : secret_(std::move(secret)),identity_(std::move(identity)),binding_(std::move(binding)),hash_(hash) {}
    public:
        static constexpr auto kind=PskKind::external;
        ExternalPsk(ExternalPsk const&)=delete;
        auto operator=(ExternalPsk const&) -> ExternalPsk& = delete;
        ExternalPsk(ExternalPsk&&) noexcept = default;
        auto operator=(ExternalPsk&&) noexcept -> ExternalPsk& = default;
        [[nodiscard]] static auto create(Secret&& secret,crypto::Bytes identity,TicketBinding binding,crypto::Hash hash)
            -> std::expected<ExternalPsk,PskError> {
            if (!psk_hash_size(hash) || secret.view().empty() || secret.view().size()>65535 || identity.empty() || identity.size()>65529)
                return std::unexpected(PskError::invalid_input);
            return ExternalPsk(std::move(secret),std::move(identity),std::move(binding),hash);
        }
        [[nodiscard]] auto binding() const noexcept -> TicketBinding const& { return binding_; }
        [[nodiscard]] auto hash() const noexcept -> crypto::Hash { return hash_; }
        [[nodiscard]] auto usable(std::uint64_t) const noexcept -> bool { return !identity_.empty() && !secret_.view().empty(); }
        [[nodiscard]] auto offer(std::uint64_t now) const noexcept -> std::expected<PskOfferView,PskError> {
            if (!usable(now)) return std::unexpected(PskError::invalid_state);
            return PskOfferView{identity_,secret_.view(),hash_,PskKind::external,0};
        }
    };
    // A caller-owned bounded cache. Taking a ticket transfers its secret to
    // one attempt; successful ticket renewal is published explicitly later.
    template<std::size_t Capacity=8,class Entry=ResumptionTicket>
    class ResumptionCache {
        static_assert(Capacity>0 && Capacity<=64);
        containers::inplace_vector<Entry,Capacity> tickets_;
    public:
        using Ticket=Entry;
        [[nodiscard]] auto size() const noexcept -> std::size_t { return tickets_.size(); }
        auto clear() noexcept -> void { tickets_.clear(); }
        auto insert(Entry&& ticket,std::uint64_t now_ms) -> void {
            containers::erase_if(tickets_,[&](auto const& entry) { return !entry.usable(now_ms); });
            if (!ticket.usable(now_ms)) return;
            if (tickets_.size()==Capacity) tickets_.erase(tickets_.begin());
            tickets_.push_back(std::move(ticket));
        }
        // Admission and nonce-based PSK derivation are shared by TLS records
        // and QUIC CRYPTO; both hand over authenticated ticket message bodies.
        template<bool Quic=false,class... Metadata>
        auto receive(std::span<std::uint8_t const> body,crypto::Hash hash,std::span<std::uint8_t const> master,
            TicketBinding const& binding,std::uint64_t now_ms,Metadata&&... metadata) -> std::expected<bool,PskError> {
            auto ticket=Entry::template from_message<Quic>(body,hash,master,binding,now_ms,
                std::forward<Metadata>(metadata)...);
            if (!ticket) {
                if (ticket.error()==PskError::expired) return false;
                return std::unexpected(ticket.error());
            }
            insert(std::move(*ticket),now_ms);return true;
        }
        [[nodiscard]] auto take(TicketBinding const& binding,std::span<std::uint16_t const> offered_suites,std::uint64_t now_ms)
            -> std::optional<Entry> {
            containers::erase_if(tickets_,[&](auto const& entry) { return !entry.usable(now_ms); });
            for (std::size_t i=tickets_.size();i>0;--i) {
                auto& entry=tickets_[i-1];
                if (entry.binding()!=binding || !std::ranges::any_of(offered_suites,[&](auto suite) { return psk_cipher_hash(suite)==entry.hash(); })) continue;
                auto result=std::move(entry);tickets_.erase(tickets_.begin()+static_cast<std::ptrdiff_t>(i-1));return result;
            }
            return {};
        }
    };
}
