export module tls.psk_server_policy;
export import tls.psk;
import tls.server_credential;
import tls.hello;
import std;

export namespace tls {
    struct ServerTicketBinding {
        crypto::Bytes sni,alpn;
        std::array<std::uint8_t,32> credential_context{};
        auto operator==(ServerTicketBinding const&) const -> bool = default;
    };
    [[nodiscard]] inline auto make_server_ticket_binding(ServerCredential const& credential,std::span<std::uint8_t const> alpn,
        std::span<std::uint8_t const> application_scope={}) -> std::expected<ServerTicketBinding,PskError> {
        if (credential.certificate().empty() || alpn.size()>255 || application_scope.size()>65535) return std::unexpected(PskError::invalid_input);
        auto digest=crypto::DigestContext::create(crypto::Hash::sha256);if (!digest)return std::unexpected(PskError::crypto_error);
        auto append=[&](std::span<std::uint8_t const> bytes) {
            std::array<std::uint8_t,8> size{};for(std::size_t i=0;i<8;++i)size[7-i]=static_cast<std::uint8_t>(bytes.size()>>(8*i));
            return digest->update(size).has_value() && digest->update(bytes).has_value();
        };
        constexpr std::array<std::uint8_t,18> domain{'n','e','x','u','s',' ','t','l','s',' ','s','e','r','v','e','r',' ','1'};
        if (!append(domain) || !append(application_scope) || !append(credential.certificate())) return std::unexpected(PskError::crypto_error);
        for(auto const& certificate:credential.chain())if (!append(certificate))return std::unexpected(PskError::crypto_error);
        auto hash=digest->snapshot();if (!hash || hash->size()!=32)return std::unexpected(PskError::crypto_error);
        ServerTicketBinding result{{},crypto::Bytes(alpn.begin(),alpn.end()),{}};std::ranges::copy(*hash,result.credential_context.begin());return result;
    }
    struct ServerTicketEntry {
        Secret secret;
        std::array<std::uint8_t,32> identity;
        ServerTicketBinding binding;
        crypto::Hash hash;
        std::uint64_t created_ms;
        std::uint32_t lifetime;
        [[nodiscard]] auto usable(std::uint64_t now) const noexcept -> bool {
            return lifetime && lifetime<=604800 && now>=created_ms && now-created_ms<std::uint64_t{lifetime}*1000 && secret.view().size()==psk_hash_size(hash);
        }
    };
    // One executor owns a store and all policies borrowing it. No global cache
    // or implicit cross-thread synchronization is introduced by TLS owners.
    template<std::size_t Capacity=64>
    class ServerTicketStore {
        static_assert(Capacity>0 && Capacity<=1024);
        std::inplace_vector<ServerTicketEntry,Capacity> entries_;
    public:
        [[nodiscard]] auto size() const noexcept -> std::size_t {return entries_.size();}
        auto clear() noexcept -> void {entries_.clear();}
        [[nodiscard]] auto contains(std::span<std::uint8_t const> identity) const noexcept -> bool {
            return std::ranges::any_of(entries_,[&](auto const& entry){return std::ranges::equal(identity,entry.identity);});
        }
        [[nodiscard]] auto find(std::span<std::uint8_t const> identity,ServerTicketBinding const& binding,crypto::Hash hash,std::uint64_t now)
            -> std::optional<PskOfferView> {
            std::erase_if(entries_,[&](auto const& entry){return !entry.usable(now);});
            for(auto const& entry:entries_)if (entry.hash==hash && entry.binding==binding && std::ranges::equal(identity,entry.identity))
                return PskOfferView{entry.identity,entry.secret.view(),entry.hash,PskKind::resumption,0};
            return {};
        }
        [[nodiscard]] auto publish(ServerTicketEntry&& entry,std::uint64_t now) -> bool {
            std::erase_if(entries_,[&](auto const& value){return !value.usable(now);});
            if (!entry.usable(now) || contains(entry.identity)) return false;
            if (entries_.size()==Capacity)entries_.erase(entries_.begin());
            entries_.push_back(std::move(entry));return true;
        }
    };
    class PendingServerTicket {
        crypto::Bytes body_;
        std::optional<ServerTicketEntry> entry_;
    public:
        PendingServerTicket(crypto::Bytes body,ServerTicketEntry&& entry) noexcept : body_(std::move(body)),entry_(std::move(entry)) {}
        PendingServerTicket(PendingServerTicket const&)=delete;
        auto operator=(PendingServerTicket const&) -> PendingServerTicket& = delete;
        PendingServerTicket(PendingServerTicket&&) noexcept = default;
        auto operator=(PendingServerTicket&&) noexcept -> PendingServerTicket& = default;
        [[nodiscard]] auto body() const noexcept -> std::span<std::uint8_t const> {return entry_ ? std::span<std::uint8_t const>(body_) : std::span<std::uint8_t const>{};}
        // Call only after the complete authenticated ticket record is sent.
        template<class Store>
        [[nodiscard]] auto publish(Store& store,std::uint64_t now) -> bool {
            if (!entry_)return false;
            auto entry=std::move(*entry_);entry_.reset();body_.clear();return store.publish(std::move(entry),now);
        }
    };
    template<class Store=ServerTicketStore<>,class Clock=PskSteadyClock>
    class ServerTicketIssuer {
        Store& store_;
        ServerTicketBinding binding_;
        Secret master_;
        crypto::Hash hash_;
        std::uint64_t nonce_=0;
    public:
        ServerTicketIssuer(Store& store,ServerTicketBinding binding,Secret&& master,crypto::Hash hash) noexcept
            : store_(store),binding_(std::move(binding)),master_(std::move(master)),hash_(hash) {}
        ServerTicketIssuer(ServerTicketIssuer const&)=delete;
        auto operator=(ServerTicketIssuer const&) -> ServerTicketIssuer& = delete;
        ServerTicketIssuer(ServerTicketIssuer&&) noexcept = default;
        [[nodiscard]] auto prepare(std::uint32_t lifetime=86400) -> std::expected<PendingServerTicket,PskError> {
            if (!lifetime || lifetime>604800 || nonce_==std::numeric_limits<std::uint64_t>::max() || master_.view().size()!=psk_hash_size(hash_))
                return std::unexpected(PskError::invalid_state);
            std::array<std::uint8_t,32> identity{};std::array<std::uint8_t,4> age{};bool unique=false;
            for(unsigned attempt=0;attempt<32;++attempt) {
                if (!crypto::random_bytes(identity))return std::unexpected(PskError::crypto_error);
                if (!store_.contains(identity)){unique=true;break;}
            }
            if (!unique || !crypto::random_bytes(age))return std::unexpected(PskError::crypto_error);
            std::array<std::uint8_t,8> nonce{};for(std::size_t i=0;i<8;++i)nonce[7-i]=static_cast<std::uint8_t>(nonce_>>(8*i));
            auto secret=expand_label(hash_,master_.view(),"resumption",nonce,psk_hash_size(hash_));if (!secret)return std::unexpected(PskError::crypto_error);
            ++nonce_;
            crypto::Bytes body;body.reserve(53);
            for(int shift:{24,16,8,0})body.push_back(static_cast<std::uint8_t>(lifetime>>shift));
            body.insert(body.end(),age.begin(),age.end());body.push_back(nonce.size());body.insert(body.end(),nonce.begin(),nonce.end());
            body.push_back(0);body.push_back(identity.size());body.insert(body.end(),identity.begin(),identity.end());body.insert(body.end(),{0,0});
            return PendingServerTicket(std::move(body),ServerTicketEntry{std::move(*secret),identity,binding_,hash_,Clock::now(),lifetime});
        }
    };
    template<class Store=ServerTicketStore<>,class Clock=PskSteadyClock>
    class PskServerPolicy {
        enum class State { initial,keys,master,complete,taken,failed } state_=State::initial;
        Store& store_;
        ServerTicketBinding binding_;
        std::optional<Secret> master_,resumption_;
        crypto::Hash hash_=crypto::Hash::sha256;
        std::optional<std::uint16_t> selected_;
    public:
        static constexpr bool enabled=true;
        static constexpr auto local_error(PskError error) noexcept -> bool {return error==PskError::crypto_error;}
        PskServerPolicy(Store& store,ServerTicketBinding binding) noexcept : store_(store),binding_(std::move(binding)) {}
        PskServerPolicy(PskServerPolicy const&)=delete;
        auto operator=(PskServerPolicy const&) -> PskServerPolicy& = delete;
        PskServerPolicy(PskServerPolicy&& other) noexcept
            : state_(std::exchange(other.state_,State::failed)),store_(other.store_),binding_(std::move(other.binding_)),master_(std::move(other.master_)),
              resumption_(std::move(other.resumption_)),hash_(other.hash_),selected_(other.selected_) {}
        auto cancel() noexcept -> void {master_.reset();resumption_.reset();selected_.reset();state_=State::failed;}
        [[nodiscard]] auto selected() const noexcept -> bool {return selected_.has_value();}
        [[nodiscard]] auto selected_index() const noexcept -> std::optional<std::uint16_t> {return selected_;}
        [[nodiscard]] auto binding() const noexcept -> ServerTicketBinding const& {return binding_;}
        auto select(ClientHello const& client,std::span<std::uint8_t const> wire,std::uint16_t suite,
            std::span<std::uint8_t const> first={},std::span<std::uint8_t const> retry={})
            -> std::expected<std::optional<std::span<std::uint8_t const>>,PskError> {
            if (state_!=State::initial || first.empty()!=retry.empty())return std::unexpected(PskError::invalid_state);
            auto hash=psk_cipher_hash(suite);if (!hash)return std::unexpected(PskError::invalid_selection);hash_=*hash;
            auto* sni=client.extension(0);binding_.sni=sni ? sni->data : crypto::Bytes{};
            auto* extension=client.extension(41);
            if (!extension){state_=State::keys;return std::optional<std::span<std::uint8_t const>>{};}
            auto* modes=client.extension(45);
            if (client.extensions.back().type!=41 || !modes || modes->data.size()<2 || modes->data[0]!=modes->data.size()-1)
                return std::unexpected(PskError::invalid_offer);
            auto parsed=parse_client_psks(extension->data);if (!parsed)return std::unexpected(parsed.error());
            bool dhe=false;for(std::size_t i=1;i<modes->data.size();++i)dhe|=modes->data[i]==1;
            if (!dhe){state_=State::keys;return std::optional<std::span<std::uint8_t const>>{};}
            if (wire.size()<extension->data.size()+4 || !std::ranges::equal(wire.last(extension->data.size()),extension->data))return std::unexpected(PskError::invalid_offer);
            auto prefix=wire.first(wire.size()-extension->data.size()+parsed->prefix_size);
            for(std::size_t i=0;i<parsed->entries.size();++i) {
                auto const& offered=parsed->entries[i];auto material=store_.find(offered.identity,binding_,*hash,Clock::now());if (!material)continue;
                auto value=psk_binder(*material,prefix,first,retry);if (!value)return std::unexpected(value.error());
                if (!crypto::constant_time_equal(value->view(),offered.binder))return std::unexpected(PskError::invalid_selection);
                selected_=static_cast<std::uint16_t>(i);state_=State::keys;return std::optional<std::span<std::uint8_t const>>(material->secret);
            }
            state_=State::keys;return std::optional<std::span<std::uint8_t const>>{};
        }
        auto retain_master(Secret&& master,crypto::Hash hash) -> std::expected<void,PskError> {
            if (state_!=State::keys || hash!=hash_ || master.view().size()!=psk_hash_size(hash))return std::unexpected(PskError::invalid_state);
            master_.emplace(std::move(master));state_=State::master;return {};
        }
        auto client_finished(std::span<std::uint8_t const> transcript_hash) -> std::expected<void,PskError> {
            if (state_!=State::master || !master_ || transcript_hash.size()!=psk_hash_size(hash_))return std::unexpected(PskError::invalid_state);
            auto value=derive_secret(hash_,master_->view(),"res master",transcript_hash);master_.reset();
            if (!value){cancel();return std::unexpected(PskError::crypto_error);}
            resumption_.emplace(std::move(*value));state_=State::complete;return {};
        }
        [[nodiscard]] auto take_issuer() -> std::expected<ServerTicketIssuer<Store,Clock>,PskError> {
            if (state_!=State::complete || !resumption_)return std::unexpected(PskError::invalid_state);
            ServerTicketIssuer<Store,Clock> result(store_,std::move(binding_),std::move(*resumption_),hash_);resumption_.reset();state_=State::taken;return result;
        }
    };
}
