module tls.psk;
import std;
import tls.hello;

namespace tls {
    auto psk_hash_size(crypto::Hash hash) noexcept -> std::size_t {
        return hash==crypto::Hash::sha256 ? 32u : hash==crypto::Hash::sha384 ? 48u : 0u;
    }
    auto psk_cipher_hash(std::uint16_t suite) noexcept -> std::optional<crypto::Hash> {
        if (suite==0x1301 || suite==0x1303) return crypto::Hash::sha256;
        if (suite==0x1302) return crypto::Hash::sha384;
        return {};
    }
    auto psk_binder(PskOfferView offer,std::span<std::uint8_t const> partial,std::span<std::uint8_t const> first,
        std::span<std::uint8_t const> retry) -> std::expected<Secret,PskError> {
        auto size=psk_hash_size(offer.hash);
        if (!size || offer.secret.empty() || offer.identity.empty() || partial.size()<4 || partial[0]!=1 || first.empty()!=retry.empty())
            return std::unexpected(PskError::invalid_input);
        auto transcript=Transcript::create(offer.hash);
        if (!transcript) return std::unexpected(PskError::crypto_error);
        if (!retry.empty() && (!transcript->append(first) || !transcript->hello_retry_request() || !transcript->append(retry)))
            return std::unexpected(PskError::crypto_error);
        auto hash=std::move(*transcript).client_hello_binder_hash(partial);auto empty=crypto::digest(offer.hash,{});auto early=early_secret(offer.hash,offer.secret);
        if (!hash || !empty || !early) return std::unexpected(PskError::crypto_error);
        auto key=derive_secret(offer.hash,early->view(),offer.kind==PskKind::resumption ? "res binder" : "ext binder",*empty);
        if (!key) return std::unexpected(PskError::crypto_error);
        auto binder=finished_verify_data(offer.hash,key->view(),*hash);
        if (!binder) return std::unexpected(PskError::crypto_error);
        return std::move(*binder);
    }
    namespace {
        auto u16(std::span<std::uint8_t const> bytes,std::size_t p) -> std::size_t { return (std::size_t{bytes[p]}<<8)|bytes[p+1]; }
        auto put16(crypto::Bytes& bytes,std::size_t n) -> void { bytes.push_back(static_cast<std::uint8_t>(n>>8));bytes.push_back(static_cast<std::uint8_t>(n)); }
    }
    auto parse_client_psks(std::span<std::uint8_t const> data) -> std::expected<ClientPskWireOffers,PskError> {
        if (data.size()<7 || data.size()>65535) return std::unexpected(PskError::invalid_offer);
        auto length=u16(data,0);if (!length || length>data.size()-4) return std::unexpected(PskError::invalid_offer);
        ClientPskWireOffers out;out.prefix_size=2+length;std::size_t p=2;
        while (p<out.prefix_size) {
            if (out.prefix_size-p<6 || out.entries.size()==out.entries.capacity()) return std::unexpected(PskError::invalid_offer);
            auto n=u16(data,p);p+=2;
            if (!n || n>out.prefix_size-p-4) return std::unexpected(PskError::invalid_offer);
            auto identity=data.subspan(p,n);p+=n;std::uint32_t age=0;
            for (unsigned j=0;j<4;++j) age=(age<<8)|data[p++];
            out.entries.push_back({identity,{},age});
        }
        if (p!=out.prefix_size || u16(data,p)!=data.size()-p-2) return std::unexpected(PskError::invalid_offer);
        p+=2;
        for (auto& offer:out.entries) {
            if (p>=data.size()) return std::unexpected(PskError::invalid_offer);
            auto n=std::size_t{data[p++]};if (n<32 || n>data.size()-p) return std::unexpected(PskError::invalid_offer);
            offer.binder=data.subspan(p,n);p+=n;
        }
        if (p!=data.size()) return std::unexpected(PskError::invalid_offer);
        return out;
    }
    auto prepare_psk_hello(ClientHello& hello,std::span<PskOfferView const> offers,bool early_data) -> std::expected<void,PskError> {
        if (hello.extension(41) || hello.extension(42) || offers.size()>8) return std::unexpected(PskError::invalid_offer);
        if (auto modes=hello.extension(45)) {
            if (modes->data!=crypto::Bytes{1,1}) return std::unexpected(PskError::invalid_offer);
        } else {
            auto position=hello.extensions.end();
            // Keep padding and the trailing GREASE marker in their original slots.
            while (position!=hello.extensions.begin()) {
                auto type=std::prev(position)->type;
                if (type!=21 && !is_grease(type)) break;
                --position;
            }
            hello.extensions.insert(position,{45,{1,1}});
        }
        if (offers.empty()) return {};
        if (early_data) hello.extensions.push_back({42,{}});
        crypto::Bytes identities,binders;
        for (auto const& offer:offers) {
            auto size=psk_hash_size(offer.hash);
            if (!size || offer.identity.empty() || offer.identity.size()>65529 || offer.secret.empty() ||
                (offer.kind==PskKind::external && offer.obfuscated_age!=0) || identities.size()+6+offer.identity.size()>65535)
                return std::unexpected(PskError::invalid_offer);
            put16(identities,offer.identity.size());identities.insert(identities.end(),offer.identity.begin(),offer.identity.end());
            for (int shift:{24,16,8,0}) identities.push_back(static_cast<std::uint8_t>(offer.obfuscated_age>>shift));
            binders.push_back(static_cast<std::uint8_t>(size));binders.resize(binders.size()+size,0);
        }
        if (4+identities.size()+binders.size()>65535) return std::unexpected(PskError::invalid_offer);
        crypto::Bytes data;data.reserve(4+identities.size()+binders.size());put16(data,identities.size());
        data.insert(data.end(),identities.begin(),identities.end());put16(data,binders.size());data.insert(data.end(),binders.begin(),binders.end());
        hello.extensions.push_back({41,std::move(data)});return {};
    }
    auto seal_psk_binders(ClientHello& hello,crypto::Bytes& wire,std::span<PskOfferView const> offers,
        std::span<std::uint8_t const> first,std::span<std::uint8_t const> retry) -> std::expected<void,PskError> {
        if (offers.empty()) return hello.extension(41) ? std::unexpected(PskError::invalid_offer) : std::expected<void,PskError>{};
        if (hello.extensions.empty() || hello.extensions.back().type!=41 || wire.size()<4 || wire[0]!=1 ||
            ((std::size_t{wire[1]}<<16)|(std::size_t{wire[2]}<<8)|wire[3])!=wire.size()-4) return std::unexpected(PskError::invalid_offer);
        auto& data=hello.extensions.back().data;
        if (data.size()>wire.size()-4) return std::unexpected(PskError::invalid_offer);
        auto parsed=parse_client_psks(data);if (!parsed || parsed->entries.size()!=offers.size()) return std::unexpected(PskError::invalid_offer);
        auto offset=wire.size()-data.size();
        if (!std::ranges::equal(std::span(wire).subspan(offset),data)) return std::unexpected(PskError::invalid_offer);
        // Compute all binders before writing any. A failure leaves the caller's
        // encoded Hello unchanged and lets the owning attempt erase its keys.
        std::array<std::optional<Secret>,8> values;
        if (offers.size()>values.size()) return std::unexpected(PskError::invalid_offer);
        for (std::size_t i=0;i<offers.size();++i) {
            auto const& offer=offers[i];auto const& encoded=parsed->entries[i];
            if (!std::ranges::equal(encoded.identity,offer.identity) || encoded.obfuscated_age!=offer.obfuscated_age ||
                encoded.binder.size()!=psk_hash_size(offer.hash)) return std::unexpected(PskError::invalid_offer);
            auto value=psk_binder(offer,std::span(wire).first(offset+parsed->prefix_size),first,retry);
            if (!value) return std::unexpected(value.error());values[i].emplace(std::move(*value));
        }
        for (std::size_t i=0;i<offers.size();++i) {
            auto binder=parsed->entries[i].binder.data()-data.data();auto view=values[i]->view();
            std::ranges::copy(view,data.begin()+binder);std::ranges::copy(view,wire.begin()+static_cast<std::ptrdiff_t>(offset)+binder);
        }
        return {};
    }
    ResumptionTicket::ResumptionTicket(Secret&& secret,crypto::Bytes&& identity,TicketBinding&& binding,crypto::Hash hash,
        std::uint64_t now,std::uint32_t lifetime,std::uint32_t age_add,std::uint32_t early) noexcept
        : secret_(std::move(secret)),identity_(std::move(identity)),binding_(std::move(binding)),hash_(hash),received_ms_(now),
          lifetime_(lifetime),age_add_(age_add),max_early_data_(early) {}

    auto ResumptionTicket::usable(std::uint64_t now) const noexcept -> bool {
        return !identity_.empty() && secret_.view().size()==psk_hash_size(hash_) && lifetime_ && now>=received_ms_ && now-received_ms_<std::uint64_t{lifetime_}*1000;
    }
    auto ResumptionTicket::offer(std::uint64_t now) const noexcept -> std::expected<PskOfferView,PskError> {
        if (!usable(now)) return std::unexpected(PskError::expired);
        auto age=static_cast<std::uint32_t>(now-received_ms_)+age_add_;
        return PskOfferView{identity_,secret_.view(),hash_,PskKind::resumption,age};
    }
}
